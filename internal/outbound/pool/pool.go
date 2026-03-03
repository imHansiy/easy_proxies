package pool

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"easy_proxies/internal/geoip"
	"easy_proxies/internal/monitor"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	// Type is the outbound type name exposed to sing-box.
	Type = "pool"
	// Tag is the default outbound tag used by builder.
	Tag = "proxy-pool"

	modeSequential = "sequential"
	modeRandom     = "random"
	modeBalance    = "balance"

	nodeMetadataRefreshInterval = 10 * time.Minute
	nodeMetadataRetryInterval   = 2 * time.Minute
)

// Options controls pool outbound behaviour.
type Options struct {
	PoolName                string
	Mode                    string
	Members                 []string
	FailureThreshold        int
	BlacklistDuration       time.Duration
	DomainFailureThreshold  int
	DomainBlacklistDuration time.Duration
	DomainRecheckInterval   time.Duration
	DomainRecheckTimeout    time.Duration
	Metadata                map[string]MemberMeta
}

// MemberMeta carries optional descriptive information for monitoring UI.
type MemberMeta struct {
	Name          string
	URI           string
	Mode          string
	ListenAddress string
	Port          uint16
	Region        string // GeoIP region code: "jp", "kr", "us", "hk", "tw", "sg", "de", "gb", "ca", "au", "other"
	Country       string // Full country name from GeoIP
}

// Register wires the pool outbound into the registry.
func Register(registry *outbound.Registry) {
	outbound.Register[Options](registry, Type, newPool)
}

type memberState struct {
	outbound adapter.Outbound
	tag      string
	entry    *monitor.EntryHandle
	shared   *sharedMemberState

	regionResolved   atomic.Bool
	ipResolved       atomic.Bool
	regionResolving  atomic.Bool
	regionRetryAfter atomic.Int64
}

type poolOutbound struct {
	outbound.Adapter
	tag            string
	ctx            context.Context
	logger         log.ContextLogger
	manager        adapter.OutboundManager
	options        Options
	mode           string
	members        []*memberState
	mu             sync.Mutex
	rrCounter      atomic.Uint32
	rng            *rand.Rand
	rngMu          sync.Mutex // protects rng for random mode
	monitor        *monitor.Manager
	candidatesPool sync.Pool
}

func newPool(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	if len(options.Members) == 0 {
		return nil, E.New("pool requires at least one member")
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil {
		return nil, E.New("missing outbound manager in context")
	}
	monitorMgr := monitor.FromContext(ctx)
	normalized := normalizeOptions(options)
	memberCount := len(normalized.Members)
	p := &poolOutbound{
		Adapter: outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, normalized.Members),
		tag:     tag,
		ctx:     ctx,
		logger:  logger,
		manager: manager,
		options: normalized,
		mode:    normalized.Mode,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		monitor: monitorMgr,
		candidatesPool: sync.Pool{
			New: func() any {
				return make([]*memberState, 0, memberCount)
			},
		},
	}

	// Register nodes immediately if monitor is available
	if monitorMgr != nil {
		logger.Info("registering ", len(normalized.Members), " nodes to monitor")
		for _, memberTag := range normalized.Members {
			// Acquire shared state for this tag (creates if not exists)
			state := acquireSharedState(normalized.PoolName, memberTag)
			monitorTag := composeMonitorTag(normalized.PoolName, memberTag)

			meta := normalized.Metadata[memberTag]
			info := monitor.NodeInfo{
				Tag:           monitorTag,
				NodeTag:       memberTag,
				PoolName:      normalized.PoolName,
				Name:          meta.Name,
				URI:           meta.URI,
				NodeIP:        resolveNodeIP(meta.URI),
				Mode:          meta.Mode,
				ListenAddress: meta.ListenAddress,
				Port:          meta.Port,
				Region:        meta.Region,
				Country:       meta.Country,
			}
			entry := monitorMgr.Register(info)
			if entry != nil {
				// Attach entry to shared state so all pool instances share it
				state.attachEntry(entry)
				logger.Info("registered node: ", memberTag)
				// Set probe and release functions immediately
				entry.SetRelease(p.makeReleaseByTagFunc(memberTag))
				entry.SetBan(p.makeBanByTagFunc(memberTag))
				if probeFn := p.makeProbeByTagFunc(memberTag); probeFn != nil {
					entry.SetProbe(probeFn)
				}
			} else {
				logger.Warn("failed to register node: ", memberTag)
			}
		}
	} else {
		logger.Warn("monitor manager is nil, skipping node registration")
	}

	return p, nil
}

func normalizeOptions(options Options) Options {
	options.PoolName = normalizePoolName(options.PoolName)
	if options.FailureThreshold <= 0 {
		options.FailureThreshold = 3
	}
	if options.BlacklistDuration <= 0 {
		options.BlacklistDuration = 24 * time.Hour
	}
	if options.DomainFailureThreshold <= 0 {
		options.DomainFailureThreshold = 2
	}
	if options.DomainBlacklistDuration <= 0 {
		options.DomainBlacklistDuration = 12 * time.Hour
	}
	if options.DomainRecheckInterval <= 0 {
		options.DomainRecheckInterval = 10 * time.Minute
	}
	if options.DomainRecheckTimeout <= 0 {
		options.DomainRecheckTimeout = 10 * time.Second
	}
	if options.Metadata == nil {
		options.Metadata = make(map[string]MemberMeta)
	}
	switch strings.ToLower(options.Mode) {
	case modeRandom:
		options.Mode = modeRandom
	case modeBalance:
		options.Mode = modeBalance
	default:
		options.Mode = modeSequential
	}
	return options
}

func (p *poolOutbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	p.mu.Lock()
	err := p.initializeMembersLocked()
	p.mu.Unlock()
	if err != nil {
		return err
	}
	// 在初始化完成后，立即在后台触发健康检查
	if p.monitor != nil {
		go p.probeAllMembersOnStartup()
	}
	if len(p.options.Members) > 1 {
		go p.runDomainRecheckLoop()
	}
	return nil
}

func (p *poolOutbound) runDomainRecheckLoop() {
	interval := p.options.DomainRecheckInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.recheckDomainBlacklists()
		}
	}
}

func (p *poolOutbound) recheckDomainBlacklists() {
	now := time.Now()
	p.mu.Lock()
	members := make([]*memberState, len(p.members))
	copy(members, p.members)
	p.mu.Unlock()

	for _, member := range members {
		if member == nil || member.shared == nil {
			continue
		}
		domains := member.shared.domainsForRecheck(now)
		for _, domain := range domains {
			ctx, cancel := context.WithTimeout(p.ctx, p.options.DomainRecheckTimeout)
			err := p.recheckDomain(ctx, member, domain)
			cancel()
			if err != nil {
				continue
			}
			if member.shared.clearDomainBlacklist(domain) {
				p.logger.Info("proxy ", member.tag, " domain blacklist cleared: ", domain)
			}
		}
	}
}

func (p *poolOutbound) recheckDomain(ctx context.Context, member *memberState, domain string) error {
	if domain == "" {
		return E.New("empty domain")
	}

	destination80 := M.ParseSocksaddrHostPort(domain, 80)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, destination80)
	if err == nil {
		defer conn.Close()
		if _, probeErr := httpProbe(conn, domain); probeErr == nil {
			return nil
		}
	}

	destination443 := M.ParseSocksaddrHostPort(domain, 443)
	conn443, err443 := member.outbound.DialContext(ctx, N.NetworkTCP, destination443)
	if err443 != nil {
		if err != nil {
			return err443
		}
		return err443
	}
	_ = conn443.Close()
	return nil
}

// initializeMembersLocked must be called with p.mu held
func (p *poolOutbound) initializeMembersLocked() error {
	if len(p.members) > 0 {
		return nil // Already initialized
	}

	members := make([]*memberState, 0, len(p.options.Members))
	for _, tag := range p.options.Members {
		detour, loaded := p.manager.Outbound(tag)
		if !loaded {
			return E.New("pool member not found: ", tag)
		}

		// Acquire shared state (creates if not exists, reuses if already created)
		state := acquireSharedState(p.options.PoolName, tag)

		member := &memberState{
			outbound: detour,
			tag:      tag,
			shared:   state,
			entry:    state.entryHandle(),
		}
		meta := p.options.Metadata[tag]
		if meta.Region != "" && meta.Region != geoip.RegionOther {
			member.regionResolved.Store(true)
		}

		// Connect to existing monitor entry if available
		if p.monitor != nil {
			monitorTag := composeMonitorTag(p.options.PoolName, tag)
			info := monitor.NodeInfo{
				Tag:           monitorTag,
				NodeTag:       tag,
				PoolName:      p.options.PoolName,
				Name:          meta.Name,
				URI:           meta.URI,
				NodeIP:        resolveNodeIP(meta.URI),
				Mode:          meta.Mode,
				ListenAddress: meta.ListenAddress,
				Port:          meta.Port,
				Region:        meta.Region,
				Country:       meta.Country,
			}
			entry := p.monitor.Register(info)
			if entry != nil {
				state.attachEntry(entry)
				member.entry = entry
				entry.SetRelease(p.makeReleaseFunc(member))
				entry.SetBan(p.makeBanFunc(member))
				if probe := p.makeProbeFunc(member); probe != nil {
					entry.SetProbe(probe)
				}
			}
		}
		members = append(members, member)
	}
	p.members = members
	p.logger.Info("pool initialized with ", len(members), " members")

	return nil
}

// probeAllMembersOnStartup performs initial health checks on all members
func (p *poolOutbound) probeAllMembersOnStartup() {
	destination, ok := p.monitor.DestinationForProbe()
	if !ok {
		p.logger.Warn("probe target not configured, skipping initial health check")
		// 没有配置探测目标时，标记所有节点为可用
		p.mu.Lock()
		for _, member := range p.members {
			if member.entry != nil {
				member.entry.MarkInitialCheckDone(true)
			}
		}
		p.mu.Unlock()
		return
	}

	p.logger.Info("starting initial health check for all nodes")

	p.mu.Lock()
	members := make([]*memberState, len(p.members))
	copy(members, p.members)
	p.mu.Unlock()

	availableCount := 0
	failedCount := 0

	for _, member := range members {
		// Create a timeout context for each probe
		ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)

		start := time.Now()
		conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, destination)

		if err != nil {
			p.logger.Warn("initial probe failed for ", member.tag, ": ", err)
			failedCount++
			p.markProbeFailure(member, err)
			if member.entry != nil {
				member.entry.MarkInitialCheckDone(false) // 标记为不可用
			}
			cancel()
			continue
		}

		// Perform HTTP probe to measure actual latency (TTFB)
		_, err = httpProbe(conn, destination.AddrString())
		conn.Close()

		if err != nil {
			p.logger.Warn("initial HTTP probe failed for ", member.tag, ": ", err)
			failedCount++
			p.markProbeFailure(member, err)
			if member.entry != nil {
				member.entry.MarkInitialCheckDone(false)
			}
			cancel()
			continue
		}

		// Total latency = dial + HTTP probe
		latency := time.Since(start)
		latencyMs := latency.Milliseconds()
		p.logger.Info("initial probe success for ", member.tag, ", latency: ", latencyMs, "ms")
		availableCount++
		p.markProbeSuccess(member, latency)
		if member.entry != nil {
			member.entry.MarkInitialCheckDone(true)
		}

		cancel()
	}

	p.logger.Info("initial health check completed: ", availableCount, " available, ", failedCount, " failed")
}

func (p *poolOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	domain := normalizeDomain(destination.AddrString())
	member, err := p.pickMember(network, domain)
	if err != nil {
		return nil, err
	}
	p.incActive(member)
	conn, err := member.outbound.DialContext(ctx, network, destination)
	if err != nil {
		p.decActive(member)
		p.recordFailure(member, err, domain)
		return nil, err
	}
	p.recordSuccess(member)
	return p.wrapConn(conn, member), nil
}

func (p *poolOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	domain := normalizeDomain(destination.AddrString())
	member, err := p.pickMember(N.NetworkUDP, domain)
	if err != nil {
		return nil, err
	}
	p.incActive(member)
	conn, err := member.outbound.ListenPacket(ctx, destination)
	if err != nil {
		p.decActive(member)
		p.recordFailure(member, err, domain)
		return nil, err
	}
	p.recordSuccess(member)
	return p.wrapPacketConn(conn, member), nil
}

func (p *poolOutbound) pickMember(network, domain string) (*memberState, error) {
	now := time.Now()
	candidates := p.getCandidateBuffer()

	p.mu.Lock()
	if len(p.members) == 0 {
		if err := p.initializeMembersLocked(); err != nil {
			p.mu.Unlock()
			p.putCandidateBuffer(candidates)
			return nil, err
		}
	}
	candidates = p.availableMembersLocked(now, network, domain, candidates)
	p.mu.Unlock()

	if len(candidates) == 0 {
		p.mu.Lock()
		if p.releaseIfAllBlacklistedLocked(now) {
			candidates = p.availableMembersLocked(now, network, domain, candidates)
		}
		p.mu.Unlock()
	}

	if len(candidates) == 0 {
		p.putCandidateBuffer(candidates)
		return nil, E.New("no healthy proxy available")
	}

	member := p.selectMember(candidates)
	p.putCandidateBuffer(candidates)
	return member, nil
}

func (p *poolOutbound) availableMembersLocked(now time.Time, network, domain string, buf []*memberState) []*memberState {
	result := buf[:0]
	for _, member := range p.members {
		// Check blacklist via shared state (auto-clears if expired)
		if member.shared != nil && member.shared.isBlacklisted(now) {
			continue
		}
		if domain != "" && member.shared != nil && member.shared.isDomainBlacklisted(domain, now) {
			continue
		}
		if network != "" && !common.Contains(member.outbound.Network(), network) {
			continue
		}
		result = append(result, member)
	}
	return result
}

func (p *poolOutbound) releaseIfAllBlacklistedLocked(now time.Time) bool {
	if len(p.members) == 0 {
		return false
	}
	hasAutoBlacklist := false
	// Check if all members are blacklisted
	for _, member := range p.members {
		if member.shared == nil || !member.shared.isBlacklisted(now) {
			return false
		}
		if member.shared.hasAutoBlacklist(now) {
			hasAutoBlacklist = true
		}
	}
	if !hasAutoBlacklist {
		return false
	}
	// All blacklisted, force release all
	for _, member := range p.members {
		if member.shared != nil {
			member.shared.clearAutoBlacklist()
		}
	}
	p.logger.Warn("all upstream proxies temporarily blacklisted, releasing auto-blacklist for retry")
	return true
}

func (p *poolOutbound) selectMember(candidates []*memberState) *memberState {
	switch p.mode {
	case modeRandom:
		p.rngMu.Lock()
		idx := p.rng.Intn(len(candidates))
		p.rngMu.Unlock()
		return candidates[idx]
	case modeBalance:
		var selected *memberState
		var minActive int32
		for _, member := range candidates {
			var active int32
			if member.shared != nil {
				active = member.shared.activeCount()
			}
			if selected == nil || active < minActive {
				selected = member
				minActive = active
			}
		}
		return selected
	default:
		idx := int(p.rrCounter.Add(1)-1) % len(candidates)
		return candidates[idx]
	}
}

func (p *poolOutbound) recordFailure(member *memberState, cause error, domain string) {
	if member.shared == nil {
		p.logger.Warn("proxy ", member.tag, " failure (no shared state): ", cause)
		return
	}
	failures, blacklisted, _ := member.shared.recordFailure(cause, p.options.FailureThreshold, p.options.BlacklistDuration)
	if domain != "" {
		domainFailures, domainBlacklisted, domainUntil := member.shared.recordDomainFailure(domain, p.options.DomainFailureThreshold, p.options.DomainBlacklistDuration)
		if domainBlacklisted {
			p.logger.Warn("proxy ", member.tag, " domain blacklisted ", domain, " until ", domainUntil)
		} else {
			p.logger.Warn("proxy ", member.tag, " domain failure ", domain, " ", domainFailures, "/", p.options.DomainFailureThreshold)
		}
	}
	if blacklisted {
		p.logger.Warn("proxy ", member.tag, " blacklisted for ", p.options.BlacklistDuration, ": ", cause)
	} else {
		p.logger.Warn("proxy ", member.tag, " failure ", failures, "/", p.options.FailureThreshold, ": ", cause)
	}
}

func (p *poolOutbound) recordSuccess(member *memberState) {
	if member.shared != nil {
		member.shared.recordSuccess()
	}
	p.maybeResolveMemberLocation(member)
}

func (p *poolOutbound) wrapConn(conn net.Conn, member *memberState) net.Conn {
	return &trackedConn{Conn: conn, release: func() {
		p.decActive(member)
	}}
}

func (p *poolOutbound) wrapPacketConn(conn net.PacketConn, member *memberState) net.PacketConn {
	return &trackedPacketConn{PacketConn: conn, release: func() {
		p.decActive(member)
	}}
}

func (p *poolOutbound) makeReleaseFunc(member *memberState) func() {
	return func() {
		if member.shared != nil {
			member.shared.forceRelease()
		}
	}
}

// httpProbe performs an HTTP probe through the connection and measures TTFB.
// It sends a minimal HTTP request and waits for the first byte of response.
func httpProbe(conn net.Conn, host string) (time.Duration, error) {
	// Build HTTP request
	req := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n", host)

	// Try to set write deadline (ignore errors for connections that don't support it)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// Record time just before sending request
	start := time.Now()

	// Send HTTP request
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, fmt.Errorf("write request: %w", err)
	}

	// Try to set read deadline (ignore errors for connections that don't support it)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read first byte (TTFB - Time To First Byte)
	reader := bufio.NewReader(conn)
	_, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	// Calculate TTFB
	ttfb := time.Since(start)
	return ttfb, nil
}

func (p *poolOutbound) makeProbeFunc(member *memberState) func(ctx context.Context) (time.Duration, error) {
	if p.monitor == nil {
		return nil
	}
	destination, ok := p.monitor.DestinationForProbe()
	if !ok {
		return nil
	}
	return func(ctx context.Context) (time.Duration, error) {
		start := time.Now()
		conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			p.markProbeFailure(member, err)
			return 0, err
		}
		defer conn.Close()

		// Perform HTTP probe to measure actual latency (TTFB)
		_, err = httpProbe(conn, destination.AddrString())
		if err != nil {
			p.markProbeFailure(member, err)
			return 0, err
		}

		// Total duration = dial time + HTTP probe
		duration := time.Since(start)
		p.markProbeSuccess(member, duration)
		return duration, nil
	}
}

// makeProbeByTagFunc creates a probe function that works before member initialization
func (p *poolOutbound) makeProbeByTagFunc(tag string) func(ctx context.Context) (time.Duration, error) {
	if p.monitor == nil {
		return nil
	}
	destination, ok := p.monitor.DestinationForProbe()
	if !ok {
		return nil
	}
	return func(ctx context.Context) (time.Duration, error) {
		// Ensure members are initialized
		p.mu.Lock()
		if len(p.members) == 0 {
			if err := p.initializeMembersLocked(); err != nil {
				p.mu.Unlock()
				return 0, err
			}
		}

		// Find the member by tag
		var member *memberState
		for _, m := range p.members {
			if m.tag == tag {
				member = m
				break
			}
		}
		p.mu.Unlock()

		if member == nil {
			return 0, E.New("member not found: ", tag)
		}

		start := time.Now()
		conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			p.markProbeFailure(member, err)
			return 0, err
		}
		defer conn.Close()

		// Perform HTTP probe to measure actual latency (TTFB)
		_, err = httpProbe(conn, destination.AddrString())
		if err != nil {
			p.markProbeFailure(member, err)
			return 0, err
		}

		// Total duration = dial time + TTFB
		duration := time.Since(start)
		p.markProbeSuccess(member, duration)
		return duration, nil
	}
}

func (p *poolOutbound) markProbeFailure(member *memberState, cause error) {
	if member == nil || cause == nil {
		return
	}
	if member.shared != nil {
		_, blacklisted, until := member.shared.recordFailure(cause, 1, p.options.BlacklistDuration)
		if blacklisted {
			p.logger.Warn("health probe temporary blacklist ", member.tag, " until ", until)
		}
		return
	}
	if member.entry != nil {
		member.entry.RecordFailure(cause)
	}
}

func (p *poolOutbound) markProbeSuccess(member *memberState, latency time.Duration) {
	if member == nil {
		return
	}
	if member.shared != nil {
		// Probe success only clears auto penalties. Manual bans remain effective.
		member.shared.clearAutoBlacklist()
	}
	if member.entry != nil {
		member.entry.RecordSuccessWithLatency(latency)
	}
	p.maybeResolveMemberLocation(member)
}

func normalizeDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	return host
}

func (p *poolOutbound) maybeResolveMemberLocation(member *memberState) {
	if member == nil || member.entry == nil {
		return
	}
	resolvedBefore := member.regionResolved.Load() && member.ipResolved.Load()
	now := time.Now()
	if retryAfter := member.regionRetryAfter.Load(); retryAfter > now.Unix() {
		return
	}
	if !member.regionResolving.CompareAndSwap(false, true) {
		return
	}

	go func(resolvedBefore bool) {
		defer member.regionResolving.Store(false)

		ctx, cancel := context.WithTimeout(p.ctx, 12*time.Second)
		defer cancel()

		region, country, nodeIP, err := p.resolveMemberLocation(ctx, member)
		if err != nil {
			member.regionRetryAfter.Store(time.Now().Add(nodeMetadataRetryInterval).Unix())
			return
		}

		if strings.TrimSpace(region) != "" {
			member.entry.UpdateLocation(region, country)
			member.regionResolved.Store(true)
		}
		if strings.TrimSpace(nodeIP) != "" {
			changed, previousIP, currentIP, released := member.entry.UpdateNodeIP(nodeIP)
			member.ipResolved.Store(true)
			if changed && previousIP != "" {
				if released {
					p.logger.Info("node IP changed for ", member.tag, ": ", previousIP, " -> ", currentIP, ", blacklist auto-released")
				} else {
					p.logger.Info("node IP changed for ", member.tag, ": ", previousIP, " -> ", currentIP)
				}
			}
		}

		if !member.regionResolved.Load() || !member.ipResolved.Load() {
			member.regionRetryAfter.Store(time.Now().Add(nodeMetadataRetryInterval).Unix())
			return
		}

		member.regionRetryAfter.Store(time.Now().Add(nodeMetadataRefreshInterval).Unix())
		if !resolvedBefore {
			p.logger.Info("node metadata resolved for ", member.tag, ": ", region, " (", country, "), ip=", nodeIP)
		}
	}(resolvedBefore)
}

func (p *poolOutbound) resolveMemberLocation(ctx context.Context, member *memberState) (string, string, string, error) {
	if member == nil {
		return "", "", "", fmt.Errorf("member is nil")
	}

	destination := M.ParseSocksaddrHostPort("www.cloudflare.com", 443)
	conn, err := member.outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	trace, err := cloudflareTrace(conn)
	if err != nil {
		return "", "", "", err
	}

	isoCode := trace.ISOCode
	region := geoip.RegionFromISO(isoCode)
	country := geoip.RegionName(region)
	if region == geoip.RegionOther {
		country = strings.ToUpper(strings.TrimSpace(isoCode))
		if country == "" {
			country = "Unknown"
		}
	}

	return region, country, strings.TrimSpace(trace.IP), nil
}

type cloudflareTraceResult struct {
	ISOCode string
	IP      string
}

func cloudflareTrace(conn net.Conn) (cloudflareTraceResult, error) {
	if conn == nil {
		return cloudflareTraceResult{}, fmt.Errorf("connection is nil")
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "www.cloudflare.com", MinVersion: tls.VersionTLS12})
	defer tlsConn.Close()

	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return cloudflareTraceResult{}, fmt.Errorf("tls handshake: %w", err)
	}

	req := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\nUser-Agent: easy-proxies/1.0\r\nAccept: */*\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return cloudflareTraceResult{}, fmt.Errorf("write trace request: %w", err)
	}

	raw, err := io.ReadAll(io.LimitReader(tlsConn, 64*1024))
	if err != nil {
		return cloudflareTraceResult{}, fmt.Errorf("read trace response: %w", err)
	}

	return parseCloudflareTrace(string(raw))
}

func parseCloudflareTrace(raw string) (cloudflareTraceResult, error) {
	sep := strings.Index(raw, "\r\n\r\n")
	if sep == -1 {
		return cloudflareTraceResult{}, fmt.Errorf("invalid trace response")
	}
	body := raw[sep+4:]
	result := cloudflareTraceResult{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "ip=") {
			result.IP = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			continue
		}
		if strings.HasPrefix(line, "loc=") {
			iso := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "loc=")))
			if len(iso) != 2 {
				return cloudflareTraceResult{}, fmt.Errorf("invalid loc value: %q", iso)
			}
			result.ISOCode = iso
		}
	}
	if result.ISOCode == "" {
		return cloudflareTraceResult{}, fmt.Errorf("loc not found in trace response")
	}
	if result.IP == "" {
		return cloudflareTraceResult{}, fmt.Errorf("ip not found in trace response")
	}
	return result, nil
}

// makeReleaseByTagFunc creates a release function that works before member initialization
func (p *poolOutbound) makeReleaseByTagFunc(tag string) func() {
	return func() {
		releaseSharedMember(p.options.PoolName, tag)
	}
}

func (p *poolOutbound) makeBanFunc(member *memberState) func(duration time.Duration) time.Time {
	return func(duration time.Duration) time.Time {
		if member == nil || member.shared == nil {
			return time.Time{}
		}
		return member.shared.manualBan(duration)
	}
}

func (p *poolOutbound) makeBanByTagFunc(tag string) func(duration time.Duration) time.Time {
	return func(duration time.Duration) time.Time {
		until, _ := banSharedMember(p.options.PoolName, tag, duration)
		return until
	}
}

var nodeIPCache sync.Map

func resolveNodeIP(rawURI string) string {
	host := extractURIHost(rawURI, 0)
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	if cached, ok := nodeIPCache.Load(host); ok {
		if value, ok := cached.(string); ok {
			return value
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		nodeIPCache.Store(host, "")
		return ""
	}

	chosen := addrs[0].IP.String()
	for _, addr := range addrs {
		if v4 := addr.IP.To4(); v4 != nil {
			chosen = v4.String()
			break
		}
	}
	nodeIPCache.Store(host, chosen)
	return chosen
}

func extractURIHost(rawURI string, depth int) string {
	if depth > 4 {
		return ""
	}

	trimmed := strings.TrimSpace(rawURI)
	if trimmed == "" {
		return ""
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "relay://") {
		if host := extractRelayHost(trimmed, depth+1); host != "" {
			return host
		}
	}
	if strings.HasPrefix(lower, "vmess://") {
		if host := extractVMessHost(trimmed); host != "" {
			return host
		}
	}
	if strings.HasPrefix(lower, "ss://") {
		if host := extractSSHost(trimmed); host != "" {
			return host
		}
	}
	if strings.HasPrefix(lower, "ssr://") {
		if host := extractSSRHost(trimmed); host != "" {
			return host
		}
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Hostname())
}

func extractRelayHost(rawURI string, depth int) string {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return ""
	}
	for _, hop := range parsed.Query()["hop"] {
		decoded := decodeBase64Loose(hop)
		if decoded == "" {
			continue
		}
		if host := extractURIHost(decoded, depth); host != "" {
			return host
		}
	}
	return ""
}

func extractVMessHost(rawURI string) string {
	body := rawURI
	if idx := strings.Index(body, "://"); idx >= 0 {
		body = body[idx+3:]
	}
	body = strings.SplitN(body, "#", 2)[0]

	// New-style VMess URI may use authority form (vmess://user@host:port?...)
	if strings.Contains(body, "@") {
		if parsed, err := url.Parse(rawURI); err == nil {
			if host := strings.TrimSpace(parsed.Hostname()); host != "" {
				return host
			}
		}
	}

	decoded := decodeBase64Loose(body)
	if decoded == "" {
		return ""
	}

	var payload struct {
		Add  string `json:"add"`
		Host string `json:"host"`
	}
	if err := json.Unmarshal([]byte(decoded), &payload); err != nil {
		return ""
	}
	host := strings.TrimSpace(payload.Add)
	if host == "" {
		host = strings.TrimSpace(payload.Host)
	}
	return host
}

func extractSSHost(rawURI string) string {
	body := rawURI
	if idx := strings.Index(body, "://"); idx >= 0 {
		body = body[idx+3:]
	}
	body = strings.SplitN(body, "#", 2)[0]
	if body == "" {
		return ""
	}

	if strings.Contains(body, "@") {
		afterAt := body[strings.LastIndex(body, "@")+1:]
		afterAt = strings.SplitN(afterAt, "?", 2)[0]
		host, _ := splitHostPortLoose(afterAt)
		return host
	}

	encoded := strings.SplitN(body, "?", 2)[0]
	decoded := decodeBase64Loose(encoded)
	if decoded == "" || !strings.Contains(decoded, "@") {
		return ""
	}
	afterAt := decoded[strings.LastIndex(decoded, "@")+1:]
	host, _ := splitHostPortLoose(afterAt)
	return host
}

func extractSSRHost(rawURI string) string {
	body := rawURI
	if idx := strings.Index(body, "://"); idx >= 0 {
		body = body[idx+3:]
	}
	body = strings.SplitN(body, "#", 2)[0]
	decoded := decodeBase64Loose(body)
	if decoded == "" {
		return ""
	}
	endpoint := strings.SplitN(decoded, "/", 2)[0]
	parts := strings.Split(endpoint, ":")
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func splitHostPortLoose(value string) (host, port string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(value); err == nil {
		return strings.TrimSpace(h), strings.TrimSpace(p)
	}
	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return value, ""
}

func decodeBase64Loose(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	candidates := []string{raw}
	normalized := strings.ReplaceAll(strings.ReplaceAll(raw, "-", "+"), "_", "/")
	if normalized != raw {
		candidates = append(candidates, normalized)
	}

	for _, candidate := range candidates {
		padded := candidate + strings.Repeat("=", (4-len(candidate)%4)%4)
		if decoded, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return string(decoded)
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(candidate); err == nil {
			return string(decoded)
		}
		if decoded, err := base64.URLEncoding.DecodeString(padded); err == nil {
			return string(decoded)
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(candidate); err == nil {
			return string(decoded)
		}
	}

	return ""
}

func composeMonitorTag(poolName, memberTag string) string {
	poolName = strings.TrimSpace(poolName)
	if poolName == "" || strings.EqualFold(poolName, "default") {
		return memberTag
	}
	return poolName + "::" + memberTag
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type trackedPacketConn struct {
	net.PacketConn
	once    sync.Once
	release func()
}

func (c *trackedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.release)
	return err
}

func (p *poolOutbound) incActive(member *memberState) {
	if member.shared != nil {
		member.shared.incActive()
	}
}

func (p *poolOutbound) decActive(member *memberState) {
	if member.shared != nil {
		member.shared.decActive()
	}
}

func (p *poolOutbound) getCandidateBuffer() []*memberState {
	if buf := p.candidatesPool.Get(); buf != nil {
		return buf.([]*memberState)
	}
	return make([]*memberState, 0, len(p.options.Members))
}

func (p *poolOutbound) putCandidateBuffer(buf []*memberState) {
	if buf == nil {
		return
	}
	const maxCached = 4096
	if cap(buf) > maxCached {
		return
	}
	p.candidatesPool.Put(buf[:0])
}
