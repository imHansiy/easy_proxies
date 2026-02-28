package subscription

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/boxmgr"
	"easy_proxies/internal/config"
	"easy_proxies/internal/monitor"
	"gopkg.in/yaml.v3"
)

// Logger defines logging interface.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Option configures the Manager.
type Option func(*Manager)

// WithLogger sets a custom logger.
func WithLogger(l Logger) Option {
	return func(m *Manager) { m.logger = l }
}

// Manager handles periodic subscription refresh.
type Manager struct {
	mu sync.RWMutex

	baseCfg    *config.Config
	boxMgr     *boxmgr.Manager
	logger     Logger
	httpClient *http.Client // Custom HTTP client with connection pooling

	status        monitor.SubscriptionStatus
	ctx           context.Context
	cancel        context.CancelFunc
	refreshMu     sync.Mutex // prevents concurrent refreshes
	manualRefresh chan struct{}

	// Track nodes.txt content hash to detect modifications
	lastSubHash      string    // Hash of nodes.txt content after last subscription refresh
	lastNodesModTime time.Time // Last known modification time of nodes.txt
	logs             []monitor.SubscriptionLog
}

const maxSubscriptionLogs = 200

// New creates a SubscriptionManager.
func New(cfg *config.Config, boxMgr *boxmgr.Manager, opts ...Option) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	// Create optimized HTTP client with connection pooling
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second, // Overall timeout
	}

	m := &Manager{
		baseCfg:       cfg,
		boxMgr:        boxMgr,
		ctx:           ctx,
		cancel:        cancel,
		manualRefresh: make(chan struct{}, 1),
		httpClient:    httpClient,
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.logger == nil {
		m.logger = defaultLogger{}
	}
	return m
}

// Start begins the periodic refresh loop.
func (m *Manager) Start() {
	interval := m.baseCfg.SubscriptionRefresh.Interval
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	autoEnabled := m.baseCfg.SubscriptionRefresh.Enabled
	if !autoEnabled {
		m.logger.Infof("subscription auto refresh disabled, manual refresh remains available")
	}
	if len(m.baseCfg.Subscriptions) == 0 {
		m.logger.Infof("no subscriptions configured, refresh loop started and waiting for subscriptions")
	}
	if autoEnabled {
		m.logger.Infof("starting subscription auto refresh, interval: %s", interval)
	}

	go m.refreshLoop(interval, autoEnabled)
}

// Stop stops the periodic refresh.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}

	// Close idle connections
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
}

// RefreshNow triggers an immediate refresh.
func (m *Manager) RefreshNow() error {
	select {
	case m.manualRefresh <- struct{}{}:
	default:
		// Already a refresh pending
	}

	// Wait for refresh to complete or timeout
	timeout := m.baseCfg.SubscriptionRefresh.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(m.ctx, timeout+m.baseCfg.SubscriptionRefresh.HealthCheckTimeout)
	defer cancel()

	// Poll status until refresh completes
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	startCount := m.Status().RefreshCount
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("refresh timeout")
		case <-ticker.C:
			status := m.Status()
			if status.RefreshCount > startCount {
				if status.LastError != "" {
					return fmt.Errorf("refresh failed: %s", status.LastError)
				}
				return nil
			}
		}
	}
}

// RefreshSubscription triggers refresh for one subscription URL while keeping others unchanged.
func (m *Manager) RefreshSubscription(subURL string) error {
	subURL = strings.TrimSpace(subURL)
	if subURL == "" {
		return fmt.Errorf("subscription url is empty")
	}
	return m.doRefreshWithTarget(subURL, "manual-single")
}

// SubscriptionLogs returns recent logs filtered by subscription URL.
func (m *Manager) SubscriptionLogs(subURL string) []monitor.SubscriptionLog {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if subURL == "" {
		out := make([]monitor.SubscriptionLog, len(m.logs))
		copy(out, m.logs)
		return out
	}
	out := make([]monitor.SubscriptionLog, 0, len(m.logs))
	for _, item := range m.logs {
		if item.Subscription == subURL {
			out = append(out, item)
		}
	}
	return out
}

// Status returns the current refresh status.
func (m *Manager) Status() monitor.SubscriptionStatus {
	m.mu.RLock()
	status := m.status
	m.mu.RUnlock()

	// Check if nodes have been modified since last refresh
	status.NodesModified = m.CheckNodesModified()
	return status
}

// refreshLoop runs auto refresh (if enabled) and always supports manual refresh.
func (m *Manager) refreshLoop(interval time.Duration, autoEnabled bool) {
	var ticker *time.Ticker
	var tickerC <-chan time.Time
	if autoEnabled {
		ticker = time.NewTicker(interval)
		tickerC = ticker.C
		defer ticker.Stop()
	}

	m.mu.Lock()
	if autoEnabled {
		m.status.NextRefresh = time.Now().Add(interval)
	} else {
		m.status.NextRefresh = time.Time{}
	}
	m.mu.Unlock()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-tickerC:
			m.doRefresh()
			m.mu.Lock()
			m.status.NextRefresh = time.Now().Add(interval)
			m.mu.Unlock()
		case <-m.manualRefresh:
			m.doRefresh()
			m.mu.Lock()
			if autoEnabled {
				if ticker != nil {
					ticker.Reset(interval)
				}
				m.status.NextRefresh = time.Now().Add(interval)
			} else {
				m.status.NextRefresh = time.Time{}
			}
			m.mu.Unlock()
		}
	}
}

// doRefresh performs a scheduled full refresh.
func (m *Manager) doRefresh() {
	if err := m.doRefreshWithTarget("", "auto"); err != nil {
		m.logger.Errorf("refresh failed: %v", err)
	}
}

func (m *Manager) doRefreshWithTarget(targetURL, trigger string) error {
	start := time.Now()
	targetURL = strings.TrimSpace(targetURL)
	if trigger == "" {
		trigger = "manual"
	}

	if !m.refreshMu.TryLock() {
		return fmt.Errorf("refresh already in progress")
	}
	defer m.refreshMu.Unlock()

	m.mu.Lock()
	m.status.IsRefreshing = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.status.IsRefreshing = false
		m.status.RefreshCount++
		m.mu.Unlock()
	}()

	if targetURL == "" {
		if len(m.baseCfg.Subscriptions) == 0 {
			newCfg := m.createNewConfig(nil)
			hadSubscriptionNodes := len(newCfg.Nodes) != len(m.baseCfg.Nodes)
			if hadSubscriptionNodes {
				portMap := m.boxMgr.CurrentPortMap()
				if err := m.boxMgr.ReloadWithPortMap(newCfg, portMap); err != nil {
					err = fmt.Errorf("reload failed while clearing subscription nodes: %w", err)
					m.logger.Errorf("%v", err)
					m.mu.Lock()
					m.status.LastError = err.Error()
					m.status.LastRefresh = time.Now()
					m.mu.Unlock()
					m.appendLog("", trigger, "error", err.Error(), 0, start)
					return err
				}

				nodesFilePath := m.getNodesFilePath()
				fileNodes := nodesFromSource(newCfg.Nodes, config.NodeSourceFile)
				if err := m.writeNodesToFile(nodesFilePath, fileNodes); err != nil {
					m.logger.Warnf("failed to sync nodes file after subscription removal: %v", err)
				}
			}

			m.mu.Lock()
			m.status.LastError = ""
			m.status.LastRefresh = time.Now()
			m.status.NodeCount = 0
			m.status.NodesModified = false
			m.lastSubHash = m.computeNodesHash(nil)
			m.lastNodesModTime = time.Now()
			if m.baseCfg != nil {
				m.baseCfg.Nodes = newCfg.Nodes
			}
			m.mu.Unlock()

			if hadSubscriptionNodes {
				m.appendLog("", trigger, "info", "no subscriptions configured, removed subscription nodes", 0, start)
				m.logger.Infof("no subscriptions configured, removed subscription nodes")
			} else {
				m.appendLog("", trigger, "info", "skip refresh: no subscriptions configured", 0, start)
			}
			return nil
		}
		m.logger.Infof("starting subscription refresh")
	} else {
		if !m.hasSubscription(targetURL) {
			return fmt.Errorf("subscription not found")
		}
		m.logger.Infof("starting subscription refresh for %s", targetURL)
	}

	nodes, err := m.fetchAllSubscriptions(trigger, targetURL)
	if err != nil {
		m.logger.Errorf("fetch subscriptions failed: %v", err)
		m.mu.Lock()
		m.status.LastError = err.Error()
		m.status.LastRefresh = time.Now()
		m.mu.Unlock()
		m.appendLog(targetURL, trigger, "error", err.Error(), 0, start)
		return err
	}

	if len(nodes) == 0 {
		err := fmt.Errorf("no nodes fetched")
		m.logger.Warnf("%v", err)
		m.mu.Lock()
		m.status.LastError = err.Error()
		m.status.LastRefresh = time.Now()
		m.mu.Unlock()
		m.appendLog(targetURL, trigger, "warn", err.Error(), 0, start)
		return err
	}

	m.logger.Infof("fetched %d nodes from subscriptions", len(nodes))

	nodesFilePath := m.getNodesFilePath()
	if err := m.writeNodesToFile(nodesFilePath, nodes); err != nil {
		err = fmt.Errorf("write nodes.txt: %w", err)
		m.logger.Errorf("%v", err)
		m.mu.Lock()
		m.status.LastError = err.Error()
		m.status.LastRefresh = time.Now()
		m.mu.Unlock()
		m.appendLog(targetURL, trigger, "error", err.Error(), len(nodes), start)
		return err
	}
	m.logger.Infof("written %d nodes to %s", len(nodes), nodesFilePath)

	newHash := m.computeNodesHash(nodes)
	m.mu.Lock()
	m.lastSubHash = newHash
	if info, statErr := os.Stat(nodesFilePath); statErr == nil {
		m.lastNodesModTime = info.ModTime()
	} else {
		m.lastNodesModTime = time.Now()
	}
	m.status.NodesModified = false
	m.mu.Unlock()

	portMap := m.boxMgr.CurrentPortMap()
	newCfg := m.createNewConfig(nodes)

	if err := m.boxMgr.ReloadWithPortMap(newCfg, portMap); err != nil {
		err = fmt.Errorf("reload failed: %w", err)
		m.logger.Errorf("%v", err)
		m.mu.Lock()
		m.status.LastError = err.Error()
		m.status.LastRefresh = time.Now()
		m.mu.Unlock()
		m.appendLog(targetURL, trigger, "error", err.Error(), len(nodes), start)
		return err
	}

	m.mu.Lock()
	m.status.LastRefresh = time.Now()
	m.status.NodeCount = len(nodes)
	m.status.LastError = ""
	if m.baseCfg != nil {
		m.baseCfg.Nodes = newCfg.Nodes
	}
	m.mu.Unlock()

	m.appendLog(targetURL, trigger, "info", "refresh success", len(nodes), start)
	m.logger.Infof("subscription refresh completed, %d nodes active", len(nodes))
	return nil
}

func (m *Manager) hasSubscription(subURL string) bool {
	for _, item := range m.baseCfg.Subscriptions {
		if strings.TrimSpace(item) == strings.TrimSpace(subURL) {
			return true
		}
	}
	return false
}

// getNodesFilePath returns the path to nodes.txt.
func (m *Manager) getNodesFilePath() string {
	if m.baseCfg.NodesFile != "" {
		return m.baseCfg.NodesFile
	}
	return filepath.Join(filepath.Dir(m.baseCfg.FilePath()), "nodes.txt")
}

// writeNodesToFile writes nodes to a file (one URI per line).
func (m *Manager) writeNodesToFile(path string, nodes []config.NodeConfig) error {
	var lines []string
	for _, node := range nodes {
		lines = append(lines, node.URI)
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// computeNodesHash computes a hash of node URIs for change detection.
func (m *Manager) computeNodesHash(nodes []config.NodeConfig) string {
	var uris []string
	for _, node := range nodes {
		uris = append(uris, node.URI)
	}
	content := strings.Join(uris, "\n")
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// CheckNodesModified checks if nodes.txt has been modified since last refresh.
// Uses file modification time as a fast path to avoid unnecessary file reads.
func (m *Manager) CheckNodesModified() bool {
	m.mu.RLock()
	lastHash := m.lastSubHash
	lastMod := m.lastNodesModTime
	m.mu.RUnlock()

	if lastHash == "" {
		return false // No previous refresh, can't determine modification
	}

	nodesFilePath := m.getNodesFilePath()

	// Fast path: check modification time first
	info, err := os.Stat(nodesFilePath)
	if err != nil {
		return false // File doesn't exist or can't stat
	}
	modTime := info.ModTime()
	if !modTime.After(lastMod) {
		return false // File hasn't been modified
	}

	// Slow path: file was modified, compute hash
	data, err := os.ReadFile(nodesFilePath)
	if err != nil {
		return false // File doesn't exist or can't read
	}

	// Parse nodes from file content
	var nodes []config.NodeConfig
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isProxyURI(line) {
			nodes = append(nodes, config.NodeConfig{URI: line})
		}
	}

	currentHash := m.computeNodesHash(nodes)
	changed := currentHash != lastHash

	// Update cached mod time
	m.mu.Lock()
	m.lastNodesModTime = modTime
	m.mu.Unlock()

	return changed
}

// MarkNodesModified updates the modification status.
func (m *Manager) MarkNodesModified() {
	m.mu.Lock()
	m.status.NodesModified = true
	m.mu.Unlock()
}

// fetchAllSubscriptions fetches nodes from all configured subscription URLs.
// If onlyURL is set, only that URL is fetched from network, others reuse cached nodes.
func (m *Manager) fetchAllSubscriptions(trigger, onlyURL string) ([]config.NodeConfig, error) {
	var allNodes []config.NodeConfig
	var lastErr error

	timeout := m.baseCfg.SubscriptionRefresh.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	for _, subURL := range m.baseCfg.Subscriptions {
		if onlyURL != "" && subURL != onlyURL {
			cached := m.cachedNodesForSubscription(subURL)
			if len(cached) > 0 {
				allNodes = append(allNodes, cached...)
				m.appendLog(subURL, trigger, "info", "reuse cached nodes", len(cached), time.Now())
			} else {
				m.appendLog(subURL, trigger, "warn", "skip refresh and no cached nodes", 0, time.Now())
			}
			continue
		}

		fetchStart := time.Now()
		nodes, err := m.fetchSubscription(subURL, timeout)
		if err != nil {
			m.logger.Warnf("failed to fetch %s: %v", subURL, err)
			m.appendLog(subURL, trigger, "error", err.Error(), 0, fetchStart)
			lastErr = err
			continue
		}
		for idx := range nodes {
			nodes[idx].Source = config.NodeSourceSubscription
			nodes[idx].SourceRef = subURL
		}
		if len(nodes) == 0 {
			m.appendLog(subURL, trigger, "warn", "subscription contains no supported nodes", 0, fetchStart)
		} else {
			m.appendLog(subURL, trigger, "info", "fetched subscription", len(nodes), fetchStart)
		}
		m.logger.Infof("fetched %d nodes from subscription", len(nodes))
		allNodes = append(allNodes, nodes...)
	}

	if len(allNodes) == 0 && lastErr != nil {
		return nil, lastErr
	}

	return allNodes, nil
}

func (m *Manager) cachedNodesForSubscription(subURL string) []config.NodeConfig {
	if m.baseCfg == nil {
		return nil
	}
	out := make([]config.NodeConfig, 0)
	for _, node := range m.baseCfg.Nodes {
		if node.Source != config.NodeSourceSubscription {
			continue
		}
		if node.SourceRef == subURL {
			out = append(out, node)
		}
	}
	if len(out) > 0 {
		return out
	}
	if len(m.baseCfg.Subscriptions) == 1 && m.baseCfg.Subscriptions[0] == subURL {
		for _, node := range m.baseCfg.Nodes {
			if node.Source == config.NodeSourceSubscription {
				out = append(out, node)
			}
		}
	}
	return out
}

func nodesFromSource(nodes []config.NodeConfig, source config.NodeSource) []config.NodeConfig {
	out := make([]config.NodeConfig, 0)
	for _, node := range nodes {
		if node.Source == source {
			out = append(out, node)
		}
	}
	return out
}

func (m *Manager) appendLog(subURL, trigger, level, message string, nodeCount int, startedAt time.Time) {
	entry := monitor.SubscriptionLog{
		Time:         time.Now(),
		Subscription: strings.TrimSpace(subURL),
		Trigger:      strings.TrimSpace(trigger),
		Level:        strings.TrimSpace(level),
		Message:      strings.TrimSpace(message),
		NodeCount:    nodeCount,
	}
	if !startedAt.IsZero() {
		d := time.Since(startedAt)
		if d > 0 {
			entry.DurationMs = d.Milliseconds()
		}
	}

	m.mu.Lock()
	m.logs = append(m.logs, entry)
	if len(m.logs) > maxSubscriptionLogs {
		m.logs = append([]monitor.SubscriptionLog(nil), m.logs[len(m.logs)-maxSubscriptionLogs:]...)
	}
	m.mu.Unlock()
}

// fetchSubscription fetches and parses a single subscription URL.
func (m *Manager) fetchSubscription(subURL string, timeout time.Duration) ([]config.NodeConfig, error) {
	ctx, cancel := context.WithTimeout(m.ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")

	// Use custom HTTP client with connection pooling
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	// Limit read size to prevent memory exhaustion
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	limitedReader := io.LimitReader(resp.Body, maxBodySize)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return parseSubscriptionContent(string(body))
}

// createNewConfig creates a new config with updated nodes while preserving other settings.
func (m *Manager) createNewConfig(nodes []config.NodeConfig) *config.Config {
	// Deep copy base config
	newCfg := *m.baseCfg

	staticNodes := make([]config.NodeConfig, 0, len(newCfg.Nodes))
	for _, n := range newCfg.Nodes {
		if n.Source == config.NodeSourceSubscription {
			continue
		}
		staticNodes = append(staticNodes, n)
	}

	allNodes := make([]config.NodeConfig, 0, len(staticNodes)+len(nodes))
	allNodes = append(allNodes, staticNodes...)
	allNodes = append(allNodes, nodes...)

	// Assign port numbers to nodes in multi-port mode
	if newCfg.Mode == "multi-port" {
		portCursor := newCfg.MultiPort.BasePort
		for i := range allNodes {
			allNodes[i].Port = portCursor
			portCursor++
			// Apply default credentials
			if allNodes[i].Username == "" {
				allNodes[i].Username = newCfg.MultiPort.Username
				allNodes[i].Password = newCfg.MultiPort.Password
			}
		}
	}

	// Process node names
	for i := range allNodes {
		allNodes[i].Name = strings.TrimSpace(allNodes[i].Name)
		allNodes[i].URI = strings.TrimSpace(allNodes[i].URI)

		// Extract name from URI fragment if not provided
		if allNodes[i].Name == "" {
			if parsed, err := url.Parse(allNodes[i].URI); err == nil && parsed.Fragment != "" {
				if decoded, err := url.QueryUnescape(parsed.Fragment); err == nil {
					allNodes[i].Name = decoded
				} else {
					allNodes[i].Name = parsed.Fragment
				}
			}
		}
		if allNodes[i].Name == "" {
			allNodes[i].Name = fmt.Sprintf("node-%d", i)
		}
	}

	newCfg.Nodes = allNodes
	return &newCfg
}

// parseSubscriptionContent parses subscription content in various formats.
// Supported: URI list, base64 URI list, Clash/Mihomo YAML with proxies.
func parseSubscriptionContent(content string) ([]config.NodeConfig, error) {
	content = strings.TrimSpace(content)

	if maybeClashYAML(content) {
		return parseClashYAML(content)
	}

	// Check if it's base64 encoded
	if isBase64(content) {
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(content)
			if err != nil {
				return parseNodesFromContent(content)
			}
		}
		content = string(decoded)
		if maybeClashYAML(content) {
			return parseClashYAML(content)
		}
	}

	// Parse as plain text (one URI per line)
	return parseNodesFromContent(content)
}

func maybeClashYAML(content string) bool {
	if content == "" {
		return false
	}
	return strings.Contains(content, "\nproxies:") || strings.HasPrefix(content, "proxies:")
}

func isBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return false
	}
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if strings.Contains(s, "://") {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		_, err = base64.RawStdEncoding.DecodeString(s)
	}
	return err == nil
}

func parseNodesFromContent(content string) ([]config.NodeConfig, error) {
	var nodes []config.NodeConfig
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isProxyURI(line) {
			nodes = append(nodes, config.NodeConfig{URI: line})
		}
	}
	return nodes, nil
}

func isProxyURI(s string) bool {
	schemes := []string{"vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "hy2://"}
	lower := strings.ToLower(s)
	for _, scheme := range schemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

type clashConfig struct {
	Proxies []clashProxy `yaml:"proxies"`
}

type clashProxy struct {
	Name              string                 `yaml:"name"`
	Type              string                 `yaml:"type"`
	Server            string                 `yaml:"server"`
	Port              int                    `yaml:"port"`
	UUID              string                 `yaml:"uuid"`
	Password          string                 `yaml:"password"`
	Cipher            string                 `yaml:"cipher"`
	Network           string                 `yaml:"network"`
	TLS               bool                   `yaml:"tls"`
	SkipCertVerify    bool                   `yaml:"skip-cert-verify"`
	ServerName        string                 `yaml:"servername"`
	SNI               string                 `yaml:"sni"`
	Flow              string                 `yaml:"flow"`
	WSOpts            *clashWSOptions        `yaml:"ws-opts"`
	GrpcOpts          *clashGrpcOptions      `yaml:"grpc-opts"`
	RealityOpts       *clashRealityOptions   `yaml:"reality-opts"`
	ClientFingerprint string                 `yaml:"client-fingerprint"`
	Plugin            string                 `yaml:"plugin"`
	PluginOpts        map[string]interface{} `yaml:"plugin-opts"`
}

type clashWSOptions struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type clashGrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name"`
}

type clashRealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

func parseClashYAML(content string) ([]config.NodeConfig, error) {
	var clash clashConfig
	if err := yaml.Unmarshal([]byte(content), &clash); err != nil {
		return nil, fmt.Errorf("parse clash yaml: %w", err)
	}

	nodes := make([]config.NodeConfig, 0, len(clash.Proxies))
	for _, proxy := range clash.Proxies {
		uri := convertClashProxyToURI(proxy)
		if uri == "" {
			continue
		}
		nodes = append(nodes, config.NodeConfig{
			Name: strings.TrimSpace(proxy.Name),
			URI:  uri,
		})
	}
	return nodes, nil
}

func convertClashProxyToURI(p clashProxy) string {
	if strings.TrimSpace(p.Server) == "" || p.Port <= 0 {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "vmess":
		if strings.TrimSpace(p.UUID) == "" {
			return ""
		}
		return buildVMessURI(p)
	case "vless":
		if strings.TrimSpace(p.UUID) == "" {
			return ""
		}
		return buildVLESSURI(p)
	case "trojan":
		if strings.TrimSpace(p.Password) == "" {
			return ""
		}
		return buildTrojanURI(p)
	case "ss", "shadowsocks":
		if strings.TrimSpace(p.Cipher) == "" || strings.TrimSpace(p.Password) == "" {
			return ""
		}
		return buildShadowsocksURI(p)
	case "hysteria2", "hy2":
		if strings.TrimSpace(p.Password) == "" {
			return ""
		}
		return buildHysteria2URI(p)
	default:
		return ""
	}
}

func buildVMessURI(p clashProxy) string {
	params := url.Values{}
	if p.Network != "" && p.Network != "tcp" {
		params.Set("type", p.Network)
	}
	if p.TLS {
		params.Set("security", "tls")
		if p.ServerName != "" {
			params.Set("sni", p.ServerName)
		} else if p.SNI != "" {
			params.Set("sni", p.SNI)
		}
	}
	if p.WSOpts != nil {
		if p.WSOpts.Path != "" {
			params.Set("path", p.WSOpts.Path)
		}
		if host, ok := p.WSOpts.Headers["Host"]; ok {
			params.Set("host", host)
		}
	}
	if p.ClientFingerprint != "" {
		params.Set("fp", p.ClientFingerprint)
	}

	query := ""
	if len(params) > 0 {
		query = "?" + params.Encode()
	}

	name := strings.TrimSpace(p.Name)
	return fmt.Sprintf("vmess://%s@%s:%d%s#%s", p.UUID, p.Server, p.Port, query, url.QueryEscape(name))
}

func buildVLESSURI(p clashProxy) string {
	params := url.Values{}
	params.Set("encryption", "none")

	if p.Network != "" && p.Network != "tcp" {
		params.Set("type", p.Network)
	}
	if p.Flow != "" {
		params.Set("flow", p.Flow)
	}
	if p.TLS {
		params.Set("security", "tls")
		if p.ServerName != "" {
			params.Set("sni", p.ServerName)
		} else if p.SNI != "" {
			params.Set("sni", p.SNI)
		}
	}
	if p.RealityOpts != nil {
		params.Set("security", "reality")
		if p.RealityOpts.PublicKey != "" {
			params.Set("pbk", p.RealityOpts.PublicKey)
		}
		if p.RealityOpts.ShortID != "" {
			params.Set("sid", p.RealityOpts.ShortID)
		}
		if p.ServerName != "" {
			params.Set("sni", p.ServerName)
		}
	}
	if p.WSOpts != nil {
		if p.WSOpts.Path != "" {
			params.Set("path", p.WSOpts.Path)
		}
		if host, ok := p.WSOpts.Headers["Host"]; ok {
			params.Set("host", host)
		}
	}
	if p.GrpcOpts != nil && p.GrpcOpts.GrpcServiceName != "" {
		params.Set("serviceName", p.GrpcOpts.GrpcServiceName)
	}
	if p.ClientFingerprint != "" {
		params.Set("fp", p.ClientFingerprint)
	}

	name := strings.TrimSpace(p.Name)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", p.UUID, p.Server, p.Port, params.Encode(), url.QueryEscape(name))
}

func buildTrojanURI(p clashProxy) string {
	params := url.Values{}
	if p.Network != "" && p.Network != "tcp" {
		params.Set("type", p.Network)
	}
	if p.ServerName != "" {
		params.Set("sni", p.ServerName)
	} else if p.SNI != "" {
		params.Set("sni", p.SNI)
	}
	if p.SkipCertVerify {
		params.Set("allowInsecure", "1")
	}
	if p.WSOpts != nil {
		if p.WSOpts.Path != "" {
			params.Set("path", p.WSOpts.Path)
		}
		if host, ok := p.WSOpts.Headers["Host"]; ok {
			params.Set("host", host)
		}
	}
	if p.ClientFingerprint != "" {
		params.Set("fp", p.ClientFingerprint)
	}

	query := ""
	if len(params) > 0 {
		query = "?" + params.Encode()
	}

	name := strings.TrimSpace(p.Name)
	return fmt.Sprintf("trojan://%s@%s:%d%s#%s", p.Password, p.Server, p.Port, query, url.QueryEscape(name))
}

func buildShadowsocksURI(p clashProxy) string {
	userInfo := base64.StdEncoding.EncodeToString([]byte(p.Cipher + ":" + p.Password))
	name := strings.TrimSpace(p.Name)
	return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, p.Server, p.Port, url.QueryEscape(name))
}

func buildHysteria2URI(p clashProxy) string {
	params := url.Values{}
	if p.ServerName != "" {
		params.Set("sni", p.ServerName)
	} else if p.SNI != "" {
		params.Set("sni", p.SNI)
	}
	if p.SkipCertVerify {
		params.Set("insecure", "1")
	}

	query := ""
	if len(params) > 0 {
		query = "?" + params.Encode()
	}
	name := strings.TrimSpace(p.Name)
	return fmt.Sprintf("hysteria2://%s@%s:%d%s#%s", p.Password, p.Server, p.Port, query, url.QueryEscape(name))
}

type defaultLogger struct{}

func (defaultLogger) Infof(format string, args ...any) {
	log.Printf("[subscription] "+format, args...)
}

func (defaultLogger) Warnf(format string, args ...any) {
	log.Printf("[subscription] WARN: "+format, args...)
}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf("[subscription] ERROR: "+format, args...)
}
