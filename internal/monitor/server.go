package monitor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/storage"
	"golang.org/x/sync/semaphore"
)

// Session represents a user session with expiration.
type Session struct {
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NodeManager exposes config node CRUD and reload operations.
type NodeManager interface {
	ListConfigNodes(ctx context.Context) ([]config.NodeConfig, error)
	CreateNode(ctx context.Context, node config.NodeConfig) (config.NodeConfig, error)
	UpdateNode(ctx context.Context, name string, node config.NodeConfig) (config.NodeConfig, error)
	DeleteNode(ctx context.Context, name string) error
	TriggerReload(ctx context.Context) error
}

// Sentinel errors for node operations.
var (
	ErrNodeNotFound = errors.New("节点不存在")
	ErrNodeConflict = errors.New("节点名称或端口已存在")
	ErrInvalidNode  = errors.New("无效的节点配置")
)

// SubscriptionRefresher interface for subscription manager.
type SubscriptionRefresher interface {
	RefreshNow() error
	Status() SubscriptionStatus
}

// SubscriptionStatus represents subscription refresh status.
type SubscriptionStatus struct {
	LastRefresh   time.Time `json:"last_refresh"`
	NextRefresh   time.Time `json:"next_refresh"`
	NodeCount     int       `json:"node_count"`
	LastError     string    `json:"last_error,omitempty"`
	RefreshCount  int       `json:"refresh_count"`
	IsRefreshing  bool      `json:"is_refreshing"`
	NodesModified bool      `json:"nodes_modified"` // True if nodes.txt was modified since last refresh
}

// SubscriptionLog describes one refresh record for a subscription URL.
type SubscriptionLog struct {
	Time         time.Time `json:"time"`
	Subscription string    `json:"subscription"`
	Trigger      string    `json:"trigger"`
	Level        string    `json:"level"`
	Message      string    `json:"message"`
	NodeCount    int       `json:"node_count,omitempty"`
	DurationMs   int64     `json:"duration_ms,omitempty"`
}

type runtimeConfigManager interface {
	GetRuntimeConfig(ctx context.Context) (storage.RuntimeConfig, error)
	UpdateRuntimeConfig(ctx context.Context, runtime storage.RuntimeConfig) (storage.RuntimeConfig, error)
}

// Server exposes HTTP endpoints for monitoring.
type Server struct {
	cfg    Config
	cfgMu  sync.RWMutex   // 保护动态配置字段
	cfgSrc *config.Config // 可持久化的配置对象
	mgr    *Manager
	srv    *http.Server
	logger *log.Logger

	// Session management
	sessionMu  sync.RWMutex
	sessions   map[string]*Session
	sessionTTL time.Duration

	// Concurrency control
	probeSem *semaphore.Weighted

	subRefresher SubscriptionRefresher
	nodeMgr      NodeManager
}

// NewServer constructs a server; it can be nil when disabled.
func NewServer(cfg Config, mgr *Manager, logger *log.Logger) *Server {
	if !cfg.Enabled || mgr == nil {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}

	// Calculate max concurrent probes
	maxConcurrentProbes := int64(runtime.NumCPU() * 4)
	if maxConcurrentProbes < 10 {
		maxConcurrentProbes = 10
	}

	s := &Server{
		cfg:        cfg,
		mgr:        mgr,
		logger:     logger,
		sessions:   make(map[string]*Session),
		sessionTTL: 24 * time.Hour,
		probeSem:   semaphore.NewWeighted(maxConcurrentProbes),
	}

	// Start session cleanup goroutine
	go s.cleanupExpiredSessions()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/docs", s.handleAPIDocs)
	mux.HandleFunc("/api/auth", s.handleAuth)
	mux.HandleFunc("/api/settings", s.withAuth(s.handleSettings))
	mux.HandleFunc("/api/runtime-config", s.withAuth(s.handleRuntimeConfig))
	mux.HandleFunc("/api/pools", s.withAuth(s.handlePools))
	mux.HandleFunc("/api/pools/", s.withAuth(s.handlePoolItem))
	mux.HandleFunc("/api/nodes", s.withAuth(s.handleNodes))
	mux.HandleFunc("/api/nodes/config", s.withAuth(s.handleConfigNodes))
	mux.HandleFunc("/api/nodes/config/", s.withAuth(s.handleConfigNodeItem))
	mux.HandleFunc("/api/nodes/ban", s.withAuth(s.handleNodeBan))
	mux.HandleFunc("/api/nodes/probe-all", s.withAuth(s.handleProbeAll))
	mux.HandleFunc("/api/nodes/", s.withAuth(s.handleNodeAction))
	mux.HandleFunc("/api/debug", s.withAuth(s.handleDebug))
	mux.HandleFunc("/api/blacklist", s.withAuth(s.handleBlacklist))
	mux.HandleFunc("/api/export", s.withAuth(s.handleExport))
	mux.HandleFunc("/api/subscription/status", s.withAuth(s.handleSubscriptionStatus))
	mux.HandleFunc("/api/subscription/refresh", s.withAuth(s.handleSubscriptionRefresh))
	mux.HandleFunc("/api/subscriptions", s.withAuth(s.handleSubscriptions))
	mux.HandleFunc("/api/subscriptions/", s.withAuth(s.handleSubscriptionItem))
	mux.HandleFunc("/api/script-sources", s.withAuth(s.handleScriptSources))
	mux.HandleFunc("/api/script-sources/test", s.withAuth(s.handleScriptSourceTest))
	mux.HandleFunc("/api/script-sources/", s.withAuth(s.handleScriptSourceItem))
	mux.HandleFunc("/api/reload", s.withAuth(s.handleReload))
	s.srv = &http.Server{Addr: cfg.Listen, Handler: s.withCORS(mux)}
	return s
}

// SetSubscriptionRefresher sets the subscription refresher for API endpoints.
func (s *Server) SetSubscriptionRefresher(sr SubscriptionRefresher) {
	if s != nil {
		s.subRefresher = sr
	}
}

// SetNodeManager enables config-node CRUD endpoints.
func (s *Server) SetNodeManager(nm NodeManager) {
	if s != nil {
		s.nodeMgr = nm
	}
}

// SetConfig binds the persistable config object for settings API.
func (s *Server) SetConfig(cfg *config.Config) {
	if s == nil {
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.cfgSrc = cfg
	if cfg != nil {
		s.cfg.ExternalIP = cfg.ExternalIP
		s.cfg.ProbeTarget = cfg.Management.ProbeTarget
		s.cfg.SkipCertVerify = cfg.SkipCertVerify
		s.cfg.ProxyUsername = cfg.Listener.Username
		s.cfg.ProxyPassword = cfg.Listener.Password
	}
}

// getSettings returns current dynamic settings (thread-safe).
func (s *Server) getSettings() (externalIP, probeTarget string, skipCertVerify bool, proxyUsername, proxyPassword string) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.ExternalIP, s.cfg.ProbeTarget, s.cfg.SkipCertVerify, s.cfg.ProxyUsername, s.cfg.ProxyPassword
}

// updateSettings updates dynamic settings and persists to config file.
func (s *Server) updateSettings(externalIP, probeTarget string, skipCertVerify bool, proxyUsername, proxyPassword string) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	s.cfg.ExternalIP = externalIP
	s.cfg.ProbeTarget = probeTarget
	s.cfg.SkipCertVerify = skipCertVerify
	s.cfg.ProxyUsername = proxyUsername
	s.cfg.ProxyPassword = proxyPassword

	if settingsSaver, ok := s.nodeMgr.(interface {
		SaveSettings(ctx context.Context, externalIP, probeTarget string, skipCertVerify bool, proxyUsername, proxyPassword string) error
	}); ok {
		if err := settingsSaver.SaveSettings(context.Background(), externalIP, probeTarget, skipCertVerify, proxyUsername, proxyPassword); err != nil {
			return fmt.Errorf("保存配置失败: %w", err)
		}
		return nil
	}

	if s.cfgSrc == nil {
		return errors.New("配置存储未初始化")
	}

	s.cfgSrc.ExternalIP = externalIP
	s.cfgSrc.Management.ProbeTarget = probeTarget
	s.cfgSrc.SkipCertVerify = skipCertVerify
	s.cfgSrc.Listener.Username = proxyUsername
	s.cfgSrc.Listener.Password = proxyPassword
	if len(s.cfgSrc.NamedPools) > 0 {
		s.cfgSrc.NamedPools[0].Listener.Username = proxyUsername
		s.cfgSrc.NamedPools[0].Listener.Password = proxyPassword
	}

	if err := s.cfgSrc.SaveSettings(); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	return nil
}

// Start launches the HTTP server.
func (s *Server) Start(ctx context.Context) {
	if s == nil || s.srv == nil {
		return
	}
	s.logger.Printf("Starting monitor server on %s", s.cfg.Listen)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Printf("❌ Monitor server error: %v", err)
		}
	}()
	// Give server a moment to start and check for immediate errors
	time.Sleep(100 * time.Millisecond)
	s.logger.Printf("✅ Monitor server started on http://%s", s.cfg.Listen)

	go func() {
		<-ctx.Done()
		s.Shutdown(context.Background())
	}()
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) {
	if s == nil || s.srv == nil {
		return
	}
	_ = s.srv.Shutdown(ctx)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.serveFrontendDist(w, r) {
		return
	}

	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	distDir := strings.TrimSpace(s.cfg.FrontendDist)
	if distDir == "" {
		distDir = "web/dist"
	}
	_, _ = fmt.Fprintf(w, "frontend assets not found at %q; run `cd web && npm run build` and restart the service\n", distDir)
}

func (s *Server) serveFrontendDist(w http.ResponseWriter, r *http.Request) bool {
	distDir := strings.TrimSpace(s.cfg.FrontendDist)
	if distDir == "" {
		return false
	}
	absDist, err := filepath.Abs(distDir)
	if err != nil {
		return false
	}
	if info, err := os.Stat(absDist); err != nil || !info.IsDir() {
		return false
	}

	requestPath := strings.TrimPrefix(r.URL.Path, "/")
	requestPath = filepath.Clean(requestPath)
	if requestPath == "." || requestPath == string(filepath.Separator) {
		requestPath = "index.html"
	}

	target := filepath.Join(absDist, requestPath)
	if !pathInside(absDist, target) {
		w.WriteHeader(http.StatusForbidden)
		return true
	}

	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		if strings.EqualFold(filepath.Ext(target), ".html") {
			setNoCacheHeaders(w)
		}
		http.ServeFile(w, r, target)
		return true
	}

	indexFile := filepath.Join(absDist, "index.html")
	if info, err := os.Stat(indexFile); err == nil && !info.IsDir() {
		setNoCacheHeaders(w)
		http.ServeFile(w, r, indexFile)
		return true
	}

	return false
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func pathInside(root, candidate string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	if absCandidate == absRoot {
		return true
	}
	prefix := absRoot + string(os.PathSeparator)
	return strings.HasPrefix(absCandidate, prefix)
}

func normalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, "/")
	return raw
}

func (s *Server) allowedOrigin(origin string) string {
	origin = normalizeOrigin(origin)
	if origin == "" {
		return ""
	}
	for _, allow := range s.cfg.AllowedOrigins {
		normalized := normalizeOrigin(allow)
		if normalized == "*" {
			return "*"
		}
		if strings.EqualFold(normalized, origin) {
			return origin
		}
	}
	return ""
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	if next == nil {
		return http.NewServeMux()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if allowed := s.allowedOrigin(origin); allowed != "" {
				if allowed == "*" {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", allowed)
					w.Header().Set("Vary", "Origin")
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
			}
		}

		if r.Method == http.MethodOptions && strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// 只返回初始检查通过的可用节点
	filtered := s.mgr.SnapshotFiltered(true)
	allNodes := s.mgr.Snapshot()
	totalNodes := len(allNodes)

	// Calculate region statistics
	regionStats := make(map[string]int)
	regionHealthy := make(map[string]int)
	for _, snap := range allNodes {
		region := snap.Region
		if region == "" {
			region = "other"
		}
		regionStats[region]++
		// Count healthy nodes per region
		if snap.InitialCheckDone && snap.Available && !snap.Blacklisted {
			regionHealthy[region]++
		}
	}

	payload := map[string]any{
		"nodes":          filtered,
		"total_nodes":    totalNodes,
		"region_stats":   regionStats,
		"region_healthy": regionHealthy,
	}
	writeJSON(w, payload)
}

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snapshots := s.mgr.Snapshot()
	var totalCalls, totalSuccess int64
	debugNodes := make([]map[string]any, 0, len(snapshots))
	for _, snap := range snapshots {
		totalCalls += snap.SuccessCount + int64(snap.FailureCount)
		totalSuccess += snap.SuccessCount
		debugNodes = append(debugNodes, map[string]any{
			"tag":                snap.Tag,
			"name":               snap.Name,
			"mode":               snap.Mode,
			"port":               snap.Port,
			"failure_count":      snap.FailureCount,
			"success_count":      snap.SuccessCount,
			"active_connections": snap.ActiveConnections,
			"last_latency_ms":    snap.LastLatencyMs,
			"last_success":       snap.LastSuccess,
			"last_failure":       snap.LastFailure,
			"last_error":         snap.LastError,
			"blacklisted":        snap.Blacklisted,
			"domain_blacklist":   snap.DomainBlacklist,
			"timeline":           snap.Timeline,
		})
	}
	var successRate float64
	if totalCalls > 0 {
		successRate = float64(totalSuccess) / float64(totalCalls) * 100
	}
	writeJSON(w, map[string]any{
		"nodes":         debugNodes,
		"total_calls":   totalCalls,
		"total_success": totalSuccess,
		"success_rate":  successRate,
	})
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snapshots := s.mgr.Snapshot()
	items := make([]map[string]any, 0, len(snapshots))
	for _, snap := range snapshots {
		if len(snap.DomainBlacklist) == 0 {
			continue
		}
		items = append(items, map[string]any{
			"tag":              snap.Tag,
			"name":             snap.Name,
			"domain_blacklist": snap.DomainBlacklist,
		})
	}
	writeJSON(w, map[string]any{"items": items})
}

func (s *Server) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/nodes/"), "/")
	if len(parts) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tag := parts[0]
	if tag == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if decoded, err := url.PathUnescape(tag); err == nil {
		tag = decoded
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "probe":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		latency, err := s.mgr.Probe(ctx, tag)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		latencyMs := latency.Milliseconds()
		if latencyMs == 0 && latency > 0 {
			latencyMs = 1 // Round up sub-millisecond latencies to 1ms
		}
		writeJSON(w, map[string]any{"message": "探测成功", "latency_ms": latencyMs})
	case "release":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := s.mgr.Release(tag); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"message": "已解除拉黑"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) handleNodeBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeIP   string `json:"node_ip"`
		PoolName string `json:"pool_name"`
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "请求格式错误"})
		return
	}

	nodeIP := strings.TrimSpace(req.NodeIP)
	poolName := strings.TrimSpace(req.PoolName)
	if nodeIP == "" || poolName == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "node_ip 和 pool_name 不能为空"})
		return
	}

	duration, err := time.ParseDuration(strings.TrimSpace(req.Duration))
	if err != nil || duration <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "duration 格式无效，示例: 30m, 2h"})
		return
	}

	matcher, err := buildNodeIPMatcher(nodeIP)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	snapshots := s.mgr.Snapshot()
	matchedTags := make([]string, 0)
	bannedUntil := time.Time{}

	for _, snap := range snapshots {
		if !strings.EqualFold(strings.TrimSpace(snap.PoolName), poolName) {
			continue
		}
		nodeIP := strings.TrimSpace(snap.NodeIP)
		host := extractHostFromNodeURI(snap.URI)
		if !matcher(nodeIP, snap.URI) && !matcher(host, snap.URI) {
			continue
		}
		until, banErr := s.mgr.Ban(snap.Tag, duration)
		if banErr != nil {
			continue
		}
		if until.After(bannedUntil) {
			bannedUntil = until
		}
		matchedTags = append(matchedTags, snap.Tag)
	}

	if len(matchedTags) == 0 {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": "未找到符合条件的节点"})
		return
	}

	writeJSON(w, map[string]any{
		"message":      "节点已封禁",
		"pool_name":    poolName,
		"matched":      len(matchedTags),
		"matched_tags": matchedTags,
		"banned_until": bannedUntil,
	})
}

func buildNodeIPMatcher(nodeIP string) (func(host, rawURI string) bool, error) {
	nodeIP = strings.TrimSpace(nodeIP)
	if nodeIP == "" {
		return nil, errors.New("node_ip 不能为空")
	}
	if parsed := net.ParseIP(nodeIP); parsed != nil {
		normalized := parsed.String()
		return func(host, _ string) bool {
			parsedHost := net.ParseIP(strings.TrimSpace(host))
			if parsedHost == nil {
				return false
			}
			return parsedHost.String() == normalized
		}, nil
	}
	re, err := regexp.Compile(nodeIP)
	if err != nil {
		return nil, fmt.Errorf("node_ip 正则无效: %w", err)
	}
	return func(host, rawURI string) bool {
		return re.MatchString(host) || re.MatchString(rawURI)
	}, nil
}

func extractHostFromNodeURI(rawURI string) string {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return ""
	}
	if parsed, err := url.Parse(rawURI); err == nil {
		if host := strings.TrimSpace(parsed.Hostname()); host != "" {
			return host
		}
	}

	lower := strings.ToLower(rawURI)
	if strings.HasPrefix(lower, "vmess://") {
		encoded := strings.TrimSpace(strings.TrimPrefix(rawURI, "vmess://"))
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(encoded)
		}
		if err == nil {
			var vmess struct {
				Add string `json:"add"`
			}
			if jsonErr := json.Unmarshal(decoded, &vmess); jsonErr == nil {
				return strings.TrimSpace(vmess.Add)
			}
		}
	}

	if strings.HasPrefix(lower, "ss://") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(rawURI, "ss://"))
		if idx := strings.Index(trimmed, "#"); idx >= 0 {
			trimmed = trimmed[:idx]
		}
		if idx := strings.LastIndex(trimmed, "@"); idx >= 0 && idx+1 < len(trimmed) {
			hostPort := trimmed[idx+1:]
			if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
				return strings.TrimSpace(parsedHost)
			}
			if colon := strings.LastIndex(hostPort, ":"); colon > 0 {
				return strings.TrimSpace(hostPort[:colon])
			}
			return strings.TrimSpace(hostPort)
		}
	}

	return ""
}

// handleProbeAll probes all nodes in batches and returns results via SSE
func (s *Server) handleProbeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Get all nodes
	snapshots := s.mgr.Snapshot()
	total := len(snapshots)
	if total == 0 {
		fmt.Fprintf(w, "data: %s\n\n", `{"type":"complete","total":0,"success":0,"failed":0}`)
		flusher.Flush()
		return
	}

	// Send start event
	fmt.Fprintf(w, "data: %s\n\n", fmt.Sprintf(`{"type":"start","total":%d}`, total))
	flusher.Flush()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	// Probe all nodes with semaphore control
	type probeResult struct {
		tag     string
		name    string
		latency int64
		err     string
	}
	results := make(chan probeResult, total)
	var wg sync.WaitGroup

	// Launch probes with semaphore control
	for _, snap := range snapshots {
		wg.Add(1)
		go func(snap Snapshot) {
			defer wg.Done()

			// Acquire semaphore permit
			if err := s.probeSem.Acquire(ctx, 1); err != nil {
				results <- probeResult{
					tag:  snap.Tag,
					name: snap.Name,
					err:  "probe cancelled: " + err.Error(),
				}
				return
			}
			defer s.probeSem.Release(1)

			// Execute probe
			probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
			defer probeCancel()

			latency, err := s.mgr.Probe(probeCtx, snap.Tag)
			if err != nil {
				results <- probeResult{
					tag:     snap.Tag,
					name:    snap.Name,
					latency: -1,
					err:     err.Error(),
				}
			} else {
				results <- probeResult{
					tag:     snap.Tag,
					name:    snap.Name,
					latency: latency.Milliseconds(),
					err:     "",
				}
			}
		}(snap)
	}

	// Wait for all probes to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	successCount := 0
	failedCount := 0
	count := 0

	for result := range results {
		count++
		if result.err != "" {
			failedCount++
		} else {
			successCount++
		}

		progress := float64(count) / float64(total) * 100
		status := "success"
		if result.err != "" {
			status = "error"
		}

		eventData := fmt.Sprintf(`{"type":"progress","tag":"%s","name":"%s","latency":%d,"status":"%s","error":"%s","current":%d,"total":%d,"progress":%.1f}`,
			result.tag, result.name, result.latency, status, result.err, count, total, progress)
		fmt.Fprintf(w, "data: %s\n\n", eventData)
		flusher.Flush()
	}

	// Send complete event
	fmt.Fprintf(w, "data: %s\n\n", fmt.Sprintf(`{"type":"complete","total":%d,"success":%d,"failed":%d}`, total, successCount, failedCount))
	flusher.Flush()
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

// withAuth 认证中间件，如果配置了密码则需要验证
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 如果没有配置密码，直接放行
		if s.cfg.Password == "" {
			next(w, r)
			return
		}

		// 检查 Cookie 中的 session token
		cookie, err := r.Cookie("session_token")
		if err == nil && s.validateSession(cookie.Value) {
			next(w, r)
			return
		}

		// 检查 Authorization header (Bearer token)
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if s.validateSession(token) {
				next(w, r)
				return
			}
		}

		// 未授权
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "未授权，请先登录"})
	}
}

// handleAuth 处理登录认证
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	// 如果没有配置密码，直接返回成功（不需要token）
	if s.cfg.Password == "" {
		writeJSON(w, map[string]any{"message": "无需密码", "no_password": true})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "请求格式错误"})
		return
	}

	// 使用 constant-time 比较防止时序攻击
	if !secureCompareStrings(req.Password, s.cfg.Password) {
		// 添加随机延迟防止暴力破解
		time.Sleep(time.Duration(100+mathrand.Intn(200)) * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "密码错误"})
		return
	}

	// 创建新会话
	session, err := s.createSession()
	if err != nil {
		s.logger.Printf("Failed to create session: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": "服务器错误"})
		return
	}

	// 设置 HttpOnly Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // 生产环境应启用 HTTPS 并设为 true
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.sessionTTL.Seconds()),
	})

	writeJSON(w, map[string]any{
		"message": "登录成功",
		"token":   session.Token,
	})
}

// handleAPIDocs exposes a minimal Key-Value API document.
func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, map[string]any{
		"service": "easy_proxies",
		"format":  "key_value",
		"auth":    "除 /api/auth 与 /api/docs 外，其余接口均需认证",
		"endpoints": map[string]string{
			"GET /api/docs":                           "API 文档（Key-Value）",
			"POST /api/auth":                          "登录并获取 session token",
			"GET /api/nodes":                          "获取节点监控列表",
			"POST /api/nodes/{tag}/probe":             "探测单节点延迟",
			"POST /api/nodes/{tag}/release":           "解除单节点拉黑状态",
			"POST /api/nodes/ban":                     "按业务池主动封禁节点",
			"POST /api/nodes/probe-all":               "批量探测节点（SSE）",
			"GET /api/nodes/config":                   "读取配置节点列表",
			"POST /api/nodes/config":                  "新增配置节点",
			"PUT /api/nodes/config/{name}":            "更新配置节点",
			"DELETE /api/nodes/config/{name}":         "删除配置节点",
			"GET /api/debug":                          "读取调试统计",
			"GET /api/blacklist":                      "读取节点域名黑名单",
			"GET /api/export":                         "导出可用代理 URI",
			"GET /api/settings":                       "读取动态设置",
			"PUT /api/settings":                       "更新动态设置",
			"GET /api/runtime-config":                 "读取完整运行配置（数据库）",
			"PUT /api/runtime-config":                 "更新完整运行配置（数据库）",
			"GET /api/pools":                          "读取命名业务池列表",
			"POST /api/pools":                         "创建命名业务池",
			"PUT /api/pools/{name}":                   "更新命名业务池",
			"DELETE /api/pools/{name}":                "删除命名业务池",
			"GET /api/subscription/status":            "读取订阅状态",
			"POST /api/subscription/refresh":          "刷新全部订阅",
			"GET /api/subscriptions":                  "读取订阅列表",
			"POST /api/subscriptions":                 "新增订阅",
			"PUT /api/subscriptions/{index}":          "更新订阅",
			"DELETE /api/subscriptions/{index}":       "删除订阅",
			"POST /api/subscriptions/{index}/refresh": "刷新指定订阅",
			"GET /api/subscriptions/{index}/logs":     "读取指定订阅日志",
			"GET /api/script-sources":                 "读取脚本源列表",
			"POST /api/script-sources":                "新增脚本源",
			"PUT /api/script-sources/{id}":            "更新脚本源",
			"DELETE /api/script-sources/{id}":         "删除脚本源",
			"POST /api/script-sources/{id}/run":       "运行脚本源并导入节点",
			"POST /api/script-sources/test":           "测试脚本（不保存、不导入）",
			"POST /api/script-sources/{id}/test":      "测试脚本源（不导入）",
			"POST /api/reload":                        "重载配置并重启代理实例",
		},
	})
}

// handleExport 导出所有可用代理池节点的 HTTP 代理 URI，每行一个
// 在 hybrid 模式下，只导出 multi-port 格式（每节点独立端口）
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 只导出初始检查通过的可用节点
	snapshots := s.mgr.SnapshotFiltered(true)
	var lines []string

	for _, snap := range snapshots {
		// 只导出有监听地址和端口的节点
		if snap.ListenAddress == "" || snap.Port == 0 {
			continue
		}

		// 在 hybrid 和 multi-port 模式下，导出每节点独立端口
		// 在 pool 模式下，所有节点共享同一端口，也正常导出
		listenAddr := snap.ListenAddress
		if listenAddr == "0.0.0.0" || listenAddr == "::" {
			if extIP, _, _, _, _ := s.getSettings(); extIP != "" {
				listenAddr = extIP
			}
		}

		var proxyURI string
		if s.cfg.ProxyUsername != "" && s.cfg.ProxyPassword != "" {
			proxyURI = fmt.Sprintf("http://%s:%s@%s:%d",
				s.cfg.ProxyUsername, s.cfg.ProxyPassword,
				listenAddr, snap.Port)
		} else {
			proxyURI = fmt.Sprintf("http://%s:%d", listenAddr, snap.Port)
		}
		lines = append(lines, proxyURI)
	}

	// 返回纯文本，每行一个 URI
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=proxy_pool.txt")
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}

func (s *Server) handleRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	runtimeMgr, ok := s.nodeMgr.(runtimeConfigManager)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "运行配置管理未启用（请启用数据库存储）"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		runtimeCfg, err := runtimeMgr.GetRuntimeConfig(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{
			"config":             runtimeCfg,
			"database_managed":   true,
			"need_reload":        false,
			"supports_apply_now": true,
		})
	case http.MethodPut:
		var req struct {
			Config   storage.RuntimeConfig `json:"config"`
			ApplyNow bool                  `json:"apply_now"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}

		updated, err := runtimeMgr.UpdateRuntimeConfig(r.Context(), req.Config)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		reloaded := false
		if req.ApplyNow {
			if err := s.nodeMgr.TriggerReload(r.Context()); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, map[string]any{
					"error":          fmt.Sprintf("配置已保存到数据库，但重载失败: %v", err),
					"saved":          true,
					"need_reload":    true,
					"runtime_config": updated,
				})
				return
			}
			reloaded = true
		}

		writeJSON(w, map[string]any{
			"message":        "运行配置已保存",
			"runtime_config": updated,
			"saved":          true,
			"reloaded":       reloaded,
			"need_reload":    !reloaded,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func runtimeNamedPools(runtimeCfg storage.RuntimeConfig) []config.NamedPoolConfig {
	if len(runtimeCfg.NamedPools) > 0 {
		pools := make([]config.NamedPoolConfig, len(runtimeCfg.NamedPools))
		copy(pools, runtimeCfg.NamedPools)
		return pools
	}

	poolCfg := runtimeCfg.Pool
	if strings.TrimSpace(poolCfg.Mode) == "" {
		poolCfg.Mode = "sequential"
	}
	return []config.NamedPoolConfig{{
		Name:     "default",
		Listener: runtimeCfg.Listener,
		Pool:     poolCfg,
	}}
}

func assignRuntimeNamedPools(runtimeCfg *storage.RuntimeConfig, pools []config.NamedPoolConfig) {
	if runtimeCfg == nil {
		return
	}
	runtimeCfg.NamedPools = make([]config.NamedPoolConfig, len(pools))
	copy(runtimeCfg.NamedPools, pools)
	if len(pools) > 0 {
		runtimeCfg.Listener = pools[0].Listener
		runtimeCfg.Pool = pools[0].Pool
	}
}

func findPoolIndex(pools []config.NamedPoolConfig, name string) int {
	target := strings.TrimSpace(name)
	if target == "" {
		return -1
	}
	for idx := range pools {
		if strings.EqualFold(strings.TrimSpace(pools[idx].Name), target) {
			return idx
		}
	}
	return -1
}

func normalizeNamedPoolInput(pool *config.NamedPoolConfig) {
	if pool == nil {
		return
	}
	pool.Name = strings.TrimSpace(pool.Name)
	pool.Listener.Address = strings.TrimSpace(pool.Listener.Address)
	pool.Listener.Username = strings.TrimSpace(pool.Listener.Username)
	pool.Listener.Password = strings.TrimSpace(pool.Listener.Password)
	if strings.TrimSpace(pool.Pool.Mode) == "" {
		pool.Pool.Mode = "sequential"
	}
}

func parseApplyNow(raw string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return parsed
}

type durationJSONValue struct {
	Duration time.Duration
}

func (d *durationJSONValue) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errors.New("duration target is nil")
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		d.Duration = 0
		return nil
	}

	if strings.HasPrefix(raw, "\"") {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		text = strings.TrimSpace(text)
		if text == "" {
			d.Duration = 0
			return nil
		}
		parsed, err := time.ParseDuration(text)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", text, err)
		}
		d.Duration = parsed
		return nil
	}

	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return err
	}
	if i64, err := number.Int64(); err == nil {
		d.Duration = time.Duration(i64)
		return nil
	}
	f64, err := number.Float64()
	if err != nil {
		return err
	}
	d.Duration = time.Duration(int64(f64))
	return nil
}

type poolPolicyMutationRequest struct {
	Mode                    string            `json:"mode"`
	FailureThreshold        int               `json:"failure_threshold"`
	BlacklistDuration       durationJSONValue `json:"blacklist_duration"`
	DomainFailureThreshold  int               `json:"domain_failure_threshold"`
	DomainBlacklistDuration durationJSONValue `json:"domain_blacklist_duration"`
	DomainRecheckInterval   durationJSONValue `json:"domain_recheck_interval"`
	DomainRecheckTimeout    durationJSONValue `json:"domain_recheck_timeout"`
}

type namedPoolMutationRequest struct {
	Name     string                    `json:"name"`
	Listener config.ListenerConfig     `json:"listener"`
	Pool     poolPolicyMutationRequest `json:"pool"`
}

func (req namedPoolMutationRequest) toConfig() config.NamedPoolConfig {
	return config.NamedPoolConfig{
		Name:     req.Name,
		Listener: req.Listener,
		Pool: config.PoolConfig{
			Mode:                    req.Pool.Mode,
			FailureThreshold:        req.Pool.FailureThreshold,
			BlacklistDuration:       req.Pool.BlacklistDuration.Duration,
			DomainFailureThreshold:  req.Pool.DomainFailureThreshold,
			DomainBlacklistDuration: req.Pool.DomainBlacklistDuration.Duration,
			DomainRecheckInterval:   req.Pool.DomainRecheckInterval.Duration,
			DomainRecheckTimeout:    req.Pool.DomainRecheckTimeout.Duration,
		},
	}
}

type poolMutationRequest struct {
	Pool     namedPoolMutationRequest `json:"pool"`
	ApplyNow bool                     `json:"apply_now"`
}

func (s *Server) handlePools(w http.ResponseWriter, r *http.Request) {
	runtimeMgr, ok := s.nodeMgr.(runtimeConfigManager)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "业务池管理未启用（请启用数据库存储）"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		runtimeCfg, err := runtimeMgr.GetRuntimeConfig(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		pools := runtimeNamedPools(runtimeCfg)
		writeJSON(w, map[string]any{
			"pools": pools,
			"count": len(pools),
		})
	case http.MethodPost:
		var req poolMutationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": fmt.Sprintf("请求格式错误: %v", err)})
			return
		}
		reqPool := req.Pool.toConfig()
		normalizeNamedPoolInput(&reqPool)
		if reqPool.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "pool.name 不能为空"})
			return
		}
		if reqPool.Listener.Port == 0 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "pool.listener.port 不能为空"})
			return
		}

		runtimeCfg, err := runtimeMgr.GetRuntimeConfig(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		pools := runtimeNamedPools(runtimeCfg)
		if findPoolIndex(pools, reqPool.Name) >= 0 {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]any{"error": "业务池名称已存在"})
			return
		}
		pools = append(pools, reqPool)
		assignRuntimeNamedPools(&runtimeCfg, pools)

		updated, err := runtimeMgr.UpdateRuntimeConfig(r.Context(), runtimeCfg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		reloaded := false
		if req.ApplyNow {
			if err := s.nodeMgr.TriggerReload(r.Context()); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, map[string]any{
					"error":       fmt.Sprintf("业务池已保存，但重载失败: %v", err),
					"saved":       true,
					"need_reload": true,
					"pools":       runtimeNamedPools(updated),
				})
				return
			}
			reloaded = true
		}

		writeJSON(w, map[string]any{
			"message":     "业务池已创建",
			"pool":        reqPool,
			"pools":       runtimeNamedPools(updated),
			"saved":       true,
			"reloaded":    reloaded,
			"need_reload": !reloaded,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePoolItem(w http.ResponseWriter, r *http.Request) {
	runtimeMgr, ok := s.nodeMgr.(runtimeConfigManager)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "业务池管理未启用（请启用数据库存储）"})
		return
	}

	namePart := strings.TrimPrefix(r.URL.Path, "/api/pools/")
	poolName, err := url.PathUnescape(namePart)
	if err != nil || strings.TrimSpace(poolName) == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "业务池名称无效"})
		return
	}
	poolName = strings.TrimSpace(poolName)

	runtimeCfg, err := runtimeMgr.GetRuntimeConfig(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	pools := runtimeNamedPools(runtimeCfg)
	targetIdx := findPoolIndex(pools, poolName)
	if targetIdx < 0 {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": "业务池不存在"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req poolMutationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": fmt.Sprintf("请求格式错误: %v", err)})
			return
		}
		reqPool := req.Pool.toConfig()
		normalizeNamedPoolInput(&reqPool)
		if reqPool.Name == "" {
			reqPool.Name = poolName
		}
		if reqPool.Listener.Port == 0 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "pool.listener.port 不能为空"})
			return
		}

		if existingIdx := findPoolIndex(pools, reqPool.Name); existingIdx >= 0 && existingIdx != targetIdx {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]any{"error": "业务池名称已存在"})
			return
		}

		pools[targetIdx] = reqPool
		assignRuntimeNamedPools(&runtimeCfg, pools)

		updated, err := runtimeMgr.UpdateRuntimeConfig(r.Context(), runtimeCfg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		reloaded := false
		if req.ApplyNow {
			if err := s.nodeMgr.TriggerReload(r.Context()); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, map[string]any{
					"error":       fmt.Sprintf("业务池已保存，但重载失败: %v", err),
					"saved":       true,
					"need_reload": true,
					"pools":       runtimeNamedPools(updated),
				})
				return
			}
			reloaded = true
		}

		writeJSON(w, map[string]any{
			"message":     "业务池已更新",
			"pool":        reqPool,
			"pools":       runtimeNamedPools(updated),
			"saved":       true,
			"reloaded":    reloaded,
			"need_reload": !reloaded,
		})

	case http.MethodDelete:
		if len(pools) <= 1 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "至少保留一个业务池"})
			return
		}
		applyNow := parseApplyNow(r.URL.Query().Get("apply_now"))
		removed := pools[targetIdx]
		pools = append(pools[:targetIdx], pools[targetIdx+1:]...)
		assignRuntimeNamedPools(&runtimeCfg, pools)

		updated, err := runtimeMgr.UpdateRuntimeConfig(r.Context(), runtimeCfg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		reloaded := false
		if applyNow {
			if err := s.nodeMgr.TriggerReload(r.Context()); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, map[string]any{
					"error":       fmt.Sprintf("业务池已删除，但重载失败: %v", err),
					"saved":       true,
					"need_reload": true,
					"pools":       runtimeNamedPools(updated),
				})
				return
			}
			reloaded = true
		}

		writeJSON(w, map[string]any{
			"message":     "业务池已删除",
			"removed":     removed,
			"pools":       runtimeNamedPools(updated),
			"saved":       true,
			"reloaded":    reloaded,
			"need_reload": !reloaded,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleSettings handles GET/PUT for dynamic settings (external_ip, probe_target, skip_cert_verify, proxy auth).
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		extIP, probeTarget, skipCertVerify, proxyUsername, proxyPassword := s.getSettings()
		writeJSON(w, map[string]any{
			"external_ip":      extIP,
			"probe_target":     probeTarget,
			"skip_cert_verify": skipCertVerify,
			"proxy_username":   proxyUsername,
			"proxy_password":   proxyPassword,
		})
	case http.MethodPut:
		var req struct {
			ExternalIP     string `json:"external_ip"`
			ProbeTarget    string `json:"probe_target"`
			SkipCertVerify bool   `json:"skip_cert_verify"`
			ProxyUsername  string `json:"proxy_username"`
			ProxyPassword  string `json:"proxy_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}

		extIP := strings.TrimSpace(req.ExternalIP)
		probeTarget := strings.TrimSpace(req.ProbeTarget)
		proxyUsername := strings.TrimSpace(req.ProxyUsername)
		proxyPassword := strings.TrimSpace(req.ProxyPassword)

		if err := s.updateSettings(extIP, probeTarget, req.SkipCertVerify, proxyUsername, proxyPassword); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}

		writeJSON(w, map[string]any{
			"message":          "设置已保存",
			"external_ip":      extIP,
			"probe_target":     probeTarget,
			"skip_cert_verify": req.SkipCertVerify,
			"proxy_username":   proxyUsername,
			"proxy_password":   proxyPassword,
			"need_reload":      true,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleSubscriptionStatus returns the current subscription refresh status.
func (s *Server) handleSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.subRefresher == nil {
		writeJSON(w, map[string]any{
			"enabled": false,
			"message": "订阅刷新未启用",
		})
		return
	}

	status := s.subRefresher.Status()
	writeJSON(w, map[string]any{
		"enabled":       true,
		"last_refresh":  status.LastRefresh,
		"next_refresh":  status.NextRefresh,
		"node_count":    status.NodeCount,
		"last_error":    status.LastError,
		"refresh_count": status.RefreshCount,
		"is_refreshing": status.IsRefreshing,
	})
}

// handleSubscriptionRefresh triggers an immediate subscription refresh.
func (s *Server) handleSubscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.subRefresher == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "订阅刷新未启用"})
		return
	}

	if err := s.subRefresher.RefreshNow(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	status := s.subRefresher.Status()
	writeJSON(w, map[string]any{
		"message":    "刷新成功",
		"node_count": status.NodeCount,
	})
}

type subscriptionPayload struct {
	URL string `json:"url"`
}

type subscriptionAdvancedRefresher interface {
	RefreshSubscription(subURL string) error
	SubscriptionLogs(subURL string) []SubscriptionLog
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.cfgMu.RLock()
		if s.cfgSrc == nil {
			s.cfgMu.RUnlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]any{"error": "配置存储未初始化"})
			return
		}
		subs := append([]string(nil), s.cfgSrc.Subscriptions...)
		nodeCounts := make(map[string]int)
		subNoRefCount := 0
		for _, n := range s.cfgSrc.Nodes {
			if n.Source != config.NodeSourceSubscription {
				continue
			}
			if strings.TrimSpace(n.SourceRef) == "" {
				subNoRefCount++
				continue
			}
			nodeCounts[n.SourceRef]++
		}
		s.cfgMu.RUnlock()

		items := make([]map[string]any, 0, len(subs))
		for idx, sub := range subs {
			count := nodeCounts[sub]
			if count == 0 && len(subs) == 1 && subNoRefCount > 0 {
				count = subNoRefCount
			}
			items = append(items, map[string]any{
				"index":      idx,
				"url":        sub,
				"node_count": count,
			})
		}

		writeJSON(w, map[string]any{
			"subscriptions": subs,
			"items":         items,
		})
	case http.MethodPost:
		s.cfgMu.Lock()
		defer s.cfgMu.Unlock()
		if s.cfgSrc == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]any{"error": "配置存储未初始化"})
			return
		}

		var payload subscriptionPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		subURL := strings.TrimSpace(payload.URL)
		if err := validateSubscriptionURL(subURL); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		for _, existing := range s.cfgSrc.Subscriptions {
			if existing == subURL {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]any{"error": "订阅链接已存在"})
				return
			}
		}
		s.cfgSrc.Subscriptions = append(s.cfgSrc.Subscriptions, subURL)
		if err := s.persistSubscriptionsLocked(r.Context()); err != nil {
			s.cfgSrc.Subscriptions = s.cfgSrc.Subscriptions[:len(s.cfgSrc.Subscriptions)-1]
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": fmt.Sprintf("保存订阅失败: %v", err)})
			return
		}

		writeJSON(w, map[string]any{
			"message":       "订阅已添加",
			"need_restart":  s.subRefresher == nil,
			"need_refresh":  s.subRefresher != nil,
			"subscriptions": append([]string(nil), s.cfgSrc.Subscriptions...),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSubscriptionItem(w http.ResponseWriter, r *http.Request) {
	idx, action, err := parseSubscriptionItemPath(r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	s.cfgMu.RLock()
	if s.cfgSrc == nil {
		s.cfgMu.RUnlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "配置存储未初始化"})
		return
	}
	if idx >= len(s.cfgSrc.Subscriptions) {
		s.cfgMu.RUnlock()
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": "订阅不存在"})
		return
	}
	subURL := s.cfgSrc.Subscriptions[idx]
	s.cfgMu.RUnlock()

	if action == "refresh" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if s.subRefresher == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]any{"error": "订阅刷新未启用，请重启服务后重试"})
			return
		}
		if advanced, ok := s.subRefresher.(subscriptionAdvancedRefresher); ok {
			if err := advanced.RefreshSubscription(subURL); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, map[string]any{"error": err.Error()})
				return
			}
		} else {
			if err := s.subRefresher.RefreshNow(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, map[string]any{"error": err.Error()})
				return
			}
		}
		status := s.subRefresher.Status()
		writeJSON(w, map[string]any{
			"message":      "订阅刷新成功",
			"subscription": subURL,
			"node_count":   status.NodeCount,
		})
		return
	}

	if action == "logs" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if advanced, ok := s.subRefresher.(subscriptionAdvancedRefresher); ok {
			writeJSON(w, map[string]any{
				"subscription": subURL,
				"logs":         advanced.SubscriptionLogs(subURL),
			})
			return
		}
		writeJSON(w, map[string]any{"subscription": subURL, "logs": []SubscriptionLog{}})
		return
	}

	if action != "" {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": "无效的订阅操作"})
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.cfgSrc == nil || idx >= len(s.cfgSrc.Subscriptions) {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": "订阅不存在"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var payload subscriptionPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		newURL := strings.TrimSpace(payload.URL)
		if err := validateSubscriptionURL(newURL); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		for i, existing := range s.cfgSrc.Subscriptions {
			if i == idx {
				continue
			}
			if existing == newURL {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]any{"error": "订阅链接已存在"})
				return
			}
		}
		backup := append([]string(nil), s.cfgSrc.Subscriptions...)
		s.cfgSrc.Subscriptions[idx] = newURL
		if err := s.persistSubscriptionsLocked(r.Context()); err != nil {
			s.cfgSrc.Subscriptions = backup
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": fmt.Sprintf("保存订阅失败: %v", err)})
			return
		}
		writeJSON(w, map[string]any{
			"message":       "订阅已更新",
			"need_restart":  s.subRefresher == nil,
			"need_refresh":  s.subRefresher != nil,
			"subscriptions": append([]string(nil), s.cfgSrc.Subscriptions...),
		})
	case http.MethodDelete:
		backup := append([]string(nil), s.cfgSrc.Subscriptions...)
		s.cfgSrc.Subscriptions = append(s.cfgSrc.Subscriptions[:idx], s.cfgSrc.Subscriptions[idx+1:]...)
		if err := s.persistSubscriptionsLocked(r.Context()); err != nil {
			s.cfgSrc.Subscriptions = backup
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": fmt.Sprintf("保存订阅失败: %v", err)})
			return
		}

		needRestart := s.subRefresher == nil
		needRefresh := s.subRefresher != nil
		refreshErr := ""
		if s.subRefresher != nil {
			if err := s.subRefresher.RefreshNow(); err != nil {
				refreshErr = err.Error()
			} else {
				needRefresh = false
			}
		}

		resp := map[string]any{
			"message":       "订阅已删除",
			"subscriptions": append([]string(nil), s.cfgSrc.Subscriptions...),
			"need_restart":  needRestart,
			"need_refresh":  needRefresh,
		}
		if refreshErr != "" {
			resp["message"] = "订阅已删除，但刷新失败，请手动刷新"
			resp["refresh_error"] = refreshErr
		}
		writeJSON(w, resp)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func parseSubscriptionItemPath(path string) (idx int, action string, err error) {
	trimmed := strings.TrimPrefix(path, "/api/subscriptions/")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return 0, "", errors.New("缺少订阅索引")
	}
	parts := strings.Split(trimmed, "/")
	idx, convErr := strconv.Atoi(parts[0])
	if convErr != nil || idx < 0 {
		return 0, "", errors.New("订阅索引无效")
	}
	action = ""
	if len(parts) > 1 {
		action = strings.ToLower(strings.TrimSpace(parts[1]))
	}
	return idx, action, nil
}

func validateSubscriptionURL(raw string) error {
	if raw == "" {
		return errors.New("订阅链接不能为空")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("订阅链接格式无效")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("订阅链接必须是 http 或 https")
	}
	if parsed.Host == "" {
		return errors.New("订阅链接缺少主机名")
	}
	return nil
}

func (s *Server) persistSubscriptionsLocked(ctx context.Context) error {
	if s.cfgSrc == nil {
		return errors.New("配置存储未初始化")
	}

	if saver, ok := s.nodeMgr.(interface {
		SaveSubscriptions(ctx context.Context, subscriptions []string) error
	}); ok {
		subs := append([]string(nil), s.cfgSrc.Subscriptions...)
		return saver.SaveSubscriptions(ctx, subs)
	}

	return s.cfgSrc.SaveSubscriptions()
}

type scriptSourceManager interface {
	ListScriptSources(ctx context.Context) ([]storage.ScriptSource, error)
	CreateScriptSource(ctx context.Context, src storage.ScriptSource) (storage.ScriptSource, error)
	UpdateScriptSource(ctx context.Context, id string, src storage.ScriptSource) (storage.ScriptSource, error)
	DeleteScriptSource(ctx context.Context, id string) error
	RunScriptSource(ctx context.Context, id string, apply bool) (storage.ScriptRunResult, error)
	TestScript(ctx context.Context, src storage.ScriptSource) (storage.ScriptRunResult, error)
}

type scriptSourcePayload struct {
	Name               string   `json:"name"`
	Command            string   `json:"command"`
	Args               []string `json:"args"`
	Script             string   `json:"script"`
	TimeoutMs          int      `json:"timeout_ms"`
	SetupTimeoutMs     int      `json:"setup_timeout_ms"`
	MaxOutputBytes     int      `json:"max_output_bytes"`
	MaxNodes           int      `json:"max_nodes"`
	PythonRequirements []string `json:"python_requirements"`
	Enabled            *bool    `json:"enabled"`
}

func (p scriptSourcePayload) toStorage() storage.ScriptSource {
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	return storage.ScriptSource{
		Name:               p.Name,
		Command:            p.Command,
		Args:               append([]string(nil), p.Args...),
		Script:             p.Script,
		TimeoutMs:          p.TimeoutMs,
		SetupTimeoutMs:     p.SetupTimeoutMs,
		MaxOutputBytes:     p.MaxOutputBytes,
		MaxNodes:           p.MaxNodes,
		PythonRequirements: append([]string(nil), p.PythonRequirements...),
		Enabled:            enabled,
	}
}

func (s *Server) handleScriptSources(w http.ResponseWriter, r *http.Request) {
	mgr, ok := s.nodeMgr.(scriptSourceManager)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "脚本源管理未启用（请启用数据库存储）"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		sources, err := mgr.ListScriptSources(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"sources": sources, "count": len(sources)})
	case http.MethodPost:
		var payload scriptSourcePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		created, err := mgr.CreateScriptSource(r.Context(), payload.toStorage())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"source": created, "message": "脚本源已创建"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScriptSourceTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	mgr, ok := s.nodeMgr.(scriptSourceManager)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "脚本源管理未启用（请启用数据库存储）"})
		return
	}

	var payload scriptSourcePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "请求格式错误"})
		return
	}

	result, testErr := mgr.TestScript(r.Context(), payload.toStorage())
	if testErr != nil {
		result.Error = testErr.Error()
	}
	writeJSON(w, result)
}

func (s *Server) handleScriptSourceItem(w http.ResponseWriter, r *http.Request) {
	mgr, ok := s.nodeMgr.(scriptSourceManager)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "脚本源管理未启用（请启用数据库存储）"})
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/script-sources/")
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "脚本源 ID 无效"})
		return
	}
	id, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(id) == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "脚本源 ID 无效"})
		return
	}
	action := ""
	if len(parts) > 1 {
		action = strings.ToLower(strings.TrimSpace(parts[1]))
	}

	if action == "run" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Apply *bool `json:"apply"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		apply := true
		if req.Apply != nil {
			apply = *req.Apply
		}
		result, runErr := mgr.RunScriptSource(r.Context(), id, apply)
		// Always return the run payload for debugging, even on error.
		if runErr != nil {
			result.Error = runErr.Error()
		}
		writeJSON(w, result)
		return
	}

	if action == "test" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		result, testErr := mgr.RunScriptSource(r.Context(), id, false)
		if testErr != nil {
			result.Error = testErr.Error()
		}
		writeJSON(w, result)
		return
	}

	if action == "test" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var payload scriptSourcePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		// Test does not persist and does not apply.
		result, testErr := mgr.TestScript(r.Context(), payload.toStorage())
		if testErr != nil {
			result.Error = testErr.Error()
		}
		writeJSON(w, result)
		return
	}

	if action != "" {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": "无效的脚本源操作"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var payload scriptSourcePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		updated, err := mgr.UpdateScriptSource(r.Context(), id, payload.toStorage())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"source": updated, "message": "脚本源已更新"})
	case http.MethodDelete:
		if err := mgr.DeleteScriptSource(r.Context(), id); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"message": "脚本源已删除"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// nodePayload is the JSON request body for node CRUD operations.
type nodePayload struct {
	Name     string `json:"name"`
	URI      string `json:"uri"`
	Port     uint16 `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p nodePayload) toConfig() config.NodeConfig {
	return config.NodeConfig{
		Name:     p.Name,
		URI:      p.URI,
		Port:     p.Port,
		Username: p.Username,
		Password: p.Password,
	}
}

type runtimeNodeCandidate struct {
	ip   string
	pool string
}

func (s *Server) configNodeIPByURI() map[string]string {
	result := make(map[string]string)
	if s == nil || s.mgr == nil {
		return result
	}

	candidates := make(map[string]runtimeNodeCandidate)
	for _, snap := range s.mgr.Snapshot() {
		uri := strings.TrimSpace(snap.URI)
		ip := strings.TrimSpace(snap.NodeIP)
		if uri == "" || ip == "" {
			continue
		}

		current := candidates[uri]
		if current.ip == "" || preferRuntimeNodeIP(current.pool, snap.PoolName) {
			candidates[uri] = runtimeNodeCandidate{ip: ip, pool: snap.PoolName}
		}
	}

	for uri, candidate := range candidates {
		result[uri] = candidate.ip
	}
	return result
}

func preferRuntimeNodeIP(currentPool, incomingPool string) bool {
	currentPool = strings.TrimSpace(strings.ToLower(currentPool))
	incomingPool = strings.TrimSpace(strings.ToLower(incomingPool))

	currentDefault := currentPool == "" || currentPool == "default"
	incomingDefault := incomingPool == "" || incomingPool == "default"
	return !currentDefault && incomingDefault
}

func fallbackIPFromNodeURI(rawURI string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil {
		return ""
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

// handleConfigNodes handles GET (list) and POST (create) for config nodes.
func (s *Server) handleConfigNodes(w http.ResponseWriter, r *http.Request) {
	if !s.ensureNodeManager(w) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		nodes, err := s.nodeMgr.ListConfigNodes(r.Context())
		if err != nil {
			s.respondNodeError(w, err)
			return
		}
		nodeIPByURI := s.configNodeIPByURI()
		response := make([]map[string]any, 0, len(nodes))
		for _, node := range nodes {
			uri := strings.TrimSpace(node.URI)
			nodeIP := strings.TrimSpace(nodeIPByURI[uri])
			if nodeIP == "" {
				nodeIP = fallbackIPFromNodeURI(uri)
			}

			response = append(response, map[string]any{
				"name":       node.Name,
				"uri":        node.URI,
				"node_ip":    nodeIP,
				"port":       node.Port,
				"username":   node.Username,
				"password":   node.Password,
				"region":     node.Region,
				"country":    node.Country,
				"source":     node.Source,
				"source_ref": node.SourceRef,
			})
		}
		writeJSON(w, map[string]any{"nodes": response})
	case http.MethodPost:
		var payload nodePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		node, err := s.nodeMgr.CreateNode(r.Context(), payload.toConfig())
		if err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"node": node, "message": "节点已添加，请点击重载使配置生效"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleConfigNodeItem handles PUT (update) and DELETE for a specific config node.
func (s *Server) handleConfigNodeItem(w http.ResponseWriter, r *http.Request) {
	if !s.ensureNodeManager(w) {
		return
	}

	namePart := strings.TrimPrefix(r.URL.Path, "/api/nodes/config/")
	nodeName, err := url.PathUnescape(namePart)
	if err != nil || nodeName == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "节点名称无效"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var payload nodePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "请求格式错误"})
			return
		}
		node, err := s.nodeMgr.UpdateNode(r.Context(), nodeName, payload.toConfig())
		if err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"node": node, "message": "节点已更新，请点击重载使配置生效"})
	case http.MethodDelete:
		if err := s.nodeMgr.DeleteNode(r.Context(), nodeName); err != nil {
			s.respondNodeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "节点已删除，请点击重载使配置生效"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleReload triggers a configuration reload.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.ensureNodeManager(w) {
		return
	}

	if err := s.nodeMgr.TriggerReload(r.Context()); err != nil {
		s.respondNodeError(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"message": "重载成功，现有连接已被中断",
	})
}

func (s *Server) ensureNodeManager(w http.ResponseWriter) bool {
	if s.nodeMgr == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "节点管理未启用"})
		return false
	}
	return true
}

func (s *Server) respondNodeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrNodeNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrNodeConflict), errors.Is(err, ErrInvalidNode):
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	writeJSON(w, map[string]any{"error": err.Error()})
}

// Session management functions

// generateSessionToken creates a cryptographically secure random token.
func (s *Server) generateSessionToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return hex.EncodeToString(tokenBytes), nil
}

// createSession creates a new session with expiration.
func (s *Server) createSession() (*Session, error) {
	token, err := s.generateSessionToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(s.sessionTTL),
	}

	s.sessionMu.Lock()
	s.sessions[token] = session
	s.sessionMu.Unlock()

	return session, nil
}

// validateSession checks if a session token is valid and not expired.
func (s *Server) validateSession(token string) bool {
	s.sessionMu.RLock()
	session, exists := s.sessions[token]
	s.sessionMu.RUnlock()

	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		s.sessionMu.Lock()
		delete(s.sessions, token)
		s.sessionMu.Unlock()
		return false
	}

	return true
}

// cleanupExpiredSessions periodically removes expired sessions.
func (s *Server) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.sessionMu.Lock()
		for token, session := range s.sessions {
			if now.After(session.ExpiresAt) {
				delete(s.sessions, token)
			}
		}
		s.sessionMu.Unlock()
	}
}

// secureCompareStrings performs constant-time string comparison to prevent timing attacks.
func secureCompareStrings(a, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)

	// If lengths differ, still perform a dummy comparison to maintain constant time
	if len(aBytes) != len(bBytes) {
		dummy := make([]byte, 32)
		subtle.ConstantTimeCompare(dummy, dummy)
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}
