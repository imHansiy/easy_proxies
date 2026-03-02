package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Config describes the high level settings for the proxy pool server.
type Config struct {
	Mode                string                    `yaml:"mode"`
	Listener            ListenerConfig            `yaml:"listener"`
	NamedPools          []NamedPoolConfig         `yaml:"named_pools"`
	MultiPort           MultiPortConfig           `yaml:"multi_port"`
	Pool                PoolConfig                `yaml:"pool"`
	Management          ManagementConfig          `yaml:"management"`
	SubscriptionRefresh SubscriptionRefreshConfig `yaml:"subscription_refresh"`
	Storage             StorageConfig             `yaml:"storage"`
	GeoIP               GeoIPConfig               `yaml:"geoip"`
	Nodes               []NodeConfig              `yaml:"nodes"`
	NodesFile           string                    `yaml:"nodes_file"`    // 节点文件路径，每行一个 URI
	Subscriptions       []string                  `yaml:"subscriptions"` // 订阅链接列表
	ExternalIP          string                    `yaml:"external_ip"`   // 外部 IP 地址，用于导出时替换 0.0.0.0
	LogLevel            string                    `yaml:"log_level"`
	SkipCertVerify      bool                      `yaml:"skip_cert_verify"` // 全局跳过 SSL 证书验证

	filePath string `yaml:"-"` // 配置文件路径，用于保存
}

// StorageConfig controls optional external persistence backends.
type StorageConfig struct {
	Driver      string                `yaml:"driver"`
	DSN         string                `yaml:"dsn"`
	AutoMigrate *bool                 `yaml:"auto_migrate"`
	Postgres    PostgresStorageConfig `yaml:"postgres"`
	MySQL       SQLStorageConfig      `yaml:"mysql"`
	SQLite      SQLStorageConfig      `yaml:"sqlite"`
}

// PostgresStorageConfig enables PostgreSQL-backed persistent state.
type PostgresStorageConfig struct {
	Enabled bool   `yaml:"enabled"`
	DSN     string `yaml:"dsn"`
}

// SQLStorageConfig provides DSN config for SQL backends.
type SQLStorageConfig struct {
	Enabled bool   `yaml:"enabled"`
	DSN     string `yaml:"dsn"`
}

// Enabled reports whether database persistence is enabled.
func (s StorageConfig) Enabled() bool {
	return s.Driver != "" || s.Postgres.Enabled || s.MySQL.Enabled || s.SQLite.Enabled
}

// ResolveDriverDSN resolves storage driver/dsn with backward compatibility.
func (s StorageConfig) ResolveDriverDSN() (driver, dsn string) {
	if strings.TrimSpace(s.Driver) != "" {
		return strings.ToLower(strings.TrimSpace(s.Driver)), strings.TrimSpace(s.DSN)
	}
	if s.Postgres.Enabled {
		return "postgres", strings.TrimSpace(s.Postgres.DSN)
	}
	if s.MySQL.Enabled {
		return "mysql", strings.TrimSpace(s.MySQL.DSN)
	}
	if s.SQLite.Enabled {
		return "sqlite", strings.TrimSpace(s.SQLite.DSN)
	}
	return "", ""
}

// ShouldAutoMigrate reports whether schema auto migration is enabled.
func (s StorageConfig) ShouldAutoMigrate() bool {
	if s.AutoMigrate == nil {
		return true
	}
	return *s.AutoMigrate
}

// GeoIPConfig controls GeoIP-based region routing.
type GeoIPConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`                           // 是否启用 GeoIP 地域分区
	DatabasePath       string        `yaml:"database_path" json:"database_path"`               // GeoLite2-Country.mmdb 文件路径
	Listen             string        `yaml:"listen" json:"listen"`                             // GeoIP 路由监听地址，默认使用 listener 配置
	Port               uint16        `yaml:"port" json:"port"`                                 // GeoIP 路由监听端口，默认 2323
	AutoUpdateEnabled  bool          `yaml:"auto_update_enabled" json:"auto_update_enabled"`   // 是否启用自动更新数据库
	AutoUpdateInterval time.Duration `yaml:"auto_update_interval" json:"auto_update_interval"` // 自动更新间隔，默认 24 小时
}

// ListenerConfig defines how the HTTP proxy should listen for clients.
type ListenerConfig struct {
	Address  string `yaml:"address" json:"address"`
	Port     uint16 `yaml:"port" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// NamedPoolConfig defines an isolated business pool bound to one listener.
type NamedPoolConfig struct {
	Name     string         `yaml:"name" json:"name"`
	Listener ListenerConfig `yaml:"listener" json:"listener"`
	Pool     PoolConfig     `yaml:"pool" json:"pool"`
}

// PoolConfig configures scheduling + failure handling.
type PoolConfig struct {
	Mode                    string        `yaml:"mode" json:"mode"`
	FailureThreshold        int           `yaml:"failure_threshold" json:"failure_threshold"`
	BlacklistDuration       time.Duration `yaml:"blacklist_duration" json:"blacklist_duration"`
	DomainFailureThreshold  int           `yaml:"domain_failure_threshold" json:"domain_failure_threshold"`
	DomainBlacklistDuration time.Duration `yaml:"domain_blacklist_duration" json:"domain_blacklist_duration"`
	DomainRecheckInterval   time.Duration `yaml:"domain_recheck_interval" json:"domain_recheck_interval"`
	DomainRecheckTimeout    time.Duration `yaml:"domain_recheck_timeout" json:"domain_recheck_timeout"`
}

// MultiPortConfig defines address/credential defaults for multi-port mode.
type MultiPortConfig struct {
	Address  string `yaml:"address" json:"address"`
	BasePort uint16 `yaml:"base_port" json:"base_port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// ManagementConfig controls the monitoring HTTP endpoint.
type ManagementConfig struct {
	Enabled        *bool    `yaml:"enabled" json:"enabled"`
	Listen         string   `yaml:"listen" json:"listen"`
	ProbeTarget    string   `yaml:"probe_target" json:"probe_target"`
	Password       string   `yaml:"password" json:"password"`               // WebUI 访问密码，为空则不需要密码
	FrontendDist   string   `yaml:"frontend_dist" json:"frontend_dist"`     // 前端 dist 目录（可选）
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"` // 允许跨域访问的 Origin 列表
}

// SubscriptionRefreshConfig controls subscription auto-refresh and reload settings.
type SubscriptionRefreshConfig struct {
	Enabled            bool          `yaml:"enabled" json:"enabled"`                           // 是否启用定时刷新
	Interval           time.Duration `yaml:"interval" json:"interval"`                         // 刷新间隔，默认 1 小时
	Timeout            time.Duration `yaml:"timeout" json:"timeout"`                           // 获取订阅的超时时间
	HealthCheckTimeout time.Duration `yaml:"health_check_timeout" json:"health_check_timeout"` // 新节点健康检查超时
	DrainTimeout       time.Duration `yaml:"drain_timeout" json:"drain_timeout"`               // 旧实例排空超时时间
	MinAvailableNodes  int           `yaml:"min_available_nodes" json:"min_available_nodes"`   // 最少可用节点数，低于此值不切换
}

// NodeSource indicates where a node configuration originated from.
type NodeSource string

const (
	NodeSourceInline       NodeSource = "inline"       // Defined directly in file-based config nodes array
	NodeSourceFile         NodeSource = "nodes_file"   // Loaded from external nodes file
	NodeSourceSubscription NodeSource = "subscription" // Fetched from subscription URL
	defaultNamedPoolName   string     = "default"
)

// NodeConfig describes a single upstream proxy endpoint expressed as URI.
type NodeConfig struct {
	Name      string     `yaml:"name" json:"name"`
	URI       string     `yaml:"uri" json:"uri"`
	Port      uint16     `yaml:"port,omitempty" json:"port,omitempty"`
	Username  string     `yaml:"username,omitempty" json:"username,omitempty"`
	Password  string     `yaml:"password,omitempty" json:"password,omitempty"`
	Region    string     `yaml:"region,omitempty" json:"region,omitempty"`
	Country   string     `yaml:"country,omitempty" json:"country,omitempty"`
	Source    NodeSource `yaml:"-" json:"source,omitempty"`     // Runtime only, not persisted
	SourceRef string     `yaml:"-" json:"source_ref,omitempty"` // Subscription URL or source identifier
}

// NodeKey returns a unique identifier for the node based on its URI.
// This is used to preserve port assignments across reloads.
func (n *NodeConfig) NodeKey() string {
	return n.URI
}

// Load reads YAML config from disk and applies defaults/validation.
func Load(path string) (*Config, error) {
	var cfg Config
	cfg.filePath = path

	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read config: %w", err)
			}
			log.Printf("INFO: config file %q not found, using env/defaults", path)
		} else {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return nil, fmt.Errorf("decode config: %w", err)
			}
			cfg.filePath = path
		}
	}

	// Resolve nodes_file path relative to config file directory
	if cfg.NodesFile != "" && !filepath.IsAbs(cfg.NodesFile) {
		configDir := "."
		if strings.TrimSpace(path) != "" {
			configDir = filepath.Dir(path)
		}
		cfg.NodesFile = filepath.Join(configDir, cfg.NodesFile)
	}

	// Resolve management.frontend_dist path relative to config file directory
	if cfg.Management.FrontendDist != "" && !filepath.IsAbs(cfg.Management.FrontendDist) {
		configDir := "."
		if strings.TrimSpace(path) != "" {
			configDir = filepath.Dir(path)
		}
		cfg.Management.FrontendDist = filepath.Join(configDir, cfg.Management.FrontendDist)
	}

	if err := cfg.ApplyEnvOverrides(); err != nil {
		return nil, fmt.Errorf("apply env overrides: %w", err)
	}

	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) normalize() error {
	if c.Mode == "" {
		c.Mode = "pool"
	}
	// Normalize mode name: support both multi-port and multi_port
	if c.Mode == "multi_port" {
		c.Mode = "multi-port"
	}
	switch c.Mode {
	case "pool", "multi-port", "hybrid":
	default:
		return fmt.Errorf("unsupported mode %q (use 'pool', 'multi-port', or 'hybrid')", c.Mode)
	}
	if c.Listener.Address == "" {
		c.Listener.Address = "0.0.0.0"
	}
	if c.Listener.Port == 0 {
		c.Listener.Port = 2323
	}
	normalizePoolConfigDefaults(&c.Pool)
	if c.MultiPort.Address == "" {
		c.MultiPort.Address = "0.0.0.0"
	}
	if c.MultiPort.BasePort == 0 {
		c.MultiPort.BasePort = 28000
	}
	if c.Management.Listen == "" {
		c.Management.Listen = "127.0.0.1:9090"
	}
	if c.Management.ProbeTarget == "" {
		c.Management.ProbeTarget = "www.apple.com:80"
	}
	if strings.TrimSpace(c.Management.FrontendDist) == "" {
		c.Management.FrontendDist = "web/dist"
	}
	c.Management.FrontendDist = strings.TrimSpace(c.Management.FrontendDist)
	c.Management.AllowedOrigins = normalizeStringList(c.Management.AllowedOrigins)
	if c.Management.Enabled == nil {
		defaultEnabled := true
		c.Management.Enabled = &defaultEnabled
	}
	if err := c.normalizeNamedPools(); err != nil {
		return err
	}

	// Subscription refresh defaults
	if c.SubscriptionRefresh.Interval <= 0 {
		c.SubscriptionRefresh.Interval = 1 * time.Hour
	}
	if c.SubscriptionRefresh.Timeout <= 0 {
		c.SubscriptionRefresh.Timeout = 30 * time.Second
	}
	if c.SubscriptionRefresh.HealthCheckTimeout <= 0 {
		c.SubscriptionRefresh.HealthCheckTimeout = 60 * time.Second
	}
	if c.SubscriptionRefresh.DrainTimeout <= 0 {
		c.SubscriptionRefresh.DrainTimeout = 30 * time.Second
	}
	if c.SubscriptionRefresh.MinAvailableNodes <= 0 {
		c.SubscriptionRefresh.MinAvailableNodes = 1
	}

	// Mark inline nodes with source
	for idx := range c.Nodes {
		c.Nodes[idx].Source = NodeSourceInline
	}

	// Load nodes from file if specified (but NOT if subscriptions exist - subscription takes priority)
	if c.NodesFile != "" && len(c.Subscriptions) == 0 {
		fileNodes, err := loadNodesFromFile(c.NodesFile)
		if err != nil {
			return fmt.Errorf("load nodes from file %q: %w", c.NodesFile, err)
		}
		for idx := range fileNodes {
			fileNodes[idx].Source = NodeSourceFile
		}
		c.Nodes = append(c.Nodes, fileNodes...)
	}

	// Load nodes from subscriptions (highest priority - writes to nodes.txt)
	if len(c.Subscriptions) > 0 {
		var subNodes []NodeConfig
		subTimeout := c.SubscriptionRefresh.Timeout
		for _, subURL := range c.Subscriptions {
			nodes, err := loadNodesFromSubscription(subURL, subTimeout)
			if err != nil {
				log.Printf("⚠️ Failed to load subscription %q: %v (skipping)", subURL, err)
				continue
			}
			for idx := range nodes {
				nodes[idx].Source = NodeSourceSubscription
				nodes[idx].SourceRef = subURL
			}
			log.Printf("✅ Loaded %d nodes from subscription", len(nodes))
			subNodes = append(subNodes, nodes...)
		}
		if len(subNodes) > 0 {
			// Determine nodes.txt path
			nodesFilePath := c.NodesFile
			if nodesFilePath == "" {
				nodesFilePath = filepath.Join(filepath.Dir(c.filePath), "nodes.txt")
				c.NodesFile = nodesFilePath
			}
			// Write subscription nodes to nodes.txt
			if err := writeNodesToFile(nodesFilePath, subNodes); err != nil {
				log.Printf("⚠️ Failed to write nodes to %q: %v", nodesFilePath, err)
			} else {
				log.Printf("✅ Written %d subscription nodes to %s", len(subNodes), nodesFilePath)
			}
		}
		c.Nodes = append(c.Nodes, subNodes...)
	}

	if len(c.Nodes) == 0 {
		if c.LogLevel == "" {
			c.LogLevel = "info"
		}
		return nil
	}
	portCursor := c.MultiPort.BasePort
	for idx := range c.Nodes {
		c.Nodes[idx].Name = strings.TrimSpace(c.Nodes[idx].Name)
		c.Nodes[idx].URI = strings.TrimSpace(c.Nodes[idx].URI)

		if c.Nodes[idx].URI == "" {
			return fmt.Errorf("node %d is missing uri", idx)
		}

		// Auto-extract name from URI fragment (#name) if not provided
		if c.Nodes[idx].Name == "" {
			if parsed, err := url.Parse(c.Nodes[idx].URI); err == nil && parsed.Fragment != "" {
				// URL decode the fragment to handle encoded characters
				if decoded, err := url.QueryUnescape(parsed.Fragment); err == nil {
					c.Nodes[idx].Name = decoded
				} else {
					c.Nodes[idx].Name = parsed.Fragment
				}
			}
		}

		// Fallback to default name if still empty
		if c.Nodes[idx].Name == "" {
			c.Nodes[idx].Name = fmt.Sprintf("node-%d", idx)
		}

		// Auto-assign port in multi-port/hybrid mode, skip occupied ports
		if c.Nodes[idx].Port == 0 && (c.Mode == "multi-port" || c.Mode == "hybrid") {
			for !isPortAvailable(c.MultiPort.Address, portCursor) {
				log.Printf("⚠️  Port %d is in use, trying next port", portCursor)
				portCursor++
				if portCursor > 65535 {
					return fmt.Errorf("no available ports found starting from %d", c.MultiPort.BasePort)
				}
			}
			c.Nodes[idx].Port = portCursor
			portCursor++
		} else if c.Nodes[idx].Port == 0 {
			c.Nodes[idx].Port = portCursor
			portCursor++
		}

		if c.Mode == "multi-port" || c.Mode == "hybrid" {
			if c.Nodes[idx].Username == "" {
				c.Nodes[idx].Username = c.MultiPort.Username
				c.Nodes[idx].Password = c.MultiPort.Password
			}
		}
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	// Auto-fix port conflicts in hybrid mode (pool port vs multi-port)
	if c.Mode == "hybrid" {
		poolPorts := c.namedPoolPorts()
		poolPortSet := make(map[uint16]struct{}, len(poolPorts))
		usedPorts := make(map[uint16]bool)
		for _, poolPort := range poolPorts {
			usedPorts[poolPort] = true
			poolPortSet[poolPort] = struct{}{}
		}
		for idx := range c.Nodes {
			usedPorts[c.Nodes[idx].Port] = true
		}
		for idx := range c.Nodes {
			if _, conflict := poolPortSet[c.Nodes[idx].Port]; conflict {
				// Find next available port
				newPort := c.Nodes[idx].Port + 1
				for usedPorts[newPort] || !isPortAvailable(c.MultiPort.Address, newPort) {
					newPort++
					if newPort > 65535 {
						return fmt.Errorf("no available port for node %q after conflict with pool listener port", c.Nodes[idx].Name)
					}
				}
				log.Printf("⚠️  Node %q port %d conflicts with pool listener port, reassigned to %d", c.Nodes[idx].Name, c.Nodes[idx].Port, newPort)
				usedPorts[newPort] = true
				c.Nodes[idx].Port = newPort
			}
		}
	}

	return nil
}

func normalizePoolConfigDefaults(pool *PoolConfig) {
	if pool == nil {
		return
	}
	if pool.Mode == "" {
		pool.Mode = "sequential"
	}
	if pool.FailureThreshold <= 0 {
		pool.FailureThreshold = 3
	}
	if pool.BlacklistDuration <= 0 {
		pool.BlacklistDuration = 24 * time.Hour
	}
	if pool.DomainFailureThreshold <= 0 {
		pool.DomainFailureThreshold = 2
	}
	if pool.DomainBlacklistDuration <= 0 {
		pool.DomainBlacklistDuration = 12 * time.Hour
	}
	if pool.DomainRecheckInterval <= 0 {
		pool.DomainRecheckInterval = 10 * time.Minute
	}
	if pool.DomainRecheckTimeout <= 0 {
		pool.DomainRecheckTimeout = 10 * time.Second
	}
}

func normalizeStringList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyPoolConfigFallback(pool *PoolConfig, fallback PoolConfig) {
	if pool == nil {
		return
	}
	if pool.Mode == "" {
		pool.Mode = fallback.Mode
	}
	if pool.FailureThreshold <= 0 {
		pool.FailureThreshold = fallback.FailureThreshold
	}
	if pool.BlacklistDuration <= 0 {
		pool.BlacklistDuration = fallback.BlacklistDuration
	}
	if pool.DomainFailureThreshold <= 0 {
		pool.DomainFailureThreshold = fallback.DomainFailureThreshold
	}
	if pool.DomainBlacklistDuration <= 0 {
		pool.DomainBlacklistDuration = fallback.DomainBlacklistDuration
	}
	if pool.DomainRecheckInterval <= 0 {
		pool.DomainRecheckInterval = fallback.DomainRecheckInterval
	}
	if pool.DomainRecheckTimeout <= 0 {
		pool.DomainRecheckTimeout = fallback.DomainRecheckTimeout
	}
}

func normalizePoolName(name string, index int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		if index == 0 {
			return defaultNamedPoolName
		}
		return fmt.Sprintf("pool-%d", index+1)
	}
	return name
}

func (c *Config) normalizeNamedPools() error {
	if c == nil {
		return nil
	}

	defaultPool := c.Pool
	normalizePoolConfigDefaults(&defaultPool)

	if len(c.NamedPools) == 0 {
		c.NamedPools = []NamedPoolConfig{{
			Name:     defaultNamedPoolName,
			Listener: c.Listener,
			Pool:     defaultPool,
		}}
	}

	nameSet := make(map[string]struct{}, len(c.NamedPools))
	listenerSet := make(map[string]string, len(c.NamedPools))
	for idx := range c.NamedPools {
		pool := &c.NamedPools[idx]
		pool.Name = normalizePoolName(pool.Name, idx)

		nameKey := strings.ToLower(pool.Name)
		if _, exists := nameSet[nameKey]; exists {
			return fmt.Errorf("duplicate named pool name %q", pool.Name)
		}
		nameSet[nameKey] = struct{}{}

		if pool.Listener.Address == "" {
			pool.Listener.Address = c.Listener.Address
		}
		if pool.Listener.Port == 0 {
			if idx == 0 {
				pool.Listener.Port = c.Listener.Port
			} else {
				candidate := int(c.Listener.Port) + idx
				if candidate > 65535 {
					return fmt.Errorf("named pool %q computed listener port exceeds 65535", pool.Name)
				}
				pool.Listener.Port = uint16(candidate)
			}
		}
		if pool.Listener.Username == "" {
			pool.Listener.Username = c.Listener.Username
		}
		if pool.Listener.Password == "" {
			pool.Listener.Password = c.Listener.Password
		}

		applyPoolConfigFallback(&pool.Pool, defaultPool)
		normalizePoolConfigDefaults(&pool.Pool)

		bindKey := net.JoinHostPort(pool.Listener.Address, strconv.Itoa(int(pool.Listener.Port)))
		if existing, exists := listenerSet[bindKey]; exists {
			return fmt.Errorf("named pools %q and %q use the same listener %s", existing, pool.Name, bindKey)
		}
		listenerSet[bindKey] = pool.Name
	}

	// Keep legacy fields aligned for compatibility.
	c.Listener = c.NamedPools[0].Listener
	c.Pool = c.NamedPools[0].Pool
	return nil
}

// EffectiveNamedPools returns a copy of configured named pools.
func (c *Config) EffectiveNamedPools() []NamedPoolConfig {
	if c == nil {
		return nil
	}
	if len(c.NamedPools) == 0 {
		poolCfg := c.Pool
		normalizePoolConfigDefaults(&poolCfg)
		return []NamedPoolConfig{{
			Name:     defaultNamedPoolName,
			Listener: c.Listener,
			Pool:     poolCfg,
		}}
	}
	out := make([]NamedPoolConfig, len(c.NamedPools))
	copy(out, c.NamedPools)
	return out
}

func (c *Config) namedPoolPorts() []uint16 {
	pools := c.EffectiveNamedPools()
	ports := make([]uint16, 0, len(pools))
	for _, pool := range pools {
		if pool.Listener.Port > 0 {
			ports = append(ports, pool.Listener.Port)
		}
	}
	return ports
}

// BuildPortMap creates a mapping from node URI to port for existing nodes.
// This is used to preserve port assignments when reloading configuration.
func (c *Config) BuildPortMap() map[string]uint16 {
	portMap := make(map[string]uint16)
	for _, node := range c.Nodes {
		if node.Port > 0 {
			portMap[node.NodeKey()] = node.Port
		}
	}
	return portMap
}

// NormalizeWithPortMap applies defaults and validation, preserving port assignments
// for nodes that exist in the provided port map.
func (c *Config) NormalizeWithPortMap(portMap map[string]uint16) error {
	if c.Mode == "" {
		c.Mode = "pool"
	}
	if c.Mode == "multi_port" {
		c.Mode = "multi-port"
	}
	switch c.Mode {
	case "pool", "multi-port", "hybrid":
	default:
		return fmt.Errorf("unsupported mode %q (use 'pool', 'multi-port', or 'hybrid')", c.Mode)
	}
	if c.Listener.Address == "" {
		c.Listener.Address = "0.0.0.0"
	}
	if c.Listener.Port == 0 {
		c.Listener.Port = 2323
	}
	normalizePoolConfigDefaults(&c.Pool)
	if c.MultiPort.Address == "" {
		c.MultiPort.Address = "0.0.0.0"
	}
	if c.MultiPort.BasePort == 0 {
		c.MultiPort.BasePort = 28000
	}
	if c.Management.Listen == "" {
		c.Management.Listen = "127.0.0.1:9090"
	}
	if c.Management.ProbeTarget == "" {
		c.Management.ProbeTarget = "www.apple.com:80"
	}
	if strings.TrimSpace(c.Management.FrontendDist) == "" {
		c.Management.FrontendDist = "web/dist"
	}
	c.Management.FrontendDist = strings.TrimSpace(c.Management.FrontendDist)
	c.Management.AllowedOrigins = normalizeStringList(c.Management.AllowedOrigins)
	if c.Management.Enabled == nil {
		defaultEnabled := true
		c.Management.Enabled = &defaultEnabled
	}
	if err := c.normalizeNamedPools(); err != nil {
		return err
	}
	if c.SubscriptionRefresh.Interval <= 0 {
		c.SubscriptionRefresh.Interval = 1 * time.Hour
	}
	if c.SubscriptionRefresh.Timeout <= 0 {
		c.SubscriptionRefresh.Timeout = 30 * time.Second
	}
	if c.SubscriptionRefresh.HealthCheckTimeout <= 0 {
		c.SubscriptionRefresh.HealthCheckTimeout = 60 * time.Second
	}
	if c.SubscriptionRefresh.DrainTimeout <= 0 {
		c.SubscriptionRefresh.DrainTimeout = 30 * time.Second
	}
	if c.SubscriptionRefresh.MinAvailableNodes <= 0 {
		c.SubscriptionRefresh.MinAvailableNodes = 1
	}

	if len(c.Nodes) == 0 {
		if c.LogLevel == "" {
			c.LogLevel = "info"
		}
		return nil
	}

	// Build set of ports already assigned from portMap
	usedPorts := make(map[uint16]bool)
	if c.Mode == "hybrid" {
		for _, poolPort := range c.namedPoolPorts() {
			usedPorts[poolPort] = true
		}
	}

	// First pass: assign ports from portMap for existing nodes
	for idx := range c.Nodes {
		c.Nodes[idx].Name = strings.TrimSpace(c.Nodes[idx].Name)
		c.Nodes[idx].URI = strings.TrimSpace(c.Nodes[idx].URI)
		if c.Nodes[idx].URI == "" {
			return fmt.Errorf("node %d is missing uri", idx)
		}

		// Extract name from URI fragment if not provided
		if c.Nodes[idx].Name == "" {
			if parsed, err := url.Parse(c.Nodes[idx].URI); err == nil && parsed.Fragment != "" {
				if decoded, err := url.QueryUnescape(parsed.Fragment); err == nil {
					c.Nodes[idx].Name = decoded
				} else {
					c.Nodes[idx].Name = parsed.Fragment
				}
			}
		}
		if c.Nodes[idx].Name == "" {
			c.Nodes[idx].Name = fmt.Sprintf("node-%d", idx)
		}

		// Check if this node has a preserved port from portMap
		if c.Mode == "multi-port" || c.Mode == "hybrid" {
			nodeKey := c.Nodes[idx].NodeKey()
			if existingPort, ok := portMap[nodeKey]; ok && existingPort > 0 {
				c.Nodes[idx].Port = existingPort
				usedPorts[existingPort] = true
				log.Printf("✅ Preserved port %d for node %q", existingPort, c.Nodes[idx].Name)
			}
		}
	}

	// Second pass: assign new ports for nodes without preserved ports
	portCursor := c.MultiPort.BasePort
	for idx := range c.Nodes {
		if c.Nodes[idx].Port == 0 && (c.Mode == "multi-port" || c.Mode == "hybrid") {
			// Find next available port that's not used
			for usedPorts[portCursor] || !isPortAvailable(c.MultiPort.Address, portCursor) {
				portCursor++
				if portCursor > 65535 {
					return fmt.Errorf("no available ports found starting from %d", c.MultiPort.BasePort)
				}
			}
			c.Nodes[idx].Port = portCursor
			usedPorts[portCursor] = true
			log.Printf("📌 Assigned new port %d for node %q", portCursor, c.Nodes[idx].Name)
			portCursor++
		} else if c.Nodes[idx].Port == 0 {
			c.Nodes[idx].Port = portCursor
			portCursor++
		}

		// Apply default credentials
		if c.Mode == "multi-port" || c.Mode == "hybrid" {
			if c.Nodes[idx].Username == "" {
				c.Nodes[idx].Username = c.MultiPort.Username
				c.Nodes[idx].Password = c.MultiPort.Password
			}
		}
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	if c.Mode == "hybrid" {
		poolPortSet := make(map[uint16]struct{})
		for _, poolPort := range c.namedPoolPorts() {
			poolPortSet[poolPort] = struct{}{}
		}
		used := make(map[uint16]struct{}, len(c.Nodes))
		for _, node := range c.Nodes {
			if node.Port > 0 {
				used[node.Port] = struct{}{}
			}
		}
		for idx := range c.Nodes {
			if _, conflict := poolPortSet[c.Nodes[idx].Port]; !conflict {
				continue
			}
			newPort := c.Nodes[idx].Port + 1
			for {
				if _, exists := used[newPort]; !exists && !portConflictsPool(newPort, poolPortSet) && isPortAvailable(c.MultiPort.Address, newPort) {
					break
				}
				newPort++
				if newPort > 65535 {
					return fmt.Errorf("no available port for node %q after conflict with pool listener port", c.Nodes[idx].Name)
				}
			}
			log.Printf("⚠️  Node %q port %d conflicts with pool listener port, reassigned to %d", c.Nodes[idx].Name, c.Nodes[idx].Port, newPort)
			delete(used, c.Nodes[idx].Port)
			used[newPort] = struct{}{}
			c.Nodes[idx].Port = newPort
		}
	}

	return nil
}

func portConflictsPool(port uint16, poolPortSet map[uint16]struct{}) bool {
	_, conflict := poolPortSet[port]
	return conflict
}

// ManagementEnabled reports whether the monitoring endpoint should run.
func (c *Config) ManagementEnabled() bool {
	if c.Management.Enabled == nil {
		return true
	}
	return *c.Management.Enabled
}

// loadNodesFromFile reads a nodes file where each line is a proxy URI
// Lines starting with # are comments, empty lines are ignored
func loadNodesFromFile(path string) ([]NodeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseNodesFromContent(string(data))
}

// loadNodesFromSubscription fetches and parses nodes from a subscription URL
// Supports multiple formats: base64 encoded, plain text, clash yaml, etc.
func loadNodesFromSubscription(subURL string, timeout time.Duration) ([]NodeConfig, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set common headers to avoid being blocked
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	content := string(body)

	// Try to detect and parse different formats
	return parseSubscriptionContent(content)
}

// parseSubscriptionContent tries to parse subscription content in various formats (optimized)
func parseSubscriptionContent(content string) ([]NodeConfig, error) {
	content = strings.TrimSpace(content)

	// Detect Clash/Mihomo YAML (proxies section may appear deep in file)
	if strings.Contains(content, "\nproxies:") || strings.HasPrefix(content, "proxies:") {
		return parseClashYAML(content)
	}

	// Check if it's base64 encoded (common for v2ray subscriptions)
	if isBase64(content) {
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			// Try URL-safe base64
			decoded, err = base64.RawStdEncoding.DecodeString(content)
			if err != nil {
				// Not base64, try as plain text
				return parseNodesFromContent(content)
			}
		}
		content = string(decoded)
		if strings.Contains(content, "\nproxies:") || strings.HasPrefix(content, "proxies:") {
			return parseClashYAML(content)
		}
	}

	// Parse as plain text (one URI per line)
	return parseNodesFromContent(content)
}

// parseNodesFromContent parses nodes from plain text content (one URI per line)
func parseNodesFromContent(content string) ([]NodeConfig, error) {
	var nodes []NodeConfig
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a valid proxy URI
		if isProxyURI(line) {
			nodes = append(nodes, NodeConfig{
				URI: line,
			})
		}
	}

	return nodes, nil
}

// isBase64 checks if a string looks like base64 encoded content (optimized version)
func isBase64(s string) bool {
	// Remove whitespace
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return false
	}

	// Remove newlines for checking
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")

	// Quick check: if it contains proxy URI schemes, it's not base64
	if strings.Contains(s, "://") {
		return false
	}

	// Check character set - base64 only contains A-Za-z0-9+/=
	// This is much faster than trying to decode
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}

	// Length must be multiple of 4 (with padding)
	return len(s)%4 == 0
}

// isProxyURI checks if a string is a valid proxy URI
func isProxyURI(s string) bool {
	schemes := []string{"vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "hy2://"}
	for _, scheme := range schemes {
		if strings.HasPrefix(strings.ToLower(s), scheme) {
			return true
		}
	}
	return false
}

// clashConfig represents a minimal Clash configuration for parsing proxies
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
	AlterId           int                    `yaml:"alterId"`
	Network           string                 `yaml:"network"`
	TLS               bool                   `yaml:"tls"`
	SkipCertVerify    bool                   `yaml:"skip-cert-verify"`
	ServerName        string                 `yaml:"servername"`
	SNI               string                 `yaml:"sni"`
	Flow              string                 `yaml:"flow"`
	UDP               bool                   `yaml:"udp"`
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

// parseClashYAML parses Clash YAML format and converts to NodeConfig
func parseClashYAML(content string) ([]NodeConfig, error) {
	var clash clashConfig
	if err := yaml.Unmarshal([]byte(content), &clash); err != nil {
		return nil, fmt.Errorf("parse clash yaml: %w", err)
	}

	var nodes []NodeConfig
	for _, proxy := range clash.Proxies {
		uri := convertClashProxyToURI(proxy)
		if uri != "" {
			nodes = append(nodes, NodeConfig{
				Name: proxy.Name,
				URI:  uri,
			})
		}
	}

	return nodes, nil
}

// convertClashProxyToURI converts a Clash proxy config to a standard URI
func convertClashProxyToURI(p clashProxy) string {
	switch strings.ToLower(p.Type) {
	case "vmess":
		return buildVMessURI(p)
	case "vless":
		return buildVLESSURI(p)
	case "trojan":
		return buildTrojanURI(p)
	case "ss", "shadowsocks":
		return buildShadowsocksURI(p)
	case "hysteria2", "hy2":
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

	return fmt.Sprintf("vmess://%s@%s:%d%s#%s", p.UUID, p.Server, p.Port, query, url.QueryEscape(p.Name))
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

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", p.UUID, p.Server, p.Port, params.Encode(), url.QueryEscape(p.Name))
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

	return fmt.Sprintf("trojan://%s@%s:%d%s#%s", p.Password, p.Server, p.Port, query, url.QueryEscape(p.Name))
}

func buildShadowsocksURI(p clashProxy) string {
	// Encode method:password in base64
	userInfo := base64.StdEncoding.EncodeToString([]byte(p.Cipher + ":" + p.Password))
	return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, p.Server, p.Port, url.QueryEscape(p.Name))
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

	return fmt.Sprintf("hysteria2://%s@%s:%d%s#%s", p.Password, p.Server, p.Port, query, url.QueryEscape(p.Name))
}

// FilePath returns the config file path.
func (c *Config) FilePath() string {
	if c == nil {
		return ""
	}
	return c.filePath
}

// SetFilePath sets the config file path (used when creating config programmatically).
func (c *Config) SetFilePath(path string) {
	if c != nil {
		c.filePath = path
	}
}

// writeNodesToFile writes nodes to a file (one URI per line) with file locking.
func writeNodesToFile(path string, nodes []NodeConfig) error {
	var lines []string
	for _, node := range nodes {
		lines = append(lines, node.URI)
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	// Use file locking for safe concurrent writes
	return writeFileWithLock(path, []byte(content), 0o644)
}

// SaveNodes persists nodes to their appropriate locations based on source.
// - subscription/nodes_file nodes -> nodes.txt (or configured nodes_file)
// - inline nodes -> file-based config nodes array (legacy fallback mode)
// File structure (subscriptions, nodes_file) is preserved.
func (c *Config) SaveNodes() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.filePath == "" {
		return errors.New("config file path is unknown")
	}

	// Separate nodes by source
	var inlineNodes []NodeConfig
	var fileNodes []NodeConfig

	for _, node := range c.Nodes {
		// Create a clean copy without runtime fields for saving
		cleanNode := NodeConfig{
			Name:     node.Name,
			URI:      node.URI,
			Port:     node.Port,
			Username: node.Username,
			Password: node.Password,
		}
		switch node.Source {
		case NodeSourceInline:
			inlineNodes = append(inlineNodes, cleanNode)
		case NodeSourceFile, NodeSourceSubscription:
			fileNodes = append(fileNodes, cleanNode)
		default:
			// Default to file nodes for unknown source
			fileNodes = append(fileNodes, cleanNode)
		}
	}

	// Write file-based nodes to nodes.txt
	if len(fileNodes) > 0 || c.NodesFile != "" {
		nodesFilePath := c.NodesFile
		if nodesFilePath == "" {
			nodesFilePath = filepath.Join(filepath.Dir(c.filePath), "nodes.txt")
		}
		if err := writeNodesToFile(nodesFilePath, fileNodes); err != nil {
			return fmt.Errorf("write nodes file %q: %w", nodesFilePath, err)
		}
	}

	// Only update file-based config if there are inline nodes to save
	// and preserve the original config structure
	if len(inlineNodes) > 0 {
		// Read original config to preserve structure
		data, err := os.ReadFile(c.filePath)
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}
		var saveCfg Config
		if err := yaml.Unmarshal(data, &saveCfg); err != nil {
			return fmt.Errorf("decode config: %w", err)
		}
		// Update only the inline nodes
		saveCfg.Nodes = inlineNodes

		newData, err := yaml.Marshal(&saveCfg)
		if err != nil {
			return fmt.Errorf("encode config: %w", err)
		}
		// Use file locking for safe concurrent writes
		if err := writeFileWithLock(c.filePath, newData, 0o644); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}

	return nil
}

// Save is deprecated, use SaveNodes instead.
// This method is kept for backward compatibility but now delegates to SaveNodes.
func (c *Config) Save() error {
	return c.SaveNodes()
}

// SaveSettings persists only runtime settings (external_ip, probe_target, skip_cert_verify, listener auth)
// without touching nodes.txt. Use this for settings API updates.
func (c *Config) SaveSettings() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.filePath == "" {
		return errors.New("config file path is unknown")
	}

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var saveCfg Config
	if err := yaml.Unmarshal(data, &saveCfg); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}

	saveCfg.ExternalIP = c.ExternalIP
	saveCfg.Management.ProbeTarget = c.Management.ProbeTarget
	saveCfg.SkipCertVerify = c.SkipCertVerify
	saveCfg.Listener.Username = c.Listener.Username
	saveCfg.Listener.Password = c.Listener.Password
	if len(saveCfg.NamedPools) > 0 {
		saveCfg.NamedPools[0].Listener.Username = c.Listener.Username
		saveCfg.NamedPools[0].Listener.Password = c.Listener.Password
	}

	newData, err := yaml.Marshal(&saveCfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	// Use file locking for safe concurrent writes
	if err := writeFileWithLock(c.filePath, newData, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// SaveSubscriptions persists only the subscriptions list to file-based config (legacy fallback mode).
func (c *Config) SaveSubscriptions() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.filePath == "" {
		return errors.New("config file path is unknown")
	}

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var saveCfg Config
	if err := yaml.Unmarshal(data, &saveCfg); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}

	saveCfg.Subscriptions = append([]string(nil), c.Subscriptions...)

	newData, err := yaml.Marshal(&saveCfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	if err := writeFileWithLock(c.filePath, newData, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// ApplyEnvOverrides applies runtime settings from environment variables.
// Storage DSN priority (high -> low):
// 1) DB_*
// 2) PG_DSN
// 3) DATABASE_URL
func (c *Config) ApplyEnvOverrides() error {
	if c == nil {
		return nil
	}

	if v, ok, _ := lookupEnvAlias("DB_DRIVER"); ok {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			c.Storage.Driver = v
		}
	}

	if v, ok, _ := lookupEnvAlias("DB_DSN"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.Storage.DSN = v
		}
	}

	if v, ok, key := lookupEnvAlias("DB_AUTO_MIGRATE"); ok {
		parsed, err := parseBoolEnv(key, v)
		if err != nil {
			return err
		}
		c.Storage.AutoMigrate = &parsed
	}

	if c.Storage.DSN == "" {
		if v, ok, _ := lookupEnvAlias("PG_DSN"); ok {
			v = strings.TrimSpace(v)
			if v != "" {
				c.Storage.DSN = v
				if c.Storage.Driver == "" {
					c.Storage.Driver = "postgres"
				}
			}
		}
	}

	if c.Storage.DSN == "" {
		if v, ok := os.LookupEnv("DATABASE_URL"); ok {
			v = strings.TrimSpace(v)
			if v != "" {
				c.Storage.DSN = v
				if c.Storage.Driver == "" {
					c.Storage.Driver = inferDriverFromDSN(v)
				}
			}
		}
	}

	if c.Storage.Driver == "" && c.Storage.DSN != "" {
		c.Storage.Driver = inferDriverFromDSN(c.Storage.DSN)
	}

	if v, ok, _ := lookupEnvAlias("MODE"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.Mode = v
		}
	}

	if v, ok, _ := lookupEnvAlias("LOG_LEVEL"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.LogLevel = v
		}
	}

	if v, ok, _ := lookupEnvAlias("EXTERNAL_IP"); ok {
		c.ExternalIP = strings.TrimSpace(v)
	}

	if v, ok, key := lookupEnvAlias("SKIP_CERT_VERIFY"); ok {
		parsed, err := parseBoolEnv(key, v)
		if err != nil {
			return err
		}
		c.SkipCertVerify = parsed
	}

	if v, ok, _ := lookupEnvAlias("PROBE_TARGET"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.Management.ProbeTarget = v
		}
	}

	managementEnabledOverridden := false
	if v, ok, key := lookupEnvAlias("MANAGEMENT_ENABLED"); ok {
		parsed, err := parseBoolEnv(key, v)
		if err != nil {
			return err
		}
		parsedValue := parsed
		c.Management.Enabled = &parsedValue
		managementEnabledOverridden = true
	}

	managementListenOverridden := false
	if v, ok, _ := lookupEnvAlias("MANAGEMENT_LISTEN"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.Management.Listen = v
			managementListenOverridden = true
		}
	}

	if v, ok, _ := lookupEnvAlias("MANAGEMENT_PASSWORD"); ok {
		c.Management.Password = strings.TrimSpace(v)
	}

	if v, ok, _ := lookupEnvAlias("MANAGEMENT_FRONTEND_DIST", "FRONTEND_DIST"); ok {
		c.Management.FrontendDist = strings.TrimSpace(v)
	}

	if v, ok, _ := lookupEnvAlias("MANAGEMENT_ALLOWED_ORIGINS", "ALLOWED_ORIGINS"); ok {
		c.Management.AllowedOrigins = normalizeStringList(parseSubscriptionEnvList(v))
	}

	listenerAddressOverridden := false
	if v, ok, _ := lookupEnvAlias("LISTENER_ADDRESS"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.Listener.Address = v
			listenerAddressOverridden = true
		}
	}

	listenerPortOverridden := false
	if v, ok, key := lookupEnvAlias("LISTENER_PORT"); ok {
		port, err := parsePortEnv(key, v)
		if err != nil {
			return err
		}
		c.Listener.Port = port
		listenerPortOverridden = true
	}

	if v, ok, _ := lookupEnvAlias("LISTENER_USERNAME"); ok {
		c.Listener.Username = strings.TrimSpace(v)
	}

	if v, ok, _ := lookupEnvAlias("LISTENER_PASSWORD"); ok {
		c.Listener.Password = strings.TrimSpace(v)
	}
	if len(c.NamedPools) > 0 {
		if listenerAddressOverridden {
			c.NamedPools[0].Listener.Address = c.Listener.Address
		}
		if listenerPortOverridden {
			c.NamedPools[0].Listener.Port = c.Listener.Port
		}
		if c.Listener.Username != "" {
			c.NamedPools[0].Listener.Username = c.Listener.Username
		}
		if c.Listener.Password != "" {
			c.NamedPools[0].Listener.Password = c.Listener.Password
		}
	}

	if v, ok, _ := lookupEnvAlias("MULTI_PORT_ADDRESS"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.MultiPort.Address = v
		}
	}

	if v, ok, key := lookupEnvAlias("MULTI_PORT_BASE_PORT"); ok {
		port, err := parsePortEnv(key, v)
		if err != nil {
			return err
		}
		c.MultiPort.BasePort = port
	}

	if v, ok, _ := lookupEnvAlias("MULTI_PORT_USERNAME"); ok {
		c.MultiPort.Username = strings.TrimSpace(v)
	}

	if v, ok, _ := lookupEnvAlias("MULTI_PORT_PASSWORD"); ok {
		c.MultiPort.Password = strings.TrimSpace(v)
	}

	if v, ok, _ := lookupEnvAlias("POOL_MODE"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.Pool.Mode = v
		}
	}

	if v, ok, key := lookupEnvAlias("POOL_FAILURE_THRESHOLD"); ok {
		n, err := parseIntEnv(key, v)
		if err != nil {
			return err
		}
		c.Pool.FailureThreshold = n
	}

	if v, ok, key := lookupEnvAlias("POOL_BLACKLIST_DURATION"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.Pool.BlacklistDuration = d
	}

	if v, ok, key := lookupEnvAlias("POOL_DOMAIN_FAILURE_THRESHOLD"); ok {
		n, err := parseIntEnv(key, v)
		if err != nil {
			return err
		}
		c.Pool.DomainFailureThreshold = n
	}

	if v, ok, key := lookupEnvAlias("POOL_DOMAIN_BLACKLIST_DURATION"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.Pool.DomainBlacklistDuration = d
	}

	if v, ok, key := lookupEnvAlias("POOL_DOMAIN_RECHECK_INTERVAL"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.Pool.DomainRecheckInterval = d
	}

	if v, ok, key := lookupEnvAlias("POOL_DOMAIN_RECHECK_TIMEOUT"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.Pool.DomainRecheckTimeout = d
	}

	if v, ok, key := lookupEnvAlias("SUBSCRIPTION_REFRESH_ENABLED"); ok {
		parsed, err := parseBoolEnv(key, v)
		if err != nil {
			return err
		}
		c.SubscriptionRefresh.Enabled = parsed
	}

	if v, ok, key := lookupEnvAlias("SUBSCRIPTION_REFRESH_INTERVAL"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.SubscriptionRefresh.Interval = d
	}

	if v, ok, key := lookupEnvAlias("SUBSCRIPTION_REFRESH_TIMEOUT"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.SubscriptionRefresh.Timeout = d
	}

	if v, ok, key := lookupEnvAlias("SUBSCRIPTION_REFRESH_HEALTH_CHECK_TIMEOUT"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.SubscriptionRefresh.HealthCheckTimeout = d
	}

	if v, ok, key := lookupEnvAlias("SUBSCRIPTION_REFRESH_DRAIN_TIMEOUT"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.SubscriptionRefresh.DrainTimeout = d
	}

	if v, ok, key := lookupEnvAlias("SUBSCRIPTION_REFRESH_MIN_AVAILABLE_NODES"); ok {
		n, err := parseIntEnv(key, v)
		if err != nil {
			return err
		}
		c.SubscriptionRefresh.MinAvailableNodes = n
	}

	if v, ok, key := lookupEnvAlias("GEOIP_ENABLED"); ok {
		parsed, err := parseBoolEnv(key, v)
		if err != nil {
			return err
		}
		c.GeoIP.Enabled = parsed
	}

	if v, ok, _ := lookupEnvAlias("GEOIP_DATABASE_PATH"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.GeoIP.DatabasePath = v
		}
	}

	if v, ok, _ := lookupEnvAlias("GEOIP_LISTEN"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			c.GeoIP.Listen = v
		}
	}

	if v, ok, key := lookupEnvAlias("GEOIP_PORT"); ok {
		port, err := parsePortEnv(key, v)
		if err != nil {
			return err
		}
		c.GeoIP.Port = port
	}

	if v, ok, key := lookupEnvAlias("GEOIP_AUTO_UPDATE_ENABLED"); ok {
		parsed, err := parseBoolEnv(key, v)
		if err != nil {
			return err
		}
		c.GeoIP.AutoUpdateEnabled = parsed
	}

	if v, ok, key := lookupEnvAlias("GEOIP_AUTO_UPDATE_INTERVAL"); ok {
		d, err := parseDurationEnv(key, v)
		if err != nil {
			return err
		}
		c.GeoIP.AutoUpdateInterval = d
	}

	if v, ok, _ := lookupEnvAlias("NODES_FILE"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			if !filepath.IsAbs(v) && c.filePath != "" {
				v = filepath.Join(filepath.Dir(c.filePath), v)
			}
			c.NodesFile = v
		}
	}

	if v, ok, _ := lookupEnvAlias("SUBSCRIPTIONS"); ok {
		c.Subscriptions = parseSubscriptionEnvList(v)
	} else if v, ok, _ := lookupEnvAlias("SUBSCRIPTION"); ok {
		v = strings.TrimSpace(v)
		if v == "" {
			c.Subscriptions = nil
		} else {
			c.Subscriptions = []string{v}
		}
	}

	// Render Web Service injects PORT dynamically.
	// RENDER_EXPOSE controls which endpoint binds to PORT:
	// - management (default): management.listen
	// - proxy: listener.address:listener.port
	if portRaw, ok := os.LookupEnv("PORT"); ok {
		port, err := parsePortEnv("PORT", portRaw)
		if err != nil {
			return err
		}

		expose := ""
		if v, ok, _ := lookupEnvAlias("RENDER_EXPOSE"); ok {
			expose = strings.ToLower(strings.TrimSpace(v))
		}
		if expose == "" {
			expose = "management"
		}

		switch expose {
		case "management", "monitor", "webui":
			if managementEnabledOverridden && !c.ManagementEnabled() {
				return errors.New("RENDER_EXPOSE=management requires MANAGEMENT_ENABLED=true")
			}
			enabled := true
			c.Management.Enabled = &enabled
			if !managementListenOverridden {
				c.Management.Listen = net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port)))
			}
		case "proxy":
			if !listenerAddressOverridden {
				c.Listener.Address = "0.0.0.0"
				if len(c.NamedPools) > 0 {
					c.NamedPools[0].Listener.Address = c.Listener.Address
				}
			}
			if !listenerPortOverridden {
				c.Listener.Port = port
				if len(c.NamedPools) > 0 {
					c.NamedPools[0].Listener.Port = c.Listener.Port
				}
			}
		default:
			return fmt.Errorf("invalid RENDER_EXPOSE %q (use proxy or management)", expose)
		}
	}

	return nil
}

func parseBoolEnv(key, raw string) (bool, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return false, fmt.Errorf("invalid %s: empty value", key)
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %w", key, err)
	}
	return parsed, nil
}

func parsePortEnv(key, raw string) (uint16, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, fmt.Errorf("invalid %s: empty value", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	if n <= 0 || n > 65535 {
		return 0, fmt.Errorf("invalid %s: must be between 1 and 65535", key)
	}
	return uint16(n), nil
}

func parseIntEnv(key, raw string) (int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, fmt.Errorf("invalid %s: empty value", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return n, nil
}

func parseDurationEnv(key, raw string) (time.Duration, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, fmt.Errorf("invalid %s: empty value", key)
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return d, nil
}

func parseSubscriptionEnvList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '\n', '\r':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func lookupEnvAlias(primary string, legacy ...string) (value string, ok bool, key string) {
	if v, found := os.LookupEnv(primary); found {
		return v, true, primary
	}
	for _, envKey := range legacy {
		if v, found := os.LookupEnv(envKey); found {
			return v, true, envKey
		}
	}
	return "", false, ""
}

func inferDriverFromDSN(dsn string) string {
	v := strings.ToLower(strings.TrimSpace(dsn))
	if strings.HasPrefix(v, "postgres://") || strings.HasPrefix(v, "postgresql://") {
		return "postgres"
	}
	if strings.HasPrefix(v, "file:") || strings.HasSuffix(v, ".db") || strings.HasSuffix(v, ".sqlite") || strings.HasSuffix(v, ".sqlite3") {
		return "sqlite"
	}
	if strings.Contains(v, "@tcp(") || strings.Contains(v, "charset=") {
		return "mysql"
	}
	return "postgres"
}

// isPortAvailable checks if a port is available for binding.
func isPortAvailable(address string, port uint16) bool {
	addr := fmt.Sprintf("%s:%d", address, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// File locking helpers

// lockFile acquires an exclusive lock on the file.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile releases the lock on the file.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// writeFileWithLock writes data to a file with exclusive locking.
func writeFileWithLock(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// Acquire exclusive lock
	if err := lockFile(f); err != nil {
		return fmt.Errorf("lock file: %w", err)
	}
	defer unlockFile(f)

	// Write data
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	// Ensure data is written to disk
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync file: %w", err)
	}

	return nil
}
