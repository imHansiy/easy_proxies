package storage

import (
	"context"
	"time"

	"easy_proxies/internal/config"
)

// Settings stores mutable runtime settings exposed by management API.
type Settings struct {
	ExternalIP     string
	ProbeTarget    string
	SkipCertVerify bool
	ProxyUsername  string
	ProxyPassword  string
	ProxyAuthSet   bool
}

// RuntimeConfig stores application runtime configuration except DB connection settings.
type RuntimeConfig struct {
	Mode                     string                           `json:"mode"`
	Listener                 config.ListenerConfig            `json:"listener"`
	NamedPools               []config.NamedPoolConfig         `json:"named_pools"`
	MultiPort                config.MultiPortConfig           `json:"multi_port"`
	Pool                     config.PoolConfig                `json:"pool"`
	ManagementEnabled        *bool                            `json:"management_enabled"`
	ManagementListen         string                           `json:"management_listen"`
	ManagementPassword       string                           `json:"management_password"`
	ManagementFrontendDist   string                           `json:"management_frontend_dist"`
	ManagementAllowedOrigins []string                         `json:"management_allowed_origins"`
	SubscriptionRefresh      config.SubscriptionRefreshConfig `json:"subscription_refresh"`
	GeoIP                    config.GeoIPConfig               `json:"geoip"`
	NodesFile                string                           `json:"nodes_file"`
	LogLevel                 string                           `json:"log_level"`
}

// ScriptSource stores a runnable script definition that outputs nodes.
// This feature is intended for trusted users only.
type ScriptSource struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Command            string    `json:"command"`                       // e.g. python3/node/bash
	Args               []string  `json:"args,omitempty"`                // optional argv before the script path
	Script             string    `json:"script"`                        // script body
	TimeoutMs          int       `json:"timeout_ms,omitempty"`          // execution timeout in milliseconds
	SetupTimeoutMs     int       `json:"setup_timeout_ms,omitempty"`    // dependency/env setup timeout in milliseconds
	MaxOutputBytes     int       `json:"max_output_bytes,omitempty"`    // stdout/stderr cap (each)
	MaxNodes           int       `json:"max_nodes,omitempty"`           // cap parsed nodes
	PythonRequirements []string  `json:"python_requirements,omitempty"` // pip requirement lines
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

// ScriptRunResult is returned by script execution endpoints.
type ScriptRunResult struct {
	SourceID        string              `json:"source_id"`
	ExitCode        int                 `json:"exit_code"`
	DurationMs      int64               `json:"duration_ms"`
	TimedOut        bool                `json:"timed_out,omitempty"`
	Stdout          string              `json:"stdout"`
	StdoutTruncated bool                `json:"stdout_truncated,omitempty"`
	Stderr          string              `json:"stderr"`
	StderrTruncated bool                `json:"stderr_truncated,omitempty"`
	Error           string              `json:"error,omitempty"`
	Nodes           []config.NodeConfig `json:"nodes,omitempty"`
	Applied         bool                `json:"applied"`
	ReplacedCount   int                 `json:"replaced_count,omitempty"`
	ImportedCount   int                 `json:"imported_count,omitempty"`
}

// NodeRuntimeState stores runtime health and activity state per node tag.
type NodeRuntimeState struct {
	Tag              string
	NodeIP           string
	FailureCount     int
	SuccessCount     int64
	Blacklisted      bool
	BlacklistedUntil time.Time
	LastError        string
	LastFailure      time.Time
	LastSuccess      time.Time
	LastProbeLatency time.Duration
	Available        bool
	InitialCheckDone bool
}

// SharedRuntimeState stores shared fail/blacklist state used by pool selection.
type SharedRuntimeState struct {
	Tag              string
	Failures         int
	Blacklisted      bool
	BlacklistedUntil time.Time
}

// Store defines the persistence contract used by this application.
type Store interface {
	Close() error
	EnsureSchema(ctx context.Context) error

	LoadNodes(ctx context.Context) ([]config.NodeConfig, error)
	SaveNodes(ctx context.Context, nodes []config.NodeConfig) error

	LoadSubscriptions(ctx context.Context) ([]string, error)
	SaveSubscriptions(ctx context.Context, subscriptions []string) error

	LoadScriptSources(ctx context.Context) ([]ScriptSource, error)
	SaveScriptSources(ctx context.Context, sources []ScriptSource) error

	LoadRuntimeConfig(ctx context.Context) (RuntimeConfig, bool, error)
	SaveRuntimeConfig(ctx context.Context, runtime RuntimeConfig) error

	LoadSettings(ctx context.Context) (Settings, bool, error)
	SaveSettings(ctx context.Context, settings Settings) error

	LoadNodeRuntimeState(ctx context.Context, tag string) (NodeRuntimeState, bool, error)
	SaveNodeRuntimeState(ctx context.Context, state NodeRuntimeState) error
	DeleteNodeRuntimeState(ctx context.Context, tag string) error

	LoadSharedRuntimeState(ctx context.Context, tag string) (SharedRuntimeState, bool, error)
	SaveSharedRuntimeState(ctx context.Context, state SharedRuntimeState) error
	DeleteSharedRuntimeState(ctx context.Context, tag string) error
}
