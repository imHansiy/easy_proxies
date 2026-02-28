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
}

// RuntimeConfig stores application runtime configuration except DB connection settings.
type RuntimeConfig struct {
	Mode                string
	Listener            config.ListenerConfig
	MultiPort           config.MultiPortConfig
	Pool                config.PoolConfig
	ManagementEnabled   *bool
	ManagementListen    string
	ManagementPassword  string
	SubscriptionRefresh config.SubscriptionRefreshConfig
	GeoIP               config.GeoIPConfig
	NodesFile           string
	LogLevel            string
}

// NodeRuntimeState stores runtime health and activity state per node tag.
type NodeRuntimeState struct {
	Tag              string
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
