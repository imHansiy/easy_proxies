package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"easy_proxies/internal/boxmgr"
	"easy_proxies/internal/config"
	"easy_proxies/internal/monitor"
	"easy_proxies/internal/storage"
	"easy_proxies/internal/subscription"
)

// Run builds the runtime components from config and blocks until shutdown.
func Run(ctx context.Context, cfg *config.Config) error {
	var persistentStore storage.Store
	if cfg.Storage.Enabled() {
		driver, dsn := cfg.Storage.ResolveDriverDSN()
		gormStore, err := storage.NewGORMStore(driver, dsn)
		if err != nil {
			return fmt.Errorf("init db storage: %w", err)
		}
		if cfg.Storage.ShouldAutoMigrate() {
			if err := gormStore.EnsureSchema(ctx); err != nil {
				_ = gormStore.Close()
				return fmt.Errorf("ensure db schema: %w", err)
			}
		}
		persistentStore = gormStore
		defer persistentStore.Close()

		if runtimeCfg, ok, err := gormStore.LoadRuntimeConfig(ctx); err != nil {
			return fmt.Errorf("load runtime config from db: %w", err)
		} else if ok {
			applyRuntimeConfig(cfg, runtimeCfg)
			if err := cfg.NormalizeWithPortMap(cfg.BuildPortMap()); err != nil {
				return fmt.Errorf("normalize config with db runtime config: %w", err)
			}
		} else {
			if err := gormStore.SaveRuntimeConfig(ctx, buildRuntimeConfig(cfg)); err != nil {
				return fmt.Errorf("seed db runtime config: %w", err)
			}
		}

		if settings, ok, err := gormStore.LoadSettings(ctx); err != nil {
			return fmt.Errorf("load settings from db: %w", err)
		} else if ok {
			cfg.ExternalIP = settings.ExternalIP
			if settings.ProbeTarget != "" {
				cfg.Management.ProbeTarget = settings.ProbeTarget
			}
			cfg.SkipCertVerify = settings.SkipCertVerify
		}

		subscriptions, err := gormStore.LoadSubscriptions(ctx)
		if err != nil {
			return fmt.Errorf("load subscriptions from db: %w", err)
		}
		if len(subscriptions) > 0 {
			cfg.Subscriptions = normalizeSubscriptions(subscriptions)
		} else {
			cfg.Subscriptions = normalizeSubscriptions(cfg.Subscriptions)
			if len(cfg.Subscriptions) > 0 {
				if err := gormStore.SaveSubscriptions(ctx, cfg.Subscriptions); err != nil {
					return fmt.Errorf("seed db subscriptions: %w", err)
				}
			}
		}

		nodes, err := gormStore.LoadNodes(ctx)
		if err != nil {
			return fmt.Errorf("load nodes from db: %w", err)
		}
		if len(nodes) > 0 {
			cfg.Nodes = nodes
			if err := cfg.NormalizeWithPortMap(cfg.BuildPortMap()); err != nil {
				return fmt.Errorf("normalize config with db nodes: %w", err)
			}
		} else if len(cfg.Nodes) > 0 {
			if err := gormStore.SaveNodes(ctx, cfg.Nodes); err != nil {
				return fmt.Errorf("seed db nodes: %w", err)
			}
			if err := gormStore.SaveSettings(ctx, storage.Settings{
				ExternalIP:     cfg.ExternalIP,
				ProbeTarget:    cfg.Management.ProbeTarget,
				SkipCertVerify: cfg.SkipCertVerify,
			}); err != nil {
				log.Printf("WARN: seed db settings failed: %v", err)
			}
		}

		if len(cfg.Subscriptions) == 0 {
			inferred := inferSubscriptionsFromNodes(cfg.Nodes)
			if len(inferred) > 0 {
				cfg.Subscriptions = inferred
				if err := gormStore.SaveSubscriptions(ctx, inferred); err != nil {
					log.Printf("WARN: backfill db subscriptions failed: %v", err)
				} else {
					log.Printf("INFO: backfilled %d subscriptions from node source refs", len(inferred))
				}
			}
		}
	}

	if len(cfg.Nodes) == 0 {
		log.Printf("INFO: no nodes configured, starting in monitor-only mode (add nodes or subscriptions then reload)")
	}

	// Build monitor config
	proxyUsername := cfg.Listener.Username
	proxyPassword := cfg.Listener.Password
	if cfg.Mode == "multi-port" || cfg.Mode == "hybrid" {
		proxyUsername = cfg.MultiPort.Username
		proxyPassword = cfg.MultiPort.Password
	}

	monitorCfg := monitor.Config{
		Enabled:       cfg.ManagementEnabled(),
		Listen:        cfg.Management.Listen,
		ProbeTarget:   cfg.Management.ProbeTarget,
		Password:      cfg.Management.Password,
		ProxyUsername: proxyUsername,
		ProxyPassword: proxyPassword,
		ExternalIP:    cfg.ExternalIP,
	}

	// Create and start BoxManager
	boxMgr := boxmgr.New(cfg, monitorCfg, boxmgr.WithStore(persistentStore))
	if err := boxMgr.Start(ctx); err != nil {
		return fmt.Errorf("start box manager: %w", err)
	}
	defer boxMgr.Close()

	// Wire up config to monitor server for settings API
	if server := boxMgr.MonitorServer(); server != nil {
		server.SetConfig(cfg)
	}

	// Create and start SubscriptionManager (supports manual refresh even when auto refresh is disabled)
	var subMgr *subscription.Manager
	subMgr = subscription.New(cfg, boxMgr)
	subMgr.Start()
	defer subMgr.Stop()

	// Wire up subscription manager to monitor server for API endpoints
	if server := boxMgr.MonitorServer(); server != nil {
		server.SetSubscriptionRefresher(subMgr)
	}

	needsSourceRefBootstrap := len(cfg.Subscriptions) > 0
	for _, n := range cfg.Nodes {
		if n.Source == config.NodeSourceSubscription && strings.TrimSpace(n.SourceRef) == "" {
			needsSourceRefBootstrap = true
			break
		}
	}
	if needsSourceRefBootstrap {
		if err := subMgr.RefreshNow(); err != nil {
			log.Printf("WARN: initial subscription refresh failed: %v", err)
		}
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
		fmt.Println("Context cancelled, initiating graceful shutdown...")
	case sig := <-sigCh:
		fmt.Printf("Received %s, initiating graceful shutdown...\n", sig)
	}

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Graceful shutdown sequence
	fmt.Println("Stopping subscription manager...")
	if subMgr != nil {
		subMgr.Stop()
	}

	fmt.Println("Stopping box manager...")
	if err := boxMgr.Close(); err != nil {
		fmt.Printf("Error closing box manager: %v\n", err)
	}

	// Wait for connections to drain
	fmt.Println("Waiting for connections to drain...")
	select {
	case <-time.After(2 * time.Second):
		fmt.Println("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		fmt.Println("Shutdown timeout exceeded, forcing exit")
	}

	return nil
}

func normalizeSubscriptions(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
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

func inferSubscriptionsFromNodes(nodes []config.NodeConfig) []string {
	out := make([]string, 0)
	seen := make(map[string]struct{})
	for _, node := range nodes {
		if node.Source != config.NodeSourceSubscription {
			continue
		}
		ref := strings.TrimSpace(node.SourceRef)
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func buildRuntimeConfig(cfg *config.Config) storage.RuntimeConfig {
	if cfg == nil {
		return storage.RuntimeConfig{}
	}
	return storage.RuntimeConfig{
		Mode:                cfg.Mode,
		Listener:            cfg.Listener,
		MultiPort:           cfg.MultiPort,
		Pool:                cfg.Pool,
		ManagementEnabled:   cloneBoolPtr(cfg.Management.Enabled),
		ManagementListen:    cfg.Management.Listen,
		ManagementPassword:  cfg.Management.Password,
		SubscriptionRefresh: cfg.SubscriptionRefresh,
		GeoIP:               cfg.GeoIP,
		NodesFile:           cfg.NodesFile,
		LogLevel:            cfg.LogLevel,
	}
}

func applyRuntimeConfig(cfg *config.Config, runtimeCfg storage.RuntimeConfig) {
	if cfg == nil {
		return
	}

	cfg.Mode = runtimeCfg.Mode
	cfg.Listener = runtimeCfg.Listener
	cfg.MultiPort = runtimeCfg.MultiPort
	cfg.Pool = runtimeCfg.Pool
	cfg.Management.Enabled = cloneBoolPtr(runtimeCfg.ManagementEnabled)
	cfg.Management.Listen = runtimeCfg.ManagementListen
	cfg.Management.Password = runtimeCfg.ManagementPassword
	cfg.SubscriptionRefresh = runtimeCfg.SubscriptionRefresh
	cfg.GeoIP = runtimeCfg.GeoIP
	cfg.NodesFile = runtimeCfg.NodesFile
	cfg.LogLevel = runtimeCfg.LogLevel
}

func cloneBoolPtr(v *bool) *bool {
	if v == nil {
		return nil
	}
	cpy := *v
	return &cpy
}
