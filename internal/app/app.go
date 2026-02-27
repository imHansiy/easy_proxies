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

		if settings, ok, err := gormStore.LoadSettings(ctx); err != nil {
			return fmt.Errorf("load settings from db: %w", err)
		} else if ok {
			cfg.ExternalIP = settings.ExternalIP
			if settings.ProbeTarget != "" {
				cfg.Management.ProbeTarget = settings.ProbeTarget
			}
			cfg.SkipCertVerify = settings.SkipCertVerify
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

	// Create and start SubscriptionManager if enabled
	var subMgr *subscription.Manager
	if cfg.SubscriptionRefresh.Enabled && len(cfg.Subscriptions) > 0 {
		subMgr = subscription.New(cfg, boxMgr)
		subMgr.Start()
		defer subMgr.Stop()

		// Wire up subscription manager to monitor server for API endpoints
		if server := boxMgr.MonitorServer(); server != nil {
			server.SetSubscriptionRefresher(subMgr)
		}

		needsSourceRefBootstrap := false
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
