package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"easy_proxies/internal/app"
	"easy_proxies/internal/config"
)

func main() {
	if err := loadDotEnv(".env"); err != nil {
		log.Fatalf("load .env: %v", err)
	}

	var configPath string
	flag.StringVar(&configPath, "config", "", "optional path to config file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "proxy pool exited with error: %v\n", err)
		os.Exit(1)
	}
}

func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			return fmt.Errorf("invalid .env line %d", idx+1)
		}
		key := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])
		if len(value) >= 2 {
			if (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"') {
				value = value[1 : len(value)-1]
			}
		}
		if key == "" {
			return fmt.Errorf("invalid .env line %d: empty key", idx+1)
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set .env %q: %w", key, err)
		}
	}

	return nil
}
