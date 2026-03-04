//go:build windows

package boxmgr

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
)

func resolvePythonCommand(ctx context.Context, cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		cmd = "python"
	}
	// If user already provided a path, keep it.
	if strings.Contains(cmd, "\\") || strings.Contains(cmd, "/") {
		return cmd, nil
	}

	// Try where.exe
	if found, err := whereFirst(ctx, cmd); err == nil && found != "" {
		return found, nil
	}

	// Fallbacks: python3, python
	for _, c := range []string{"python3", "python"} {
		if found, err := whereFirst(ctx, c); err == nil && found != "" {
			return found, nil
		}
	}

	// Try py launcher
	if _, err := exec.LookPath("py"); err == nil {
		return "py", nil
	}

	return "", errors.New("python executable not found (tried where python/python3 and py launcher)")
}

func whereFirst(ctx context.Context, name string) (string, error) {
	args := []string{name}
	cmd := exec.CommandContext(ctx, "where", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return line, nil
	}
	return "", nil
}
