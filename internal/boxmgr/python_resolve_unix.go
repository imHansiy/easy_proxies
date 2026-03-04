//go:build !windows

package boxmgr

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

func resolvePythonCommand(ctx context.Context, cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		cmd = "python3"
	}
	if strings.Contains(cmd, "/") {
		// absolute or relative path
		return cmd, nil
	}
	if path, err := exec.LookPath(cmd); err == nil {
		return path, nil
	}
	// fallback order
	for _, c := range []string{"python3", "python"} {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
	}
	return "", errors.New("python executable not found (tried python3/python)")
}
