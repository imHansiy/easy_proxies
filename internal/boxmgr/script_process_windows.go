//go:build windows

package boxmgr

import "os/exec"

func configureScriptProcess(cmd *exec.Cmd) {
	// Best-effort: Windows doesn't support Setpgid.
}

func killScriptProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
