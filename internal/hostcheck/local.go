package hostcheck

import (
	"context"
	"os/exec"
	"time"
)

// LocalProber runs the checks on the machine the scanner runs on.
type LocalProber struct {
	Timeout time.Duration
}

// Target names the scanned host.
func (p *LocalProber) Target() string { return "local" }

// Run executes the script with /bin/sh and returns its combined output.
func (p *LocalProber) Run(ctx context.Context, script string) (string, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
