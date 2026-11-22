package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runMain runs main() in a child copy of the test binary with exactly env and args, and returns its output and exit code.
func runMain(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainChild$")
	cmd.Env = append([]string{"MARKET_SIM_TEST_CHILD=1", "MARKET_SIM_TEST_ARGS=" + strings.Join(args, "\x1f")}, env...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode()
	}
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	return string(out), 0
}

// TestMainChild is the child side of runMain; it does nothing in a normal run.
func TestMainChild(t *testing.T) {
	if os.Getenv("MARKET_SIM_TEST_CHILD") != "1" {
		return
	}
	os.Args = []string{"market-sim"}
	if a := os.Getenv("MARKET_SIM_TEST_ARGS"); a != "" {
		os.Args = append(os.Args, strings.Split(a, "\x1f")...)
	}
	main()
	os.Exit(0)
}

func TestVersionPrintsTheSourceCommit(t *testing.T) {
	out, code := runMain(t, nil, "-version")
	if code != 0 || !strings.Contains(out, "market-sim source unknown\n") {
		t.Fatalf("-version: exit %d, output %q", code, out)
	}
	out, code = runMain(t, nil, "--version")
	if code != 0 || !strings.Contains(out, "market-sim source unknown\n") {
		t.Fatalf("--version: exit %d, output %q", code, out)
	}
}

// An empty environment is a configuration the simulator cannot run with: refused with 78, naming the key, before
// anything is sent to a gateway.
func TestEmptyEnvironmentRefusesWith78NamingTheKey(t *testing.T) {
	out, code := runMain(t, nil)
	if code != exitConfig {
		t.Fatalf("exit %d, want %d; output %q", code, exitConfig, out)
	}
	if !strings.Contains(out, "market-sim config: SIM_STREAM_URL: ") {
		t.Fatalf("the refusal does not name SIM_STREAM_URL: %q", out)
	}
}

func TestBadFaucetCapRefusesWith78(t *testing.T) {
	out, code := runMain(t, nil, "-user-stream=false", "-faucet-max=nonsense")
	if code != exitConfig || !strings.Contains(out, "market-sim config: SIM_FAUCET_MAX: ") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}
