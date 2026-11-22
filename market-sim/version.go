package main

import (
	"fmt"
	"os"
)

// sourceSha is the tools commit this binary was built from, set at link time:
//
//	go build -trimpath -buildvcs=false -ldflags "-buildid= -X main.sourceSha=<40-hex commit>" .
//
// runtime-e2e/arm64_sibling.py go-build sets it when it cross-builds the release binary; a plain `go build` leaves
// "unknown", which no release check accepts.
var sourceSha = "unknown"

// exitConfig is the exit code of a refused configuration (sysexits EX_CONFIG), the code every other service of the
// stack uses for it: a supervisor does not restart a process that exits 78, an operator fixes the setting.
const exitConfig = 78

// printVersion writes "market-sim source <commit>" on stdout: the line the release self-check reads.
func printVersion() {
	fmt.Printf("market-sim source %s\n", sourceSha)
}

// refuseConfig names the setting (its environment key, or its flag where it has none) and exits 78, before anything
// is sent to the gateway.
func refuseConfig(key, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "market-sim config: %s: %s\n", key, fmt.Sprintf(format, args...))
	fmt.Fprintln(os.Stderr, "market-sim: refusing to start: configuration problem (exit 78)")
	os.Exit(exitConfig)
}
