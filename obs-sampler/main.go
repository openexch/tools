// obs-sampler: the read-only observation sampler of an Open Exchange host. Once per host, every OBS_SAMPLE_S, it reads
// each local service's /metrics, /health and /ready over HTTP, the supervisor's state and pid, the pid's CPU time and
// thread states from /proc, the use of each volume, the bytes of each configured directory, /dev/shm and its entries,
// and PostgreSQL sizes and progress values over a connection. It appends one JSON line per sample with a running
// SHA-256 chain. It writes nothing else and sends nothing anywhere. See README.md.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// sourceSha is the tools commit this binary was built from, set at link time:
//
//	go build -trimpath -buildvcs=false -ldflags "-buildid= -X main.sourceSha=<40-hex commit>" .
var sourceSha = "unknown"

// exitConfig is the exit code of a refused configuration (sysexits EX_CONFIG): a supervisor does not restart a process
// that exits 78; an operator fixes the setting.
const exitConfig = 78

func refuseConfig(key, why string) {
	fmt.Fprintf(os.Stderr, "obs-sampler config: %s: %s\n", key, why)
	fmt.Fprintln(os.Stderr, "obs-sampler: refusing to start: configuration problem (exit 78)")
	os.Exit(exitConfig)
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: obs-sampler                 sample this host (settings from the environment)
       obs-sampler liveness <file>   size of the sample file and the age of its last line
       obs-sampler verify <file>     check the hash chain of a sample file
       obs-sampler --version
Environment: OBS_SAMPLER_CONFIG (required), OBS_SAMPLE_S (60), OBS_HTTP_TIMEOUT_MS (2000), OBS_PSQL_TIMEOUT_S (10),
OBS_MAX_SAMPLES (0 = until stopped); liveness: OBS_MAX_GAP_S (180).
`)
}

func main() {
	version := flag.Bool("version", false, "print the source commit and exit")
	flag.Usage = usage
	flag.Parse()
	if *version {
		fmt.Printf("obs-sampler source %s\n", sourceSha)
		return
	}
	args := flag.Args()
	if len(args) > 0 {
		switch {
		case args[0] == "liveness" && len(args) == 2:
			os.Exit(liveness(args[1], os.Getenv, time.Now()))
		case args[0] == "verify" && len(args) == 2:
			os.Exit(verify(args[1]))
		default:
			usage()
			os.Exit(64)
		}
	}
	settings, key, why := readSettings(os.Getenv)
	if key != "" {
		refuseConfig(key, why)
	}
	cfg, raw, err := loadConfig(settings.ConfigPath)
	if err != nil {
		refuseConfig("OBS_SAMPLER_CONFIG", err.Error())
	}
	os.Exit(run(cfg, raw, settings))
}

func run(cfg *Config, raw []byte, s Settings) int {
	prev := GenesisHash
	last, err := lastLine(cfg.Out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "obs-sampler: cannot read the sample file %s: %v\n", cfg.Out, err)
		return 1
	}
	if last != nil {
		h, _, err := lineHash(last)
		if err != nil {
			fmt.Fprintf(os.Stderr, "obs-sampler: the last line of %s does not verify (%v); refusing to extend a broken chain\n", cfg.Out, err)
			return 1
		}
		prev = h
	}
	f, err := os.OpenFile(cfg.Out, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "obs-sampler: cannot open the sample file: %v\n", err)
		return 1
	}
	defer f.Close()
	sum := sha256.Sum256(raw)
	var cfgDoc any
	_ = json.Unmarshal(raw, &cfgDoc)
	c := &Collector{Cfg: cfg, Client: &http.Client{Timeout: time.Duration(s.HTTPTimeoutMS) * time.Millisecond}, Run: execRun,
		ProcRoot: "/proc", PGTime: time.Duration(s.PSQLTimeoutS) * time.Second}
	lines := 0
	write := func(rec map[string]any) error {
		rec["host"] = cfg.Host
		rec["ts_ms"] = time.Now().UnixMilli()
		line, h, err := sealLine(rec, prev)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
		prev = h
		lines++
		return nil
	}
	start := map[string]any{"type": "start", "version": sourceSha, "resumed": last != nil, "config": cfgDoc,
		"config_sha256": hex.EncodeToString(sum[:]), "clk_tck": clockTicks(), "pid": os.Getpid(),
		"settings": map[string]int{"OBS_SAMPLE_S": s.SampleS, "OBS_HTTP_TIMEOUT_MS": s.HTTPTimeoutMS,
			"OBS_PSQL_TIMEOUT_S": s.PSQLTimeoutS, "OBS_MAX_SAMPLES": s.MaxSamples}}
	if err := write(start); err != nil {
		fmt.Fprintf(os.Stderr, "obs-sampler: write: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	period := time.Duration(s.SampleS) * time.Second
	next := time.Now()
	for n := 1; ; n++ {
		t0 := time.Now()
		rec := c.sample(context.Background())
		rec["type"] = "sample"
		rec["seq"] = n
		rec["took_ms"] = time.Since(t0).Milliseconds()
		if st, err := f.Stat(); err == nil {
			rec["self"] = map[string]int64{"file_bytes": st.Size(), "lines": int64(lines)}
		}
		if err := write(rec); err != nil {
			fmt.Fprintf(os.Stderr, "obs-sampler: write: %v\n", err)
			return 1
		}
		if s.MaxSamples > 0 && n >= s.MaxSamples {
			break
		}
		next = next.Add(period)
		if d := time.Until(next); d > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		} else {
			next = time.Now()
		}
		if ctx.Err() != nil {
			break
		}
	}
	reason := "max samples"
	if ctx.Err() != nil {
		reason = "signal"
	}
	if err := write(map[string]any{"type": "stop", "reason": reason}); err != nil {
		return 1
	}
	return 0
}

// liveness prints the size of the sample file and the age of its last line; a last line older than OBS_MAX_GAP_S
// (default 180) is reported and exits 1. It reads the file only.
func liveness(path string, env func(string) string, now time.Time) int {
	gap := 180
	if v := env("OBS_MAX_GAP_S"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &gap); err != nil || gap < 1 {
			fmt.Fprintf(os.Stderr, "obs-sampler: OBS_MAX_GAP_S must be a positive integer, got %q\n", v)
			return 64
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		fmt.Printf("LIVENESS FAIL no sample file: %v\n", err)
		return 1
	}
	last, err := lastLine(path)
	if err != nil || last == nil {
		fmt.Printf("LIVENESS FAIL sample file %s has no line (size %d)\n", path, st.Size())
		return 1
	}
	var rec struct {
		TS   int64  `json:"ts_ms"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(last, &rec); err != nil {
		fmt.Printf("LIVENESS FAIL last line unreadable: %v\n", err)
		return 1
	}
	age := now.Sub(time.UnixMilli(rec.TS)).Seconds()
	fmt.Printf("sample file %s size %d bytes, last line %s age %.0f s\n", path, st.Size(), rec.Type, age)
	if age > float64(gap) || rec.Type == "stop" {
		fmt.Printf("LIVENESS FAIL last line older than OBS_MAX_GAP_S=%d s or the sampler stopped\n", gap)
		return 1
	}
	fmt.Println("LIVENESS OK")
	return 0
}

func verify(path string) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("VERIFY FAIL %v\n", err)
		return 1
	}
	defer f.Close()
	rep := verifyChain(f)
	out, _ := json.Marshal(rep)
	fmt.Println(string(out))
	if rep.Error != "" {
		fmt.Printf("VERIFY FAIL line %d: %s\n", rep.AtLine, rep.Error)
		return 1
	}
	fmt.Printf("VERIFY OK %d lines\n", rep.Lines)
	return 0
}
