package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestSettingsDefaultsAndRefusals(t *testing.T) {
	_, key, _ := readSettings(envOf(nil))
	if key != "OBS_SAMPLER_CONFIG" {
		t.Fatalf("an empty environment must be refused naming OBS_SAMPLER_CONFIG, got %q", key)
	}
	s, key, _ := readSettings(envOf(map[string]string{"OBS_SAMPLER_CONFIG": "/x"}))
	if key != "" || s.SampleS != 60 || s.HTTPTimeoutMS != 2000 || s.PSQLTimeoutS != 10 || s.MaxSamples != 0 {
		t.Fatalf("defaults: %+v %q", s, key)
	}
	for _, bad := range []map[string]string{{"OBS_SAMPLE_S": "0"}, {"OBS_SAMPLE_S": "x"}, {"OBS_MAX_SAMPLES": "-1"}} {
		bad["OBS_SAMPLER_CONFIG"] = "/x"
		if _, key, _ := readSettings(envOf(bad)); key == "" {
			t.Fatalf("not refused: %v", bad)
		}
	}
}

func TestConfigRefusesWhatItCannotSample(t *testing.T) {
	good := `{"host":"h","out":"/tmp/x","supervisor":"docker","services":[{"name":"a","kind":"k","container":"c"}]}`
	if _, err := parseConfig([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"host":"h","out":"/tmp/x","supervisor":"docker","services":[{"name":"a","kind":"k"}]}`,
		`{"host":"h","out":"/tmp/x","supervisor":"init","services":[{"name":"a","kind":"k","container":"c"}]}`,
		`{"out":"/tmp/x","supervisor":"docker","services":[{"name":"a","kind":"k","container":"c"}]}`,
		`{"host":"h","out":"/tmp/x","supervisor":"docker","services":[]}`,
		`{"host":"h","out":"/tmp/x","supervisor":"docker","services":[{"name":"a","kind":"k","container":"c"}],"typo":1}`,
		`{"host":"h","out":"/tmp/x","supervisor":"docker","services":[{"name":"a","kind":"k","container":"c"},{"name":"a","kind":"k","container":"d"}]}`,
	} {
		if _, err := parseConfig([]byte(bad)); err == nil || !strings.HasPrefix(err.Error(), "OBS_SAMPLER_CONFIG") {
			t.Fatalf("not refused naming the setting: %s (%v)", bad, err)
		}
	}
}

func TestChainSealsAndDetectsTampering(t *testing.T) {
	var buf bytes.Buffer
	prev := GenesisHash
	for i := 0; i < 3; i++ {
		line, h, err := sealLine(map[string]any{"type": "sample", "seq": i, "x": "<&>"}, prev)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
		prev = h
	}
	rep := verifyChain(bytes.NewReader(buf.Bytes()))
	if rep.Error != "" || rep.Lines != 3 || rep.LastHash != prev {
		t.Fatalf("clean chain: %+v", rep)
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	tampered := bytes.Join([][]byte{lines[0], bytes.Replace(lines[1], []byte(`"seq":1`), []byte(`"seq":7`), 1), lines[2]}, []byte("\n"))
	if rep := verifyChain(bytes.NewReader(tampered)); rep.Error == "" || rep.AtLine != 2 {
		t.Fatalf("a changed line was not found: %+v", rep)
	}
	dropped := bytes.Join([][]byte{lines[0], lines[2]}, []byte("\n"))
	if rep := verifyChain(bytes.NewReader(dropped)); !strings.HasPrefix(rep.Error, "chain broken") || rep.AtLine != 2 {
		t.Fatalf("a dropped line was not found: %+v", rep)
	}
}

func TestMetricsParse(t *testing.T) {
	body := []byte("# HELP a x\n# TYPE a counter\na 3\nb{route=\"x y\",code=\"200\"} 4.5 1700000000\nc NaN\nd +Inf\nbad\nsim_x 1\n")
	m := parseMetrics(body, nil)
	if m["a"] != 3 || m[`b{route="x y",code="200"}`] != 4.5 || len(m) != 3 {
		t.Fatalf("parsed %v", m)
	}
	if k := parseMetrics(body, []string{"sim_"}); len(k) != 1 || k["sim_x"] != 1 {
		t.Fatalf("keep: %v", k)
	}
}

func TestSupervisorParsers(t *testing.T) {
	d := parseDockerState(`{"Status":"running","Running":true,"Pid":4242,"StartedAt":"2000-01-01T00:00:00Z"} 3`)
	if d.State != "running" || d.Pid != 4242 || d.Restarts == nil || *d.Restarts != 3 {
		t.Fatalf("docker: %+v", d)
	}
	s := parseSystemdShow("MainPID=17\nActiveState=active\nSubState=running\nNRestarts=2\nExecMainStartTimestamp=Sun 2026\n")
	if s.State != "active/running" || s.Pid != 17 || *s.Restarts != 2 {
		t.Fatalf("systemd: %+v", s)
	}
}

func TestProcReadsTheHostView(t *testing.T) {
	p := readProc("/proc", os.Getpid())
	if !p.Alive || p.StartTick == 0 || p.Threads < 1 || len(p.States) == 0 {
		t.Fatalf("own pid: %+v", p)
	}
	if q := readProc("/proc", 1<<30); q.Alive || q.Error == "" {
		t.Fatalf("a missing pid must read as not alive with its error: %+v", q)
	}
	if clockTicks() <= 0 {
		t.Fatal("no clock tick rate")
	}
}

// A real sampling run: one service (this test process, found through a pid file) whose /metrics answers and whose
// /health does not, a directory, /dev/shm; two samples; the file verifies and every failed read is a line with its error.
func TestRunWritesAVerifiedSampleFile(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			fmt.Fprintln(w, "work_total 7")
			return
		}
		w.WriteHeader(503)
	}))
	defer srv.Close()
	pidfile := filepath.Join(dir, "pid")
	os.WriteFile(pidfile, []byte(fmt.Sprint(os.Getpid())), 0o600)
	os.MkdirAll(filepath.Join(dir, "state"), 0o755)
	os.WriteFile(filepath.Join(dir, "state", "f"), make([]byte, 10000), 0o600)
	out := filepath.Join(dir, "samples.jsonl")
	cfg := fmt.Sprintf(`{"host":"t","out":%q,"supervisor":"pidfile","volumes":[%q],
	  "dirs":[{"name":"state","path":%q,"model":"log_dir"},{"name":"gone","path":%q,"model":"log_dir"}],
	  "services":[{"name":"svc","kind":"k","pidfile":%q,"metrics":%q,"health":%q,"ready":"http://127.0.0.1:1/ready"}]}`,
		out, dir, filepath.Join(dir, "state"), filepath.Join(dir, "missing"), pidfile, srv.URL+"/metrics", srv.URL+"/health")
	c, err := parseConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{SampleS: 1, HTTPTimeoutMS: 500, PSQLTimeoutS: 1, MaxSamples: 2}
	if code := run(c, []byte(cfg), s); code != 0 {
		t.Fatalf("run exit %d", code)
	}
	// a second run continues the same chain
	if code := run(c, []byte(cfg), Settings{SampleS: 1, HTTPTimeoutMS: 500, PSQLTimeoutS: 1, MaxSamples: 1}); code != 0 {
		t.Fatalf("second run exit %d", code)
	}
	f, _ := os.Open(out)
	rep := verifyChain(f)
	f.Close()
	if rep.Error != "" || rep.Lines != 7 { // start, 2 samples, stop, start, 1 sample, stop
		t.Fatalf("chain: %+v", rep)
	}
	raw, _ := os.ReadFile(out)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var sample map[string]any
	for sc.Scan() {
		var rec map[string]any
		json.Unmarshal(sc.Bytes(), &rec)
		if rec["type"] == "sample" {
			sample = rec
			break
		}
	}
	svc := sample["services"].(map[string]any)["svc"].(map[string]any)
	if svc["metrics"].(map[string]any)["series"].(map[string]any)["work_total"].(float64) != 7 {
		t.Fatalf("metrics: %v", svc["metrics"])
	}
	if svc["health"].(map[string]any)["code"].(float64) != 503 {
		t.Fatalf("health: %v", svc["health"])
	}
	if svc["ready"].(map[string]any)["error"] == nil {
		t.Fatalf("an unanswered read must be a line with its error: %v", svc["ready"])
	}
	if !svc["proc"].(map[string]any)["alive"].(bool) {
		t.Fatalf("proc: %v", svc["proc"])
	}
	dirs := sample["dirs"].(map[string]any)
	if dirs["state"].(map[string]any)["bytes"].(float64) < 10000 || dirs["gone"].(map[string]any)["missing"] != true {
		t.Fatalf("dirs: %v", dirs)
	}
	if code := liveness(out, envOf(nil), time.Now()); code != 1 {
		t.Fatalf("a stopped sampler must fail the liveness check, got %d", code)
	}
}

func TestLivenessReportsAnOldLastLine(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "s.jsonl")
	line, _, _ := sealLine(map[string]any{"type": "sample", "ts_ms": time.Now().Add(-10 * time.Minute).UnixMilli()}, GenesisHash)
	os.WriteFile(out, append(line, '\n'), 0o600)
	if code := liveness(out, envOf(nil), time.Now()); code != 1 {
		t.Fatalf("a 600 s old line must fail at the default OBS_MAX_GAP_S=180, got %d", code)
	}
	if code := liveness(out, envOf(map[string]string{"OBS_MAX_GAP_S": "900"}), time.Now()); code != 0 {
		t.Fatalf("a 600 s old line is live at OBS_MAX_GAP_S=900, got %d", code)
	}
}

func TestPGReadsRecordTheirErrors(t *testing.T) {
	calls := 0
	fake := func(ctx context.Context, argv []string) ([]byte, error) {
		calls++
		sql := argv[len(argv)-1]
		switch {
		case strings.Contains(sql, "pg_database_size"):
			return []byte("123\n"), nil
		case strings.Contains(sql, "pg_ls_waldir"):
			return nil, fmt.Errorf("permission denied")
		default:
			return []byte("42\n"), nil
		}
	}
	r := readPG(context.Background(), fake, &PG{Command: []string{"psql"}, Databases: []string{"a"}, WALFrom: "a",
		Queries: []PGQuery{{Name: "rows", DB: "a", SQL: "SELECT 42"}}}, time.Second)
	if r.Sizes["a"] != 123 || r.Values["rows"] != "42" || r.WAL != nil || !strings.Contains(r.Errors["wal"], "permission") || calls != 3 {
		t.Fatalf("pg: %+v", r)
	}
}
