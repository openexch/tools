package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// errText keeps an error short enough for a sample line.
func errText(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// ---------------------------------------------------------------- supervisor

// SupState is what the supervisor reports for one service.
type SupState struct {
	State     string `json:"state"`
	Pid       int    `json:"pid"`
	StartedAt string `json:"started_at,omitempty"`
	Restarts  *int64 `json:"restarts,omitempty"`
	Error     string `json:"error,omitempty"`
}

type runner func(ctx context.Context, argv []string) ([]byte, error)

func execRun(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", argv[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// supervise reads every service's supervisor state in one pass.
func supervise(ctx context.Context, c *Config, run runner) map[string]SupState {
	out := map[string]SupState{}
	switch c.Supervisor {
	case "docker":
		// one inspect per container: a missing container must not hide the others
		for _, s := range c.Services {
			raw, err := run(ctx, []string{"docker", "inspect", "--format", "{{json .State}} {{.RestartCount}}", s.Container})
			if err != nil {
				out[s.Name] = SupState{State: "unknown", Error: errText(err)}
				continue
			}
			out[s.Name] = parseDockerState(strings.TrimSpace(string(raw)))
		}
	case "systemd":
		for _, s := range c.Services {
			raw, err := run(ctx, []string{"systemctl", "show", s.Unit, "--property=MainPID,ActiveState,SubState,NRestarts,ExecMainStartTimestamp"})
			if err != nil {
				out[s.Name] = SupState{State: "unknown", Error: errText(err)}
				continue
			}
			out[s.Name] = parseSystemdShow(string(raw))
		}
	case "pidfile":
		for _, s := range c.Services {
			raw, err := os.ReadFile(s.Pidfile)
			if err != nil {
				out[s.Name] = SupState{State: "stopped", Error: errText(err)}
				continue
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				out[s.Name] = SupState{State: "unknown", Error: "pidfile holds no pid"}
				continue
			}
			state := "running"
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
				state = "stopped"
			}
			out[s.Name] = SupState{State: state, Pid: pid}
		}
	}
	return out
}

func parseDockerState(s string) SupState {
	cut := strings.LastIndex(s, " ")
	if cut < 0 {
		return SupState{State: "unknown", Error: "unreadable docker state"}
	}
	var st struct {
		Status    string
		Pid       int
		StartedAt string
	}
	if err := json.Unmarshal([]byte(s[:cut]), &st); err != nil {
		return SupState{State: "unknown", Error: errText(err)}
	}
	r := SupState{State: st.Status, Pid: st.Pid, StartedAt: st.StartedAt}
	if n, err := strconv.ParseInt(s[cut+1:], 10, 64); err == nil {
		r.Restarts = &n
	}
	return r
}

func parseSystemdShow(s string) SupState {
	kv := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[k] = v
		}
	}
	r := SupState{State: kv["ActiveState"], StartedAt: kv["ExecMainStartTimestamp"]}
	if kv["SubState"] != "" {
		r.State = kv["ActiveState"] + "/" + kv["SubState"]
	}
	r.Pid, _ = strconv.Atoi(kv["MainPID"])
	if n, err := strconv.ParseInt(kv["NRestarts"], 10, 64); err == nil {
		r.Restarts = &n
	}
	return r
}

// ---------------------------------------------------------------- /proc

// ProcState is the host's view of one pid: alive, its start time (clock ticks since boot, stable for the pid's life),
// CPU time in clock ticks and the state of each thread.
type ProcState struct {
	Alive     bool           `json:"alive"`
	StartTick uint64         `json:"start_ticks,omitempty"`
	CPUTicks  uint64         `json:"cpu_ticks,omitempty"`
	Threads   int            `json:"threads,omitempty"`
	States    map[string]int `json:"thread_states,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// statFields returns the fields of a /proc stat line after the command name (field 3 onward).
func statFields(line string) ([]string, error) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return nil, errors.New("no command name")
	}
	f := strings.Fields(line[i+1:])
	if len(f) < 20 {
		return nil, errors.New("short stat line")
	}
	return f, nil
}

func readProc(root string, pid int) ProcState {
	if pid <= 0 {
		return ProcState{}
	}
	raw, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", root, pid))
	if err != nil {
		return ProcState{Error: errText(err)}
	}
	f, err := statFields(string(raw))
	if err != nil {
		return ProcState{Error: err.Error()}
	}
	// f[0] is field 3 (state): field n is f[n-3]
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	threads, _ := strconv.Atoi(f[17])
	start, _ := strconv.ParseUint(f[19], 10, 64)
	p := ProcState{Alive: f[0] != "Z" && f[0] != "X", StartTick: start, CPUTicks: ut + st, Threads: threads, States: map[string]int{}}
	tasks, _ := os.ReadDir(fmt.Sprintf("%s/%d/task", root, pid))
	for _, t := range tasks {
		raw, err := os.ReadFile(fmt.Sprintf("%s/%d/task/%s/stat", root, pid, t.Name()))
		if err != nil {
			continue
		}
		if tf, err := statFields(string(raw)); err == nil {
			p.States[tf[0]]++
		}
	}
	return p
}

// clockTicks reads AT_CLKTCK from the auxiliary vector (the unit of the CPU and start times); 100 when unreadable.
func clockTicks() int {
	raw, err := os.ReadFile("/proc/self/auxv")
	if err == nil {
		for i := 0; i+16 <= len(raw); i += 16 {
			key := binary.LittleEndian.Uint64(raw[i:])
			if key == 17 {
				return int(binary.LittleEndian.Uint64(raw[i+8:]))
			}
			if key == 0 {
				break
			}
		}
	}
	return 100
}

// ---------------------------------------------------------------- HTTP

// HTTPRead is one HTTP read. A failed read is a line with its error, never left out: the verdict must tell "the process
// did not answer" from "no sample was taken".
type HTTPRead struct {
	Code   int                `json:"code"`
	Error  string             `json:"error,omitempty"`
	Body   string             `json:"body,omitempty"`
	Series map[string]float64 `json:"series,omitempty"`
	MS     int64              `json:"ms"`
}

func httpGet(client *http.Client, url string, limit int64) (int, []byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, body, err
}

func readHTTP(client *http.Client, url string, metrics bool, keep []string) *HTTPRead {
	if url == "" {
		return nil
	}
	t0 := time.Now()
	code, body, err := httpGet(client, url, 16<<20)
	r := &HTTPRead{Code: code, MS: time.Since(t0).Milliseconds()}
	if err != nil {
		r.Error = errText(err)
		return r
	}
	if metrics {
		r.Series = parseMetrics(body, keep)
		return r
	}
	if len(body) > 512 {
		body = body[:512]
	}
	r.Body = string(body)
	return r
}

// parseMetrics reads Prometheus text: "name{labels} value [ts]" lines; comments, non-finite and unparsable values are
// left out. keep limits the names to these prefixes (empty keeps all).
func parseMetrics(body []byte, keep []string) map[string]float64 {
	out := map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		var key, rest string
		if i := strings.IndexByte(line, '{'); i >= 0 && i < strings.IndexAny(line+" ", " \t") {
			j := strings.LastIndexByte(line, '}')
			if j < i {
				continue
			}
			key, rest = line[:j+1], line[j+1:]
		} else {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			key, rest = f[0], strings.Join(f[1:], " ")
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		if len(keep) > 0 {
			ok := false
			for _, p := range keep {
				if strings.HasPrefix(key, p) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out[key] = v
	}
	return out
}

// ---------------------------------------------------------------- disk

// VolumeUse is one statfs read, in bytes.
type VolumeUse struct {
	Total int64  `json:"total,omitempty"`
	Used  int64  `json:"used,omitempty"`
	Avail int64  `json:"avail,omitempty"`
	Error string `json:"error,omitempty"`
}

func statVolume(path string) VolumeUse {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return VolumeUse{Error: errText(err)}
	}
	bs := int64(st.Bsize)
	return VolumeUse{Total: int64(st.Blocks) * bs, Used: int64(st.Blocks-st.Bfree) * bs, Avail: int64(st.Bavail) * bs}
}

// DirUse is one walk of a directory: allocated bytes (as du), apparent bytes, the file count and the errors met.
type DirUse struct {
	Bytes    int64  `json:"bytes"`
	Apparent int64  `json:"apparent"`
	Files    int64  `json:"files"`
	Missing  bool   `json:"missing,omitempty"`
	Errors   int    `json:"errors,omitempty"`
	Error    string `json:"error,omitempty"`
}

func duDir(path string) DirUse {
	var u DirUse
	if _, err := os.Lstat(path); err != nil {
		u.Missing = errors.Is(err, fs.ErrNotExist)
		u.Error = errText(err)
		return u
	}
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			u.Errors++
			if u.Error == "" {
				u.Error = errText(err)
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			u.Errors++
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			u.Bytes += st.Blocks * 512
		}
		if info.Mode().IsRegular() {
			u.Apparent += info.Size()
			u.Files++
		}
		return nil
	})
	return u
}

// ShmUse is the tmpfs use and the bytes of each top-level entry.
type ShmUse struct {
	VolumeUse
	Entries map[string]int64 `json:"entries"`
}

func readShm(path string) ShmUse {
	s := ShmUse{VolumeUse: statVolume(path), Entries: map[string]int64{}}
	ents, err := os.ReadDir(path)
	if err != nil {
		s.Error = errText(err)
		return s
	}
	for _, e := range ents {
		s.Entries[e.Name()] = duDir(filepath.Join(path, e.Name())).Bytes
	}
	return s
}

// ---------------------------------------------------------------- PostgreSQL

// PGRead is the server reads of one sample: database sizes, WAL size and the named query values.
type PGRead struct {
	Sizes  map[string]int64  `json:"sizes"`
	WAL    *int64            `json:"wal_bytes,omitempty"`
	Values map[string]string `json:"values"`
	Errors map[string]string `json:"errors,omitempty"`
}

func psql(ctx context.Context, run runner, pg *PG, db, sql string) (string, error) {
	argv := append(append([]string{}, pg.Command...), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql)
	out, err := run(ctx, argv)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func readPG(parent context.Context, run runner, pg *PG, timeout time.Duration) *PGRead {
	if pg == nil {
		return nil
	}
	r := &PGRead{Sizes: map[string]int64{}, Values: map[string]string{}, Errors: map[string]string{}}
	one := func(name, db, sql string) (string, bool) {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		v, err := psql(ctx, run, pg, db, sql)
		if err != nil {
			r.Errors[name] = errText(err)
			return "", false
		}
		return v, true
	}
	for _, db := range pg.Databases {
		if v, ok := one("size:"+db, db, "SELECT pg_database_size(current_database())"); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				r.Sizes[db] = n
			}
		}
	}
	if pg.WALFrom != "" {
		if v, ok := one("wal", pg.WALFrom, "SELECT COALESCE(sum(size), 0) FROM pg_ls_waldir()"); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				r.WAL = &n
			}
		}
	}
	for _, q := range pg.Queries {
		if v, ok := one(q.Name, q.DB, q.SQL); ok {
			r.Values[q.Name] = v
		}
	}
	if len(r.Errors) == 0 {
		r.Errors = nil
	}
	return r
}

// ---------------------------------------------------------------- one sample

// ServiceSample is everything read about one service at one sample.
type ServiceSample struct {
	Kind       string    `json:"kind"`
	Supervisor SupState  `json:"supervisor"`
	Proc       ProcState `json:"proc"`
	Metrics    *HTTPRead `json:"metrics,omitempty"`
	Health     *HTTPRead `json:"health,omitempty"`
	Ready      *HTTPRead `json:"ready,omitempty"`
}

// Collector holds what a sample needs.
type Collector struct {
	Cfg      *Config
	Client   *http.Client
	Run      runner
	ProcRoot string
	PGTime   time.Duration
}

func (c *Collector) sample(ctx context.Context) map[string]any {
	// a sample is always completed: the supervisor reads have their own bound, not the run's stop signal
	supCtx, cancel := context.WithTimeout(ctx, c.PGTime)
	defer cancel()
	sup := supervise(supCtx, c.Cfg, c.Run)
	services := map[string]ServiceSample{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range c.Cfg.Services {
		wg.Add(1)
		go func(s Service) {
			defer wg.Done()
			st := sup[s.Name]
			ss := ServiceSample{Kind: s.Kind, Supervisor: st, Proc: readProc(c.ProcRoot, st.Pid)}
			ss.Metrics = readHTTP(c.Client, s.Metrics, true, c.Cfg.MetricsKeep)
			ss.Health = readHTTP(c.Client, s.Health, false, nil)
			ss.Ready = readHTTP(c.Client, s.Ready, false, nil)
			mu.Lock()
			services[s.Name] = ss
			mu.Unlock()
		}(s)
	}
	volumes := map[string]VolumeUse{}
	for _, v := range c.Cfg.Volumes {
		volumes[v] = statVolume(v)
	}
	dirs := map[string]DirUse{}
	for _, d := range c.Cfg.Dirs {
		if d.Path != "" {
			dirs[d.Name] = duDir(d.Path)
		}
	}
	shm := map[string]ShmUse{}
	for _, p := range c.Cfg.Shm {
		shm[p] = readShm(p)
	}
	pg := readPG(ctx, c.Run, c.Cfg.PG, c.PGTime)
	wg.Wait()
	rec := map[string]any{"services": services, "volumes": volumes, "dirs": dirs, "shm": shm}
	if pg != nil {
		rec["pg"] = pg
	}
	return rec
}
