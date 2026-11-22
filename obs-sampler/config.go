package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is the sampler's per-host configuration file (OBS_SAMPLER_CONFIG). It names what this host runs and where it
// keeps its state; the sampler reads only this host (its processes over HTTP, its /proc, its file systems) and a
// PostgreSQL server over a connection. The whole file is copied into the first line of every run, so a sample set
// describes itself and the offline verdict needs nothing else from the host.
type Config struct {
	Host string `json:"host"`
	// Out is the sample file. Lines are appended; a restarted sampler continues the hash chain of the file it finds.
	Out string `json:"out"`
	// Supervisor is how a service's process is found: systemd (Unit), docker (Container) or pidfile (Pidfile).
	Supervisor string    `json:"supervisor"`
	Services   []Service `json:"services"`
	// Volumes are file systems whose size and use are read (statfs) at every sample.
	Volumes []string `json:"volumes"`
	// Dirs are the directories whose allocated bytes are read (a walk, as du) at every sample; a dir with no path is
	// not walked (a database or the WAL, whose size comes from PostgreSQL). Model and the fields after it are for the
	// verdict only (its disk growth line); the sampler records them and does not read them.
	Dirs []Dir `json:"dirs"`
	// Shm lists the tmpfs mounts whose use and top-level entries are read; empty means /dev/shm.
	Shm []string `json:"shm"`
	PG  *PG      `json:"pg,omitempty"`
	// MetricsKeep limits the stored series to these name prefixes; empty keeps every series.
	MetricsKeep []string `json:"metrics_keep,omitempty"`
	// Verdict holds the verdict's per-set inputs (driver mode, snapshot mode and the like). The sampler copies it.
	Verdict map[string]any `json:"verdict,omitempty"`
}

// Service is one supervised process of the host.
type Service struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Unit      string `json:"unit,omitempty"`
	Container string `json:"container,omitempty"`
	Pidfile   string `json:"pidfile,omitempty"`
	Metrics   string `json:"metrics,omitempty"`
	Health    string `json:"health,omitempty"`
	Ready     string `json:"ready,omitempty"`
}

// Dir is one directory of the disk model.
type Dir struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Model   string `json:"model"`
	Service string `json:"service,omitempty"`
	Follows string `json:"follows,omitempty"`
	// DB, Rows and Size name the database and the two query values of a database model
	DB       string   `json:"db,omitempty"`
	Rows     string   `json:"rows,omitempty"`
	Size     string   `json:"size,omitempty"`
	SlopeMBH *float64 `json:"slope_mb_h,omitempty"`
}

// PG names the server, the databases whose size is read and the progress and row queries.
type PG struct {
	// Command is the psql command line without the database and query, e.g. ["psql", "-h", "127.0.0.1", "-U", "obs"]
	// or ["sudo", "-n", "-u", "postgres", "psql"]. A password, if any, comes from the environment or a pgpass file,
	// never from this file.
	Command   []string  `json:"command"`
	Databases []string  `json:"databases"`
	WALFrom   string    `json:"wal_from,omitempty"`
	Queries   []PGQuery `json:"queries,omitempty"`
}

// PGQuery is one read-only query whose single value is recorded under Name.
type PGQuery struct {
	Name string `json:"name"`
	DB   string `json:"db"`
	SQL  string `json:"sql"`
}

// Settings are the environment settings, each with a default except the configuration file.
type Settings struct {
	ConfigPath    string
	SampleS       int
	HTTPTimeoutMS int
	PSQLTimeoutS  int
	MaxSamples    int
}

var supervisors = map[string]bool{"systemd": true, "docker": true, "pidfile": true}

// readSettings returns the settings or the key of the first refused one and why.
func readSettings(env func(string) string) (Settings, string, string) {
	s := Settings{ConfigPath: env("OBS_SAMPLER_CONFIG"), SampleS: 60, HTTPTimeoutMS: 2000, PSQLTimeoutS: 10}
	if s.ConfigPath == "" {
		return s, "OBS_SAMPLER_CONFIG", "required: the sampler's configuration file for this host"
	}
	for _, kv := range []struct {
		key string
		dst *int
		min int
	}{{"OBS_SAMPLE_S", &s.SampleS, 1}, {"OBS_HTTP_TIMEOUT_MS", &s.HTTPTimeoutMS, 1}, {"OBS_PSQL_TIMEOUT_S", &s.PSQLTimeoutS, 1},
		{"OBS_MAX_SAMPLES", &s.MaxSamples, 0}} {
		v := env(kv.key)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < kv.min {
			return s, kv.key, fmt.Sprintf("must be an integer >= %d, got %q", kv.min, v)
		}
		*kv.dst = n
	}
	return s, "", ""
}

// loadConfig reads and checks the configuration file; the error names the field.
func loadConfig(path string) (*Config, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("OBS_SAMPLER_CONFIG: %v", err)
	}
	c, err := parseConfig(raw)
	return c, raw, err
}

func parseConfig(raw []byte) (*Config, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: not a configuration: %v", err)
	}
	if c.Host == "" {
		return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: host is required")
	}
	if c.Out == "" {
		return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: out (the sample file) is required")
	}
	if !supervisors[c.Supervisor] {
		return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: supervisor must be systemd, docker or pidfile, got %q", c.Supervisor)
	}
	if len(c.Services) == 0 {
		return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: services is empty")
	}
	seen := map[string]bool{}
	for i, s := range c.Services {
		if s.Name == "" || s.Kind == "" {
			return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: services[%d] needs a name and a kind", i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: service %s is listed twice", s.Name)
		}
		seen[s.Name] = true
		ref := map[string]string{"systemd": s.Unit, "docker": s.Container, "pidfile": s.Pidfile}[c.Supervisor]
		if ref == "" {
			return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: service %s names no %s", s.Name,
				map[string]string{"systemd": "unit", "docker": "container", "pidfile": "pidfile"}[c.Supervisor])
		}
	}
	for i, d := range c.Dirs {
		if d.Name == "" || d.Model == "" {
			return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: dirs[%d] needs a name and a model", i)
		}
	}
	if c.PG != nil && len(c.PG.Command) == 0 {
		return nil, fmt.Errorf("OBS_SAMPLER_CONFIG: pg.command is empty")
	}
	if len(c.Shm) == 0 {
		c.Shm = []string{"/dev/shm"}
	}
	return &c, nil
}
