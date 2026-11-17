package oms

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Credentials put one bot user's credential on a request. A credential is
// always a header, never part of a URL.
type Credentials interface {
	// Apply sets the user's credential header on h.
	Apply(h http.Header, userID int64) error
	// Mode names the scheme for logs ("api-key" or "dev").
	Mode() string
}

// minAPIKeyChars mirrors the gateway's refusal of short keys, so a bad
// keys file fails here at start instead of as 401s later.
const minAPIKeyChars = 16

// APIKeys sends X-API-Key with the key of the bot user.
type APIKeys struct {
	byUser map[int64]string
}

func (k *APIKeys) Mode() string { return "api-key" }

func (k *APIKeys) Apply(h http.Header, userID int64) error {
	key, ok := k.byUser[userID]
	if !ok {
		return fmt.Errorf("no API key for user %d in the keys file", userID)
	}
	h.Set("X-API-Key", key)
	return nil
}

// Users lists the user ids that have a key, ascending.
func (k *APIKeys) Users() []int64 {
	out := make([]int64, 0, len(k.byUser))
	for u := range k.byUser {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Missing returns the users in want that have no key.
func (k *APIKeys) Missing(want []int64) []int64 {
	var out []int64
	for _, u := range want {
		if _, ok := k.byUser[u]; !ok {
			out = append(out, u)
		}
	}
	return out
}

// LoadAPIKeys reads a keys file in the gateway's GATEWAY_API_KEYS_FILE
// format: one `key:userId` per line, blank lines and lines starting with '#'
// ignored, the userId after the last ':'. The same file can feed the gateway
// and the simulator. Each user may appear once: two keys for one bot user
// would leave the choice to the file order, so that is refused.
func LoadAPIKeys(path string) (*APIKeys, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseAPIKeys(bufio.NewScanner(f), path)
}

func ParseAPIKeys(sc *bufio.Scanner, source string) (*APIKeys, error) {
	k := &APIKeys{byUser: map[int64]string{}}
	seenKey := map[string]int{}
	var problems []string
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" || line[0] == '#' {
			continue
		}
		where := fmt.Sprintf("%s line %d", source, n)
		colon := strings.LastIndexByte(line, ':')
		if colon < 0 {
			problems = append(problems, where+": expected key:userId")
			continue
		}
		key, user := line[:colon], line[colon+1:]
		if len(key) < minAPIKeyChars || !visibleNoColon(key) {
			problems = append(problems, fmt.Sprintf("%s: the key must be %d or more visible ASCII characters without ':'", where, minAPIKeyChars))
			continue
		}
		uid, err := strconv.ParseInt(user, 10, 64)
		if err != nil || uid <= 0 || user[0] == '+' {
			problems = append(problems, where+": the userId must be a positive integer")
			continue
		}
		if prev, dup := seenKey[key]; dup {
			problems = append(problems, fmt.Sprintf("%s: the key is listed twice (first on line %d)", where, prev))
			continue
		}
		seenKey[key] = n
		if _, dup := k.byUser[uid]; dup {
			problems = append(problems, fmt.Sprintf("%s: user %d has a second key (one key per bot user)", where, uid))
			continue
		}
		k.byUser[uid] = key
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	if len(k.byUser) == 0 {
		return nil, fmt.Errorf("%s holds no key:userId entry", source)
	}
	return k, nil
}

func visibleNoColon(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == ':' {
			return false
		}
	}
	return true
}

// DevAuth sends `Authorization: Bearer dev:<userId>`. The gateway accepts it
// only with `dev` in GATEWAY_AUTH_MODES and GATEWAY_ALLOW_DEV_AUTH=1, so it
// is for a local dev gateway and is never the default.
type DevAuth struct{}

func (DevAuth) Mode() string { return "dev" }

func (DevAuth) Apply(h http.Header, userID int64) error {
	h.Set("Authorization", "Bearer dev:"+strconv.FormatInt(userID, 10))
	return nil
}
