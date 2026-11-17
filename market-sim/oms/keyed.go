package oms

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// NewIdempotencyKey returns a fresh random UUID (version 4). One logical
// request gets one key; every retry of that request reuses it.
func NewIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// KeyedKind names a keyed command: the ones the core remembers under the
// request key and counts toward a user's request cap.
type KeyedKind string

const (
	KeyedCreate   KeyedKind = "create"
	KeyedAmend    KeyedKind = "amend"
	KeyedCancel   KeyedKind = "cancel"
	KeyedDeposit  KeyedKind = "deposit"
	KeyedWithdraw KeyedKind = "withdraw"
)

// KeyedOutcome classifies the final answer of a keyed request.
type KeyedOutcome int

const (
	// OutcomeStored: the core holds a decision under the key (2xx, or a
	// reject with keyFinal true). It occupies a request-table entry.
	OutcomeStored KeyedOutcome = iota
	// OutcomeNotStored: refused before or without storing (keyFinal false,
	// gateway validation, auth, a bucket).
	OutcomeNotStored
	// OutcomeUnknown: retries ran out with the outcome unknown; it may hold
	// an entry.
	OutcomeUnknown
)

// KeyedCounter records, per user, the keyed requests the simulator sends:
// one per fresh Idempotency-Key (a retry with the same key is the same
// request-table entry and is counted apart as a retry). Two views over the
// window: the sliding count (the most keys one user had in flight inside any
// span of one window, which is what a per-user cap over one TTL refuses on)
// and tumbling windows (per-window per-user counts for a stats line).
type KeyedCounter struct {
	mu     sync.Mutex
	window time.Duration
	keep   int
	now    func() time.Time

	since       time.Time
	windowStart time.Time
	users       map[int64]*keyedUser
	closed      []KeyedWindow
}

type keyedUser struct {
	sent, retries, stored, notStored, unknown int64
	byKind                                    map[KeyedKind]int64

	recent       []time.Time // sent inside the sliding window
	peak         int
	peakAt       time.Time
	storedRecent []time.Time
	storedPeak   int

	cur int // sent in the current tumbling window
}

// KeyedWindow is one closed tumbling window.
type KeyedWindow struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Users      int       `json:"users"` // users that sent at least one keyed request
	Total      int64     `json:"total"`
	PerUserP50 int       `json:"perUserP50"`
	PerUserP99 int       `json:"perUserP99"`
	PerUserMax int       `json:"perUserMax"`
	MaxUser    int64     `json:"maxUser"`
}

// NewKeyedCounter counts over window (must be positive) and keeps the last
// keep closed windows (keep <= 0 keeps 64).
func NewKeyedCounter(window time.Duration, keep int) *KeyedCounter {
	return newKeyedCounter(window, keep, time.Now)
}

func newKeyedCounter(window time.Duration, keep int, now func() time.Time) *KeyedCounter {
	if window <= 0 {
		panic("KeyedCounter: window must be positive")
	}
	if keep <= 0 {
		keep = 64
	}
	t := now()
	return &KeyedCounter{window: window, keep: keep, now: now, since: t, windowStart: t, users: map[int64]*keyedUser{}}
}

func (k *KeyedCounter) Window() time.Duration { return k.window }

func (k *KeyedCounter) user(id int64) *keyedUser {
	u := k.users[id]
	if u == nil {
		u = &keyedUser{byKind: map[KeyedKind]int64{}}
		k.users[id] = u
	}
	return u
}

func slide(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return ts
	}
	return append(ts[:0], ts[i:]...)
}

// Sent records a fresh key's first send.
func (k *KeyedCounter) Sent(userID int64, kind KeyedKind) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	t := k.now()
	k.roll(t)
	u := k.user(userID)
	u.sent++
	u.byKind[kind]++
	u.cur++
	u.recent = append(slide(u.recent, t.Add(-k.window)), t)
	if len(u.recent) > u.peak {
		u.peak = len(u.recent)
		u.peakAt = t
	}
}

// Retry records a resend with an existing key.
func (k *KeyedCounter) Retry(userID int64) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.user(userID).retries++
}

// Done records the final classification of a keyed request.
func (k *KeyedCounter) Done(userID int64, o KeyedOutcome) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	t := k.now()
	u := k.user(userID)
	switch o {
	case OutcomeStored:
		u.stored++
		u.storedRecent = append(slide(u.storedRecent, t.Add(-k.window)), t)
		if len(u.storedRecent) > u.storedPeak {
			u.storedPeak = len(u.storedRecent)
		}
	case OutcomeNotStored:
		u.notStored++
	default:
		u.unknown++
	}
}

// roll closes every tumbling window that ended before t. Caller holds mu.
func (k *KeyedCounter) roll(t time.Time) {
	for !t.Before(k.windowStart.Add(k.window)) {
		end := k.windowStart.Add(k.window)
		var counts []int
		w := KeyedWindow{Start: k.windowStart, End: end}
		for id, u := range k.users {
			if u.cur == 0 {
				continue
			}
			counts = append(counts, u.cur)
			w.Total += int64(u.cur)
			if u.cur > w.PerUserMax || (u.cur == w.PerUserMax && id < w.MaxUser) {
				w.PerUserMax, w.MaxUser = u.cur, id
			}
			u.cur = 0
		}
		w.Users = len(counts)
		w.PerUserP50 = percentile(counts, 50)
		w.PerUserP99 = percentile(counts, 99)
		k.closed = append(k.closed, w)
		if len(k.closed) > k.keep {
			k.closed = k.closed[len(k.closed)-k.keep:]
		}
		k.windowStart = end
	}
}

// percentile is nearest-rank over the users that sent (0 for none).
func percentile(v []int, p int) int {
	if len(v) == 0 {
		return 0
	}
	s := append([]int(nil), v...)
	sort.Ints(s)
	rank := (p*len(s) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	return s[rank-1]
}

// KeyedUserStats is one user's row in a snapshot.
type KeyedUserStats struct {
	Sent             int64               `json:"sent"`
	Retries          int64               `json:"retries"`
	Stored           int64               `json:"stored"`
	NotStored        int64               `json:"notStored"`
	Unknown          int64               `json:"unknown"`
	ByKind           map[KeyedKind]int64 `json:"byKind"`
	InWindow         int                 `json:"inWindow"`
	PeakInWindow     int                 `json:"peakInWindow"`
	PeakAt           *time.Time          `json:"peakAt"`
	StoredPeakWindow int                 `json:"storedPeakInWindow"`
}

// KeyedSnapshot is the JSON counter file.
type KeyedSnapshot struct {
	WindowMs     int64                     `json:"windowMs"`
	Since        time.Time                 `json:"since"`
	At           time.Time                 `json:"at"`
	PeakInWindow int                       `json:"peakInWindow"` // max over users of their sliding peak
	PeakUser     int64                     `json:"peakUser"`
	StoredPeak   int                       `json:"storedPeakInWindow"`
	Users        map[string]KeyedUserStats `json:"users"`
	Windows      []KeyedWindow             `json:"windows"`
}

func (k *KeyedCounter) Snapshot() KeyedSnapshot {
	k.mu.Lock()
	defer k.mu.Unlock()
	t := k.now()
	k.roll(t)
	s := KeyedSnapshot{WindowMs: k.window.Milliseconds(), Since: k.since, At: t,
		Users: map[string]KeyedUserStats{}, Windows: append([]KeyedWindow(nil), k.closed...)}
	ids := make([]int64, 0, len(k.users))
	for id := range k.users {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		u := k.users[id]
		u.recent = slide(u.recent, t.Add(-k.window))
		row := KeyedUserStats{Sent: u.sent, Retries: u.retries, Stored: u.stored, NotStored: u.notStored,
			Unknown: u.unknown, ByKind: map[KeyedKind]int64{}, InWindow: len(u.recent),
			PeakInWindow: u.peak, StoredPeakWindow: u.storedPeak}
		for kk, v := range u.byKind {
			row.ByKind[kk] = v
		}
		if !u.peakAt.IsZero() {
			at := u.peakAt
			row.PeakAt = &at
		}
		s.Users[strconv.FormatInt(id, 10)] = row
		if u.peak > s.PeakInWindow {
			s.PeakInWindow, s.PeakUser = u.peak, id
		}
		if u.storedPeak > s.StoredPeak {
			s.StoredPeak = u.storedPeak
		}
	}
	return s
}

// Line is the one-line stats summary for the log.
func (s KeyedSnapshot) Line() string {
	var sent, retries int64
	for _, u := range s.Users {
		sent += u.Sent
		retries += u.Retries
	}
	line := fmt.Sprintf("keyed window=%dms users=%d sent=%d retries=%d peak_per_user=%d (user %d) stored_peak_per_user=%d",
		s.WindowMs, len(s.Users), sent, retries, s.PeakInWindow, s.PeakUser, s.StoredPeak)
	if n := len(s.Windows); n > 0 {
		w := s.Windows[n-1]
		line += fmt.Sprintf(" | last window users=%d total=%d p50=%d p99=%d max=%d (user %d)",
			w.Users, w.Total, w.PerUserP50, w.PerUserP99, w.PerUserMax, w.MaxUser)
	}
	return line
}

// WriteFile writes the snapshot as JSON, atomically (temp file + rename).
func (s KeyedSnapshot) WriteFile(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyed-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
