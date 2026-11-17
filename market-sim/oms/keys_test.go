package oms

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scannerOf(s string) *bufio.Scanner { return bufio.NewScanner(strings.NewReader(s)) }

func TestParseAPIKeysGatewayFormat(t *testing.T) {
	k, err := ParseAPIKeys(scannerOf("# bots\n\nkey-aaaaaaaaaaaaaaaa:900001\r\nkey-bbbbbbbbbbbbbbbb:900002\n"), "f")
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	if err := k.Apply(h, 900002); err != nil || h.Get("X-API-Key") != "key-bbbbbbbbbbbbbbbb" {
		t.Fatalf("apply: %v %q", err, h.Get("X-API-Key"))
	}
	if got := k.Missing([]int64{900001, 900003}); len(got) != 1 || got[0] != 900003 {
		t.Fatalf("missing %v", got)
	}
	if u := k.Users(); len(u) != 2 || u[0] != 900001 {
		t.Fatalf("users %v", u)
	}
}

func TestParseAPIKeysRefusals(t *testing.T) {
	for name, text := range map[string]string{
		"no colon":         "key-aaaaaaaaaaaaaaaa\n",
		"short key":        "short:900001\n",
		"bad user":         "key-aaaaaaaaaaaaaaaa:0\n",
		"signed user":      "key-aaaaaaaaaaaaaaaa:+5\n",
		"key twice":        "key-aaaaaaaaaaaaaaaa:1\nkey-aaaaaaaaaaaaaaaa:2\n",
		"two keys one bot": "key-aaaaaaaaaaaaaaaa:1\nkey-bbbbbbbbbbbbbbbb:1\n",
		"empty":            "# nothing\n",
		"space in key":     "key aaaaaaaaaaaaaaaa:1\n",
	} {
		if _, err := ParseAPIKeys(scannerOf(text), "f"); err == nil {
			t.Errorf("%s: accepted %q", name, text)
		}
	}
}

func TestLoadAPIKeysFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(p, []byte("key-aaaaaaaaaaaaaaaa:7\n"), 0o600)
	k, err := LoadAPIKeys(p)
	if err != nil || len(k.Users()) != 1 {
		t.Fatalf("%v %v", k, err)
	}
	if _, err := LoadAPIKeys(p + ".missing"); err == nil {
		t.Fatal("a missing file was accepted")
	}
}
