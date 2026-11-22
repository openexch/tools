package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

// The running SHA-256 chain of a sample file. Every line is a JSON object whose keys include "prev", the hash of the
// line before it (64 zeros on the first line of a file), and ends with ,"hash":"<hex>"}. The hash is the SHA-256 of the
// line with that last member removed (the object then closes right after its other members). A line changed, dropped,
// reordered or inserted breaks the chain at that point.

// GenesisHash is the "prev" of a file's first line.
var GenesisHash = string(bytes.Repeat([]byte("0"), 64))

var hashTail = regexp.MustCompile(`,"hash":"([0-9a-f]{64})"\}$`)

// sealLine marshals rec (with "prev" set) and appends the hash member. json.Marshal sorts map keys, so the bytes of a
// record are a function of its content.
func sealLine(rec map[string]any, prev string) ([]byte, string, error) {
	rec["prev"] = prev
	body, err := json.Marshal(rec)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	line := append(body[:len(body)-1:len(body)-1], []byte(`,"hash":"`+h+`"}`)...)
	return line, h, nil
}

// lineHash checks one line's own hash and returns it with the line's prev.
func lineHash(line []byte) (hash, prev string, err error) {
	m := hashTail.FindSubmatchIndex(line)
	if m == nil {
		return "", "", errors.New("line does not end with its hash")
	}
	body := append(append([]byte{}, line[:m[0]]...), '}')
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	want := string(line[m[2]:m[3]])
	if got != want {
		return "", "", fmt.Errorf("hash differs: line says %s, content gives %s", want, got)
	}
	var head struct {
		Prev string `json:"prev"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return "", "", err
	}
	return got, head.Prev, nil
}

// VerifyReport is the result of a chain check over a whole file.
type VerifyReport struct {
	Lines    int    `json:"lines"`
	LastHash string `json:"last_hash"`
	Error    string `json:"error,omitempty"`
	AtLine   int    `json:"at_line,omitempty"`
}

// verifyChain walks a sample file and stops at the first broken link.
func verifyChain(r io.Reader) VerifyReport {
	rep := VerifyReport{LastHash: GenesisHash}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	for sc.Scan() {
		rep.Lines++
		h, prev, err := lineHash(sc.Bytes())
		if err != nil {
			rep.Error, rep.AtLine = err.Error(), rep.Lines
			return rep
		}
		if prev != rep.LastHash {
			rep.Error, rep.AtLine = fmt.Sprintf("chain broken: prev %s, the line before hashes to %s", prev, rep.LastHash), rep.Lines
			return rep
		}
		rep.LastHash = h
	}
	if err := sc.Err(); err != nil {
		rep.Error = err.Error()
	}
	return rep
}

// lastLine returns the last complete line of a file (nil for an empty or missing file).
func lastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}
	var chunk int64 = 64 << 10
	for {
		if chunk > size {
			chunk = size
		}
		buf := make([]byte, chunk)
		if _, err := f.ReadAt(buf, size-chunk); err != nil && err != io.EOF {
			return nil, err
		}
		trimmed := bytes.TrimRight(buf, "\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
		if chunk == size {
			return trimmed, nil
		}
		chunk *= 4
	}
}
