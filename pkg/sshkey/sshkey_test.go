package sshkey

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestPublicKeyRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	line := k.Public("router-01").String()
	if !strings.HasPrefix(line, "ssh-ed25519 AAAA") || !strings.HasSuffix(line, " router-01") {
		t.Fatalf("unexpected line %q", line)
	}
	pk, err := ParsePublicKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Key.Equal(k.Key.Public()) {
		t.Fatal("public key mismatch")
	}
	if pk.Comment != "router-01" {
		t.Fatalf("comment = %q", pk.Comment)
	}
}

func TestParsePublicKeyRejectsOtherTypes(t *testing.T) {
	// ecdsa-sha2-nistp256 key
	line := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= test"
	if _, err := ParsePublicKey(line); err == nil {
		t.Fatal("expected error for non-ed25519 key")
	}
}

func TestX25519Conversion(t *testing.T) {
	for range 16 {
		k, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.Public("").X25519()
		if err != nil {
			t.Fatal(err)
		}
		derived, err := curve25519.X25519(k.X25519(), curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, derived) {
			t.Fatalf("x25519 public mismatch: %x != %x", pub, derived)
		}
	}
}

func TestPrivateKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "key")
	k, created, err := LoadOrGenerate(path, "node-a")
	if err != nil || !created {
		t.Fatalf("LoadOrGenerate: %v created=%v", err, created)
	}
	k2, created, err := LoadOrGenerate(path, "node-a")
	if err != nil || created {
		t.Fatalf("second LoadOrGenerate: %v created=%v", err, created)
	}
	if !k.Key.Equal(k2.Key) {
		t.Fatal("loaded key differs")
	}
}

func TestFingerprintMatchesSSHKeygen(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}
	k, _ := Generate()
	pk := k.Public("fp-test")
	path := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(path, []byte(pk.String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(sshKeygen, "-lf", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), pk.Fingerprint()) {
		t.Fatalf("ssh-keygen output %q does not contain %q", out, pk.Fingerprint())
	}
}
