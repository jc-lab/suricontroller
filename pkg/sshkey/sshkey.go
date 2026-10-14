// Package sshkey handles Ed25519 keys in OpenSSH formats.
//
// Public keys use the authorized_keys line format
// ("ssh-ed25519 AAAA... comment"); private keys use the OpenSSH private key
// PEM format. The same keys are used for Noise DH by converting them to
// X25519, the way age's ssh-ed25519 recipients do.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

// PublicKey is an Ed25519 public key with its authorized_keys comment.
type PublicKey struct {
	Key     ed25519.PublicKey
	Comment string
}

// PrivateKey is an Ed25519 private key.
type PrivateKey struct {
	Key ed25519.PrivateKey
}

// Generate creates a new random Ed25519 key.
func Generate() (*PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{Key: priv}, nil
}

// ParsePublicKey parses an authorized_keys style line. Only ssh-ed25519 keys
// are accepted.
func ParsePublicKey(line string) (*PublicKey, error) {
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return nil, fmt.Errorf("sshkey: parse public key: %w", err)
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("sshkey: unsupported public key")
	}
	edpk, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sshkey: key type %s is not ssh-ed25519", pk.Type())
	}
	return &PublicKey{Key: edpk, Comment: comment}, nil
}

// String returns the authorized_keys line ("ssh-ed25519 AAAA... comment").
func (p *PublicKey) String() string {
	pk, err := ssh.NewPublicKey(p.Key)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	if p.Comment != "" {
		line += " " + p.Comment
	}
	return line
}

// Fingerprint returns the key fingerprint in the format used by
// `ssh-keygen -lf` ("SHA256:<base64>").
func (p *PublicKey) Fingerprint() string {
	pk, err := ssh.NewPublicKey(p.Key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(pk.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// X25519 returns the Montgomery form of the public key for use in X25519 DH.
func (p *PublicKey) X25519() ([]byte, error) {
	pt, err := new(edwards25519.Point).SetBytes(p.Key)
	if err != nil {
		return nil, fmt.Errorf("sshkey: invalid ed25519 public key: %w", err)
	}
	return pt.BytesMontgomery(), nil
}

// Public returns the public half of the key with the given comment.
func (k *PrivateKey) Public(comment string) *PublicKey {
	return &PublicKey{Key: k.Key.Public().(ed25519.PublicKey), Comment: comment}
}

// X25519 returns the X25519 private scalar derived from the Ed25519 seed.
// Clamping is left to the X25519 function.
func (k *PrivateKey) X25519() []byte {
	h := sha512.Sum512(k.Key.Seed())
	return h[:32]
}

// MarshalOpenSSH encodes the key in the OpenSSH private key PEM format.
func (k *PrivateKey) MarshalOpenSSH(comment string) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(k.Key, comment)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// ParsePrivateKey parses an unencrypted OpenSSH ed25519 private key.
func ParsePrivateKey(data []byte) (*PrivateKey, error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshkey: parse private key: %w", err)
	}
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		return &PrivateKey{Key: *k}, nil
	case ed25519.PrivateKey:
		return &PrivateKey{Key: k}, nil
	default:
		return nil, fmt.Errorf("sshkey: private key type %T is not ed25519", raw)
	}
}

// LoadPrivateKey reads an OpenSSH private key file.
func LoadPrivateKey(path string) (*PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}

// SavePrivateKey writes the key to path with mode 0600. It fails if the file
// already exists.
func SavePrivateKey(path string, k *PrivateKey, comment string) error {
	data, err := k.MarshalOpenSSH(comment)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadOrGenerate loads the private key at path, generating and saving a new
// one if the file does not exist. created reports whether a key was generated.
func LoadOrGenerate(path, comment string) (k *PrivateKey, created bool, err error) {
	k, err = LoadPrivateKey(path)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	k, err = Generate()
	if err != nil {
		return nil, false, err
	}
	if err := SavePrivateKey(path, k, comment); err != nil {
		return nil, false, err
	}
	return k, true, nil
}
