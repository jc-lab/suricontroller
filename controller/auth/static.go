package auth

import (
	"context"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// StaticAdmin is a PasswordLogin with a single fixed administrator account.
type StaticAdmin struct {
	username string
	hash     []byte
}

// NewStaticAdmin creates a StaticAdmin from a plaintext password.
func NewStaticAdmin(username, password string) (*StaticAdmin, error) {
	if username == "" || password == "" {
		return nil, errors.New("auth: admin username and password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &StaticAdmin{username: username, hash: hash}, nil
}

// NewStaticAdminHash creates a StaticAdmin from a bcrypt password hash.
func NewStaticAdminHash(username, bcryptHash string) (*StaticAdmin, error) {
	if username == "" {
		return nil, errors.New("auth: admin username is required")
	}
	if _, err := bcrypt.Cost([]byte(bcryptHash)); err != nil {
		return nil, err
	}
	return &StaticAdmin{username: username, hash: []byte(bcryptHash)}, nil
}

// Login implements PasswordLogin.
func (a *StaticAdmin) Login(_ context.Context, username, password string) (*Principal, error) {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	// Always run bcrypt so the response time does not reveal the username.
	passErr := bcrypt.CompareHashAndPassword(a.hash, []byte(password))
	if !userOK || passErr != nil {
		return nil, ErrInvalidCredentials
	}
	return &Principal{ID: a.username, DisplayName: a.username, Roles: []string{"admin"}}, nil
}
