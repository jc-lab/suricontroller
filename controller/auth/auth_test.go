package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newSession(t *testing.T) *CookieSession {
	t.Helper()
	admin, err := NewStaticAdmin("admin", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewCookieSession(CookieSessionConfig{Login: admin, Secret: []byte(strings.Repeat("k", 32)), MaxAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func requestWith(h http.Header) *http.Request {
	r := httptest.NewRequest("POST", "/", nil)
	for _, c := range (&http.Response{Header: h}).Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestLoginAndSession(t *testing.T) {
	s := newSession(t)
	ctx := WithRemoteAddr(context.Background(), "10.0.0.1:1234")
	if _, err := s.Login(ctx, "admin", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Login(ctx, "root", "s3cret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong user: %v", err)
	}
	p, err := s.Login(ctx, "admin", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	if err := s.IssueSession(h, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.Get("Set-Cookie"), "HttpOnly") || !strings.Contains(h.Get("Set-Cookie"), "SameSite=Strict") {
		t.Fatalf("cookie attributes: %s", h.Get("Set-Cookie"))
	}
	got, err := s.Authenticate(requestWith(h))
	if err != nil || got.ID != "admin" {
		t.Fatalf("authenticate: %v %v", got, err)
	}

	// Rate limit: 3 attempts per minute per address were used above.
	if _, err := s.Login(ctx, "admin", "s3cret"); err == nil {
		t.Fatal("expected rate limit")
	}
	other := WithRemoteAddr(context.Background(), "10.0.0.2:1")
	if _, err := s.Login(other, "admin", "s3cret"); err != nil {
		t.Fatalf("other address limited: %v", err)
	}
}

func TestSessionTamperAndExpiry(t *testing.T) {
	s := newSession(t)
	h := http.Header{}
	_ = s.IssueSession(h, &Principal{ID: "admin"})
	r := requestWith(h)
	c, _ := r.Cookie("suricontroller_session")

	bad := httptest.NewRequest("POST", "/", nil)
	bad.AddCookie(&http.Cookie{Name: c.Name, Value: "x" + c.Value})
	if _, err := s.Authenticate(bad); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("tampered cookie accepted")
	}

	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	if _, err := s.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired cookie accepted")
	}
	if _, err := s.Authenticate(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("missing cookie accepted")
	}
}
