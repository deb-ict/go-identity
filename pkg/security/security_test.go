package security

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestBcryptHasher(t *testing.T) {
	h := NewBcryptHasher(4)
	hash, err := h.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(hash, "secret"); err != nil {
		t.Fatalf("expected match: %v", err)
	}
	if err := h.Verify(hash, "other"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected mismatch, got %v", err)
	}

	// bcrypt ignores everything after 72 bytes: longer secrets are refused, not truncated
	max := strings.Repeat("a", MaxSecretLength)
	hash, err = h.Hash(max)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(hash, max); err != nil {
		t.Fatalf("expected 72 byte secret to match: %v", err)
	}
	if _, err := h.Hash(max + "a"); !errors.Is(err, ErrSecretTooLong) {
		t.Fatalf("expected ErrSecretTooLong, got %v", err)
	}
	if err := h.Verify(hash, max+"b"); !errors.Is(err, ErrMismatch) {
		t.Fatal("a secret with a matching 72 byte prefix must not match")
	}
}

func TestRandomToken(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b || len(a) != 43 {
		t.Fatalf("unexpected tokens %q %q", a, b)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(a) {
		t.Fatalf("token is not URL safe: %q", a)
	}
}

func TestNewId(t *testing.T) {
	id := NewId()
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Fatalf("invalid uuid %q", id)
	}
}

func TestHashToken(t *testing.T) {
	if HashToken("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("unexpected sha256")
	}
}

func TestPkce(t *testing.T) {
	// RFC 7636 appendix B
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if S256Challenge(verifier) != challenge {
		t.Fatal("unexpected S256 challenge")
	}
	if !VerifyCodeChallenge(challenge, "S256", verifier) {
		t.Fatal("expected S256 to verify")
	}
	if VerifyCodeChallenge(challenge, "S256", verifier[:43-1]+"x") {
		t.Fatal("expected S256 mismatch")
	}
	if !VerifyCodeChallenge(verifier, "plain", verifier) {
		t.Fatal("expected plain to verify")
	}
	if VerifyCodeChallenge("short", "plain", "short") {
		t.Fatal("verifier must have at least 43 characters")
	}
	if VerifyCodeChallenge(verifier, "other", verifier) {
		t.Fatal("unsupported method must fail")
	}
}
