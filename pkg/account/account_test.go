package account

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/mail"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
	"github.com/deb-ict/go-identity/pkg/store/memory"
)

type links struct{}

func (links) ActivationURL(token string) string {
	return "https://id.example.com/activate?token=" + url.QueryEscape(token)
}

func (links) PasswordResetURL(token string) string {
	return "https://id.example.com/password/reset?token=" + url.QueryEscape(token)
}

type fixture struct {
	svc    *Service
	store  *memory.Store
	mailer *mail.MemorySender
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{store: memory.New(), mailer: &mail.MemorySender{}, now: time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)}
	f.svc = New(Options{
		Store:             f.store,
		Hasher:            security.NewBcryptHasher(4),
		Mailer:            f.mailer,
		Links:             links{},
		RequireActivation: true,
		MaxFailedAttempts: 3,
		LockoutDuration:   10 * time.Minute,
		Now:               func() time.Time { return f.now },
	})
	return f
}

func tokenFromLastMail(t *testing.T, m *mail.MemorySender) string {
	t.Helper()
	msg := m.Last()
	if msg == nil {
		t.Fatal("expected an email")
	}
	i := strings.Index(msg.Text, "token=")
	if i < 0 {
		t.Fatalf("no token in email: %s", msg.Text)
	}
	token := msg.Text[i+len("token="):]
	token = strings.Fields(token)[0]
	token, _ = url.QueryUnescape(token)
	return token
}

func TestRegisterActivateAuthenticate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	user, err := f.svc.Register(ctx, "Alice", "Alice@Example.com", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if user.EmailVerified || !user.Enabled || user.NormalizedUsername != "alice" || user.NormalizedEmail != "alice@example.com" {
		t.Fatalf("unexpected user %+v", user)
	}
	if f.mailer.Last() == nil || f.mailer.Last().To != "Alice@Example.com" || !strings.Contains(f.mailer.Last().Subject, "activate") {
		t.Fatalf("expected activation email")
	}

	// Duplicate
	if _, err := f.svc.Register(ctx, "alice", "other@example.com", "correct horse"); !errors.Is(err, ErrUserExists) {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
	if _, err := f.svc.Register(ctx, "bob", "ALICE@example.com", "correct horse"); !errors.Is(err, ErrUserExists) {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
	// Validation
	if _, err := f.svc.Register(ctx, "bob", "bob@example.com", "short"); !identity.IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := f.svc.Register(ctx, "b", "bob@example.com", "long enough"); !identity.IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := f.svc.Register(ctx, "bob", "not an email", "long enough"); !identity.IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}

	// Not activated yet: only revealed with the correct password
	if _, err := f.svc.Authenticate(ctx, "alice", "wrong password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, "alice", "correct horse"); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("expected ErrNotActivated, got %v", err)
	}

	// Resend invalidates the first token
	firstToken := tokenFromLastMail(t, f.mailer)
	if err := f.svc.ResendActivation(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	secondToken := tokenFromLastMail(t, f.mailer)
	if _, err := f.svc.Activate(ctx, firstToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected old token to be invalid, got %v", err)
	}
	if _, err := f.svc.Activate(ctx, secondToken); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Activate(ctx, secondToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("activation token must be single use, got %v", err)
	}

	// Login by username and email
	if _, err := f.svc.Authenticate(ctx, "ALICE", "correct horse"); err != nil {
		t.Fatal(err)
	}
	logged, err := f.svc.Authenticate(ctx, "alice@example.com", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if logged.LastLoginAt == nil || !logged.LastLoginAt.Equal(f.now) {
		t.Fatal("expected last login to be set")
	}
	if _, err := f.svc.Authenticate(ctx, "nobody", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// Resend for activated or unknown accounts is silent
	count := len(f.mailer.Messages())
	f.svc.ResendActivation(ctx, "alice@example.com")
	f.svc.ResendActivation(ctx, "nobody@example.com")
	if len(f.mailer.Messages()) != count {
		t.Fatal("no email expected")
	}
}

func TestActivationExpires(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Register(ctx, "alice", "alice@example.com", "correct horse"); err != nil {
		t.Fatal(err)
	}
	token := tokenFromLastMail(t, f.mailer)
	f.now = f.now.Add(49 * time.Hour)
	if _, err := f.svc.Activate(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected expired token, got %v", err)
	}
}

func TestLockout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.svc.CreateUser(ctx, CreateUserInput{Username: "alice", Email: "alice@example.com", Password: "correct horse", EmailVerified: true, Enabled: true})

	for i := 0; i < 3; i++ {
		if _, err := f.svc.Authenticate(ctx, "alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}
	if _, err := f.svc.Authenticate(ctx, "alice", "correct horse"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("expected ErrLockedOut, got %v", err)
	}
	f.now = f.now.Add(11 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, "alice", "correct horse"); err != nil {
		t.Fatalf("expected lockout to end, got %v", err)
	}
}

func TestDisabled(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, _ := f.svc.CreateUser(ctx, CreateUserInput{Username: "alice", Email: "alice@example.com", Password: "correct horse", EmailVerified: true, Enabled: true})
	stamp := user.SecurityStamp
	user.Enabled = false
	if err := f.svc.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if user.SecurityStamp == stamp {
		t.Fatal("disabling must rotate the security stamp")
	}
	if _, err := f.svc.Authenticate(ctx, "alice", "correct horse"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
	// No password reset for disabled accounts
	count := len(f.mailer.Messages())
	f.svc.RequestPasswordReset(ctx, "alice@example.com")
	if len(f.mailer.Messages()) != count {
		t.Fatal("no email expected")
	}
}

func TestPasswordReset(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, _ := f.svc.Register(ctx, "alice", "alice@example.com", "correct horse")
	f.store.CreateRefreshToken(ctx, &identity.RefreshToken{Id: "r1", TokenHash: "h1", UserId: user.Id, ExpiresAt: f.now.Add(time.Hour)})

	if err := f.svc.RequestPasswordReset(ctx, "nobody@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RequestPasswordReset(ctx, "ALICE@example.com"); err != nil {
		t.Fatal(err)
	}
	token := tokenFromLastMail(t, f.mailer)
	if err := f.svc.VerifyPasswordResetToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.VerifyPasswordResetToken(ctx, "invalid"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := f.svc.ResetPassword(ctx, token, "short"); !identity.IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := f.svc.ResetPassword(ctx, token, "a new password"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ResetPassword(ctx, token, "a new password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reset token must be single use, got %v", err)
	}

	// The reset proves ownership of the email, so the account is activated
	updated, err := f.svc.Authenticate(ctx, "alice", "a new password")
	if err != nil {
		t.Fatal(err)
	}
	if updated.SecurityStamp == user.SecurityStamp {
		t.Fatal("expected a new security stamp")
	}
	if _, err := f.svc.Authenticate(ctx, "alice", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("old password must not work")
	}
	if _, err := f.store.GetRefreshTokenById(ctx, "r1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tokens must be revoked after a password reset")
	}
}

func TestDeleteUser(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, _ := f.svc.Register(ctx, "alice", "alice@example.com", "correct horse")
	f.store.CreateAccessToken(ctx, &identity.AccessToken{Id: "a1", TokenHash: "h1", UserId: user.Id, ExpiresAt: f.now.Add(time.Hour)})
	if err := f.svc.DeleteUser(ctx, user.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetAccessTokenById(ctx, "a1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tokens must be deleted with the user")
	}
	if err := f.svc.DeleteUser(ctx, user.Id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateUserKeepsCredentials(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, _ := f.svc.CreateUser(ctx, CreateUserInput{Username: "alice", Email: "alice@example.com", Password: "correct horse", EmailVerified: true, Enabled: true})
	f.svc.CreateUser(ctx, CreateUserInput{Username: "bob", Email: "bob@example.com", Enabled: true})

	update := *user
	update.PasswordHash = "tampered"
	update.Username = "alice2"
	if err := f.svc.UpdateUser(ctx, &update); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, "alice2", "correct horse"); err != nil {
		t.Fatalf("password must be unchanged: %v", err)
	}
	update.Username = "bob"
	if err := f.svc.UpdateUser(ctx, &update); !errors.Is(err, ErrUserExists) {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
	// A user without password can't log in
	if _, err := f.svc.Authenticate(ctx, "bob", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
