// Package account implements the user account flows: registration, activation,
// authentication (with lockout), password reset and user administration.
package account

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/deb-ict/go-identity/pkg/identity"
	"github.com/deb-ict/go-identity/pkg/mail"
	"github.com/deb-ict/go-identity/pkg/security"
	"github.com/deb-ict/go-identity/pkg/store"
)

var (
	ErrInvalidCredentials = errors.New("account: invalid username or password")
	ErrNotActivated       = errors.New("account: the account is not activated")
	ErrLockedOut          = errors.New("account: the account is temporarily locked")
	ErrDisabled           = errors.New("account: the account is disabled")
	ErrInvalidToken       = errors.New("account: the token is invalid or has expired")
	ErrUserExists         = errors.New("account: the username or email address is already in use")
	ErrNotFound           = errors.New("account: user not found")
)

// LinkBuilder builds the absolute URLs that are sent by email.
type LinkBuilder interface {
	ActivationURL(token string) string
	PasswordResetURL(token string) string
}

// Options configures the account service.
type Options struct {
	Store  store.Store
	Hasher security.PasswordHasher
	Mailer mail.Sender
	Links  LinkBuilder
	// ApplicationName is used in the emails.
	ApplicationName string
	// RequireActivation requires users to confirm their email address before they can log in.
	RequireActivation          bool
	ActivationTokenLifetime    time.Duration
	PasswordResetTokenLifetime time.Duration
	MinPasswordLength          int
	// MaxFailedAttempts locks the account after this many consecutive failed logins. 0 disables lockout.
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	Now               func() time.Time
	Logger            *slog.Logger
}

// Service implements the account flows.
type Service struct {
	opts      Options
	dummyOnce sync.Once
	dummyHash string
}

// New creates the account service.
func New(opts Options) *Service {
	if opts.Hasher == nil {
		opts.Hasher = security.NewBcryptHasher(0)
	}
	if opts.Mailer == nil {
		opts.Mailer = &mail.LogSender{Logger: opts.Logger}
	}
	if opts.ApplicationName == "" {
		opts.ApplicationName = "Identity"
	}
	if opts.ActivationTokenLifetime <= 0 {
		opts.ActivationTokenLifetime = 48 * time.Hour
	}
	if opts.PasswordResetTokenLifetime <= 0 {
		opts.PasswordResetTokenLifetime = time.Hour
	}
	if opts.MinPasswordLength <= 0 {
		opts.MinPasswordLength = 8
	}
	if opts.LockoutDuration <= 0 {
		opts.LockoutDuration = 15 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Service{opts: opts}
}

// Options returns the effective options.
func (s *Service) Options() Options {
	return s.opts
}

func (s *Service) now() time.Time {
	return s.opts.Now().UTC().Truncate(time.Millisecond)
}

// ValidatePassword checks the password policy.
func (s *Service) ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < s.opts.MinPasswordLength {
		return identity.NewValidationError("password", "is too short")
	}
	if len(password) > security.MaxSecretLength {
		return identity.NewValidationError("password", "is too long, the maximum is 72 bytes")
	}
	return nil
}

// GetUser returns the user by id.
func (s *Service) GetUser(ctx context.Context, id string) (*identity.User, error) {
	user, err := s.opts.Store.GetUserById(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	return user, err
}

// FindUser looks up a user by username or email address.
func (s *Service) FindUser(ctx context.Context, login string) (*identity.User, error) {
	user, err := s.opts.Store.GetUserByNormalizedUsername(ctx, identity.NormalizeUsername(login))
	if errors.Is(err, store.ErrNotFound) && strings.Contains(login, "@") {
		user, err = s.opts.Store.GetUserByNormalizedEmail(ctx, identity.NormalizeEmail(login))
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	return user, err
}

// CreateUserInput contains the data of a new user.
type CreateUserInput struct {
	Username      string
	Email         string
	Password      string
	EmailVerified bool
	Enabled       bool
	// SendActivation sends the activation email when the email is not verified.
	SendActivation bool
}

// Register creates a new self-registered user. When activation is required, the activation email is sent.
func (s *Service) Register(ctx context.Context, username string, email string, password string) (*identity.User, error) {
	return s.CreateUser(ctx, CreateUserInput{
		Username:       username,
		Email:          email,
		Password:       password,
		EmailVerified:  !s.opts.RequireActivation,
		Enabled:        true,
		SendActivation: s.opts.RequireActivation,
	})
}

// CreateUser creates a user. The password is optional: users without password can set one with the password reset flow.
func (s *Service) CreateUser(ctx context.Context, input CreateUserInput) (*identity.User, error) {
	now := s.now()
	user := &identity.User{
		Id:            security.NewId(),
		Username:      input.Username,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		Enabled:       input.Enabled,
		SecurityStamp: security.NewToken(),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	user.Normalize()
	if err := user.Validate(); err != nil {
		return nil, err
	}
	if input.Password != "" {
		if err := s.ValidatePassword(input.Password); err != nil {
			return nil, err
		}
		hash, err := s.opts.Hasher.Hash(input.Password)
		if err != nil {
			return nil, err
		}
		user.PasswordHash = hash
	}
	if err := s.ensureUnique(ctx, user); err != nil {
		return nil, err
	}
	if err := s.opts.Store.CreateUser(ctx, user); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return nil, ErrUserExists
		}
		return nil, err
	}
	if input.SendActivation && !user.EmailVerified {
		if err := s.SendActivation(ctx, user); err != nil {
			s.opts.Logger.ErrorContext(ctx, "failed to send activation email", "user", user.Id, "error", err)
		}
	}
	return user, nil
}

func (s *Service) ensureUnique(ctx context.Context, user *identity.User) error {
	existing, err := s.opts.Store.GetUserByNormalizedUsername(ctx, user.NormalizedUsername)
	if err == nil && existing.Id != user.Id {
		return ErrUserExists
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	existing, err = s.opts.Store.GetUserByNormalizedEmail(ctx, user.NormalizedEmail)
	if err == nil && existing.Id != user.Id {
		return ErrUserExists
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// UpdateUser saves the profile and status of the user. The password is changed with SetPassword.
func (s *Service) UpdateUser(ctx context.Context, user *identity.User) error {
	current, err := s.GetUser(ctx, user.Id)
	if err != nil {
		return err
	}
	user.Normalize()
	if err := user.Validate(); err != nil {
		return err
	}
	if err := s.ensureUnique(ctx, user); err != nil {
		return err
	}
	// The credentials can't be changed by an update
	user.PasswordHash = current.PasswordHash
	user.CreatedAt = current.CreatedAt
	user.UpdatedAt = s.now()
	if user.SecurityStamp == "" {
		user.SecurityStamp = current.SecurityStamp
	}
	if !user.Enabled && current.Enabled || user.NormalizedEmail != current.NormalizedEmail {
		// Disabling the account or changing the email invalidates sessions
		user.SecurityStamp = security.NewToken()
	}
	if err := s.opts.Store.UpdateUser(ctx, user); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return ErrUserExists
		}
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if !user.Enabled && current.Enabled {
		return s.RevokeTokens(ctx, user.Id)
	}
	return nil
}

// DeleteUser deletes the user and all tokens of the user.
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	if err := s.opts.Store.DeleteUser(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if err := s.RevokeTokens(ctx, id); err != nil {
		return err
	}
	for _, purpose := range []identity.UserTokenPurpose{identity.UserTokenPurposeActivation, identity.UserTokenPurposePasswordReset} {
		if _, err := s.opts.Store.DeleteUserTokens(ctx, id, purpose); err != nil {
			return err
		}
	}
	return nil
}

// RevokeTokens deletes all access and refresh tokens of the user.
func (s *Service) RevokeTokens(ctx context.Context, userId string) error {
	filter := store.TokenFilter{UserId: userId}
	if _, err := s.opts.Store.DeleteRefreshTokens(ctx, filter); err != nil {
		return err
	}
	_, err := s.opts.Store.DeleteAccessTokens(ctx, filter)
	return err
}

// SetPassword changes the password, unlocks the account and revokes all tokens and sessions.
func (s *Service) SetPassword(ctx context.Context, userId string, password string) error {
	user, err := s.GetUser(ctx, userId)
	if err != nil {
		return err
	}
	return s.setPassword(ctx, user, password)
}

func (s *Service) setPassword(ctx context.Context, user *identity.User, password string) error {
	if err := s.ValidatePassword(password); err != nil {
		return err
	}
	hash, err := s.opts.Hasher.Hash(password)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	user.SecurityStamp = security.NewToken()
	user.FailedLoginCount = 0
	user.LockoutEnd = nil
	user.UpdatedAt = s.now()
	if err := s.opts.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	return s.RevokeTokens(ctx, user.Id)
}

// Authenticate verifies the credentials. The login is the username or the email address.
//
// The password is verified before the account status is revealed, so only the owner of the
// account learns that it is disabled or not activated.
func (s *Service) Authenticate(ctx context.Context, login string, password string) (*identity.User, error) {
	now := s.now()
	user, err := s.FindUser(ctx, login)
	if errors.Is(err, ErrNotFound) {
		// Spend the same time as a real verification to avoid user enumeration
		s.opts.Hasher.Verify(s.getDummyHash(), password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if user.IsLockedOut(now) {
		return nil, ErrLockedOut
	}
	if user.PasswordHash == "" || s.opts.Hasher.Verify(user.PasswordHash, password) != nil {
		if user.PasswordHash == "" {
			s.opts.Hasher.Verify(s.getDummyHash(), password)
		}
		if s.opts.MaxFailedAttempts > 0 {
			user.FailedLoginCount++
			if user.FailedLoginCount >= s.opts.MaxFailedAttempts {
				lockoutEnd := now.Add(s.opts.LockoutDuration)
				user.LockoutEnd = &lockoutEnd
				user.FailedLoginCount = 0
				s.opts.Logger.WarnContext(ctx, "account locked after failed login attempts", "user", user.Id)
			}
			user.UpdatedAt = now
			if err := s.opts.Store.UpdateUser(ctx, user); err != nil {
				return nil, err
			}
		}
		return nil, ErrInvalidCredentials
	}
	if !user.Enabled {
		return nil, ErrDisabled
	}
	if s.opts.RequireActivation && !user.EmailVerified {
		return nil, ErrNotActivated
	}
	user.FailedLoginCount = 0
	user.LockoutEnd = nil
	user.LastLoginAt = &now
	user.UpdatedAt = now
	if err := s.opts.Store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// CanSignIn checks if the user is allowed to sign in (and to get tokens).
func (s *Service) CanSignIn(user *identity.User) error {
	if !user.Enabled {
		return ErrDisabled
	}
	if s.opts.RequireActivation && !user.EmailVerified {
		return ErrNotActivated
	}
	return nil
}

func (s *Service) getDummyHash() string {
	s.dummyOnce.Do(func() {
		s.dummyHash, _ = s.opts.Hasher.Hash(security.NewToken())
	})
	return s.dummyHash
}

func (s *Service) createUserToken(ctx context.Context, user *identity.User, purpose identity.UserTokenPurpose, lifetime time.Duration) (string, error) {
	// Only the most recent token is valid
	if _, err := s.opts.Store.DeleteUserTokens(ctx, user.Id, purpose); err != nil {
		return "", err
	}
	now := s.now()
	token := security.NewToken()
	err := s.opts.Store.CreateUserToken(ctx, &identity.UserToken{
		Id:        security.NewId(),
		UserId:    user.Id,
		Purpose:   purpose,
		TokenHash: security.HashToken(token),
		CreatedAt: now,
		ExpiresAt: now.Add(lifetime),
	})
	return token, err
}

func (s *Service) lookupUserToken(ctx context.Context, purpose identity.UserTokenPurpose, token string) (*identity.UserToken, *identity.User, error) {
	if token == "" {
		return nil, nil, ErrInvalidToken
	}
	userToken, err := s.opts.Store.GetUserTokenByHash(ctx, purpose, security.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	if userToken.HasExpired(s.now()) {
		return nil, nil, ErrInvalidToken
	}
	user, err := s.opts.Store.GetUserById(ctx, userToken.UserId)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	return userToken, user, nil
}

// SendActivation sends a new activation email to the user.
func (s *Service) SendActivation(ctx context.Context, user *identity.User) error {
	token, err := s.createUserToken(ctx, user, identity.UserTokenPurposeActivation, s.opts.ActivationTokenLifetime)
	if err != nil {
		return err
	}
	return s.opts.Mailer.Send(ctx, activationMessage(s.opts.ApplicationName, user, s.opts.Links.ActivationURL(token), s.opts.ActivationTokenLifetime))
}

// ResendActivation sends a new activation email when an inactive account exists for the email address.
// It doesn't reveal whether the account exists.
func (s *Service) ResendActivation(ctx context.Context, email string) error {
	user, err := s.opts.Store.GetUserByNormalizedEmail(ctx, identity.NormalizeEmail(email))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if user.EmailVerified || !user.Enabled {
		return nil
	}
	return s.SendActivation(ctx, user)
}

// Activate confirms the email address of the user.
func (s *Service) Activate(ctx context.Context, token string) (*identity.User, error) {
	userToken, user, err := s.lookupUserToken(ctx, identity.UserTokenPurposeActivation, token)
	if err != nil {
		return nil, err
	}
	user.EmailVerified = true
	user.UpdatedAt = s.now()
	if err := s.opts.Store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	if err := s.opts.Store.DeleteUserToken(ctx, userToken.Id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return user, nil
}

// RequestPasswordReset sends a password reset email when an enabled account exists for the email address.
// It doesn't reveal whether the account exists.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.opts.Store.GetUserByNormalizedEmail(ctx, identity.NormalizeEmail(email))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !user.Enabled {
		return nil
	}
	token, err := s.createUserToken(ctx, user, identity.UserTokenPurposePasswordReset, s.opts.PasswordResetTokenLifetime)
	if err != nil {
		return err
	}
	return s.opts.Mailer.Send(ctx, passwordResetMessage(s.opts.ApplicationName, user, s.opts.Links.PasswordResetURL(token), s.opts.PasswordResetTokenLifetime))
}

// VerifyPasswordResetToken checks that the password reset token is valid.
func (s *Service) VerifyPasswordResetToken(ctx context.Context, token string) error {
	_, user, err := s.lookupUserToken(ctx, identity.UserTokenPurposePasswordReset, token)
	if err == nil && !user.Enabled {
		return ErrInvalidToken
	}
	return err
}

// ResetPassword sets a new password with a password reset token. The email address is
// confirmed as well, since the user proved to have access to it.
func (s *Service) ResetPassword(ctx context.Context, token string, password string) (*identity.User, error) {
	if err := s.ValidatePassword(password); err != nil {
		return nil, err
	}
	_, user, err := s.lookupUserToken(ctx, identity.UserTokenPurposePasswordReset, token)
	if err != nil {
		return nil, err
	}
	if !user.Enabled {
		return nil, ErrInvalidToken
	}
	user.EmailVerified = true
	if err := s.setPassword(ctx, user, password); err != nil {
		return nil, err
	}
	if _, err := s.opts.Store.DeleteUserTokens(ctx, user.Id, identity.UserTokenPurposePasswordReset); err != nil {
		return nil, err
	}
	return user, nil
}
