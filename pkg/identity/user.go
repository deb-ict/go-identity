package identity

import (
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

// User is an end-user (resource owner) account.
type User struct {
	Id                 string
	Username           string
	NormalizedUsername string
	Email              string
	NormalizedEmail    string
	PasswordHash       string
	EmailVerified      bool
	Enabled            bool
	// SecurityStamp changes whenever the credentials change, which invalidates existing sessions.
	SecurityStamp    string
	FailedLoginCount int
	LockoutEnd       *time.Time
	LastLoginAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// IsLockedOut returns true when the account is temporarily locked because of failed login attempts.
func (u *User) IsLockedOut(now time.Time) bool {
	return u.LockoutEnd != nil && now.Before(*u.LockoutEnd)
}

// Normalize fills in the normalized username and email.
func (u *User) Normalize() {
	u.Username = strings.TrimSpace(u.Username)
	u.Email = strings.TrimSpace(u.Email)
	u.NormalizedUsername = NormalizeUsername(u.Username)
	u.NormalizedEmail = NormalizeEmail(u.Email)
}

// Validate checks the user properties.
func (u *User) Validate() error {
	if err := ValidateUsername(u.Username); err != nil {
		return err
	}
	return ValidateEmail(u.Email)
}

func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidateUsername checks that the username has 3 to 64 characters: letters, digits, '.', '_', '-' or '@'.
func ValidateUsername(username string) error {
	n := utf8.RuneCountInString(username)
	if n < 3 || n > 64 {
		return NewValidationError("username", "must be between 3 and 64 characters")
	}
	for _, r := range username {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '@') {
			return NewValidationError("username", "may only contain letters, digits, '.', '_', '-' and '@'")
		}
	}
	return nil
}

// ValidateEmail checks that the email is a plain email address.
func ValidateEmail(email string) error {
	if email == "" || len(email) > 254 {
		return NewValidationError("email", "is required")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return NewValidationError("email", "is not a valid email address")
	}
	return nil
}
