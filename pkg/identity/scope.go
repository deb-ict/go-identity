package identity

import (
	"strings"
)

// ParseScope parses a space-delimited scope parameter (RFC 6749 section 3.3).
// Duplicate scope tokens are removed, the order is preserved.
func ParseScope(scope string) []string {
	fields := strings.Split(scope, " ")
	result := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		result = append(result, field)
	}
	return result
}

// FormatScope formats scopes as a space-delimited string.
func FormatScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// IsValidScopeToken checks the scope-token syntax: 1*( %x21 / %x23-5B / %x5D-7E ).
func IsValidScopeToken(scope string) bool {
	if scope == "" {
		return false
	}
	for i := 0; i < len(scope); i++ {
		c := scope[i]
		if c < 0x21 || c == 0x22 || c == 0x5C || c > 0x7E {
			return false
		}
	}
	return true
}

// ValidateScopeSyntax checks every scope token.
func ValidateScopeSyntax(scopes []string) bool {
	for _, scope := range scopes {
		if !IsValidScopeToken(scope) {
			return false
		}
	}
	return true
}

// ScopesEqual returns true when both slices contain the same scopes, regardless of order.
func ScopesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if !set[s] {
			return false
		}
	}
	return true
}

// HasScope returns true when the scope is part of the list.
func HasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
