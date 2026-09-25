package identity

import (
	"errors"
	"fmt"
)

// ValidationError is returned when an entity contains invalid data.
type ValidationError struct {
	Field   string
	Message string
}

func NewValidationError(field string, message string) *ValidationError {
	return &ValidationError{Field: field, Message: message}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s %s", e.Field, e.Message)
}

// IsValidationError checks if the error is (or wraps) a validation error.
func IsValidationError(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}
