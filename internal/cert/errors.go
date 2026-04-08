package cert

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound is returned when a certificate serial is not in the store.
	ErrNotFound = errors.New("certificate not found")

	// ErrInvalidRequest is returned when a signing request fails validation.
	ErrInvalidRequest = errors.New("invalid certificate request")

	// ErrAlreadyExists is returned on a serial number collision (astronomically rare).
	ErrAlreadyExists = errors.New("certificate already exists")

	// ErrCNAlreadyActive is the sentinel wrapped by CNConflictError.
	ErrCNAlreadyActive = errors.New("active certificate already exists for this common name")
)

// CNConflictError is returned by the service when an active certificate for the
// requested CN already exists. It carries the existing serial so callers can
// retrieve it directly.
type CNConflictError struct {
	CommonName string
	Serial     string
}

func (e *CNConflictError) Error() string {
	return fmt.Sprintf("%s: cn=%q serial=%s", ErrCNAlreadyActive, e.CommonName, e.Serial)
}

func (e *CNConflictError) Unwrap() error { return ErrCNAlreadyActive }
