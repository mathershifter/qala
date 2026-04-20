package cert_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// TestCNConflictError verifies the Error() method and Unwrap() behavior.
func TestCNConflictError(t *testing.T) {
	e := &cert.CNConflictError{
		CommonName: "svc.lab",
		Serial:     "aabbcc",
	}

	// Error() should return a non-empty string.
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}

	// Unwrap() should allow errors.Is to find ErrCNAlreadyActive.
	if !errors.Is(e, cert.ErrCNAlreadyActive) {
		t.Errorf("errors.Is(CNConflictError, ErrCNAlreadyActive) = false, want true")
	}

	// errors.As should find the CNConflictError.
	var conflict *cert.CNConflictError
	if !errors.As(e, &conflict) {
		t.Error("errors.As did not find CNConflictError")
	} else {
		if conflict.CommonName != "svc.lab" {
			t.Errorf("CommonName: got %q, want %q", conflict.CommonName, "svc.lab")
		}
		if conflict.Serial != "aabbcc" {
			t.Errorf("Serial: got %q, want %q", conflict.Serial, "aabbcc")
		}
	}
}

// TestValidateClientRequest_ValidityDays exercises the missing validity branch
// in validateClientRequest.
func TestValidateClientRequest_ValidityDays(t *testing.T) {
	tests := []struct {
		name    string
		req     cert.ClientRequest
		wantErr error
	}{
		{
			name: "validity_days too large",
			req:  cert.ClientRequest{CommonName: "alice", ValidityDays: 366},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name: "validity_days within max",
			req:  cert.ClientRequest{CommonName: "alice", ValidityDays: 365},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := cert.NewService(newRealSigner(t), &fakeRevoker{}, &fakeStore{}, cert.CertDefaults{}, testLogger())
			_, err := svc.IssueClient(context.Background(), tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
