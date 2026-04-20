package cert_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// ---------------------------------------------------------------------------
// GetByCN
// ---------------------------------------------------------------------------

func TestGetByCN(t *testing.T) {
	tests := []struct {
		name       string
		certType   cert.CertType
		cn         string
		seed       []cert.IssuedCert
		wantErr    error
		wantSerial string
	}{
		{
			name:     "returns active server cert",
			certType: cert.TypeServer,
			cn:       "svc.lab",
			seed: []cert.IssuedCert{{
				Serial:     "abc123",
				Type:       cert.TypeServer,
				CommonName: "svc.lab",
				ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
			}},
			wantSerial: "abc123",
		},
		{
			name:     "returns active client cert",
			certType: cert.TypeClient,
			cn:       "alice",
			seed: []cert.IssuedCert{{
				Serial:     "def456",
				Type:       cert.TypeClient,
				CommonName: "alice",
				ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
			}},
			wantSerial: "def456",
		},
		{
			name:     "returns ErrNotFound when no active cert",
			certType: cert.TypeServer,
			cn:       "missing.lab",
			seed:     nil,
			wantErr:  cert.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &fakeStore{saved: tt.seed}
			svc := cert.NewService(newRealSigner(t), &fakeRevoker{}, st, cert.CertDefaults{}, testLogger())

			got, err := svc.GetByCN(context.Background(), tt.certType, tt.cn)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got err %v, want wrapping %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Serial != tt.wantSerial {
				t.Errorf("Serial: got %q, want %q", got.Serial, tt.wantSerial)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

func TestRevoke(t *testing.T) {
	tests := []struct {
		name    string
		serial  string
		reason  string
		seed    []cert.IssuedCert
		wantErr error
	}{
		{
			name:   "revokes an existing certificate with unspecified reason",
			serial: "abc123",
			reason: "unspecified",
			seed: []cert.IssuedCert{{
				Serial:     "abc123",
				Type:       cert.TypeServer,
				CommonName: "svc.lab",
				ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
			}},
		},
		{
			name:   "revokes with keyCompromise reason",
			serial: "abc123",
			reason: "keyCompromise",
			seed: []cert.IssuedCert{{
				Serial:     "abc123",
				Type:       cert.TypeServer,
				CommonName: "svc.lab",
				ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
			}},
		},
		{
			name:    "returns ErrNotFound for unknown serial",
			serial:  "nosuchserial",
			reason:  "unspecified",
			seed:    nil,
			wantErr: cert.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &fakeStore{saved: tt.seed}
			revoker := &fakeRevoker{}
			svc := cert.NewService(newRealSigner(t), revoker, st, cert.CertDefaults{}, testLogger())

			summary, err := svc.Revoke(context.Background(), tt.serial, tt.reason)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got err %v, want wrapping %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if summary.Serial != tt.serial {
				t.Errorf("Summary.Serial: got %q, want %q", summary.Serial, tt.serial)
			}
			if summary.RevocationReason != tt.reason {
				t.Errorf("Summary.RevocationReason: got %q, want %q", summary.RevocationReason, tt.reason)
			}
			if summary.RevokedAt.IsZero() {
				t.Error("expected non-zero RevokedAt in summary")
			}
		})
	}
}

// TestRevoke_CRLError verifies that a CRL update failure is propagated.
func TestRevoke_CRLError(t *testing.T) {
	st := &fakeStore{saved: []cert.IssuedCert{{
		Serial:     "abc123",
		Type:       cert.TypeServer,
		CommonName: "svc.lab",
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}}}
	revoker := &errRevoker{err: errors.New("CRL write failed")}
	svc := cert.NewService(newRealSigner(t), revoker, st, cert.CertDefaults{}, testLogger())

	_, err := svc.Revoke(context.Background(), "abc123", "unspecified")
	if err == nil {
		t.Fatal("expected error from CRL update, got nil")
	}
}

// errRevoker is a Revoker that always returns an error.
type errRevoker struct {
	err error
}

func (e *errRevoker) Revoke(_ string, _ time.Time, _ string) error {
	return e.err
}
