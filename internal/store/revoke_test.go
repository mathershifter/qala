package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

func TestRevoke(t *testing.T) {
	tests := []struct {
		name    string
		serial  string
		seed    bool
		preRevoke bool // revoke before the test call to trigger already-revoked
		reason  string
		wantErr error
	}{
		{
			name:   "revokes an existing certificate",
			serial: "rev001",
			seed:   true,
			reason: "unspecified",
		},
		{
			name:   "revokes with keyCompromise reason",
			serial: "rev002",
			seed:   true,
			reason: "keyCompromise",
		},
		{
			name:    "returns ErrNotFound for unknown serial",
			serial:  "nope",
			seed:    false,
			reason:  "unspecified",
			wantErr: cert.ErrNotFound,
		},
		{
			name:      "returns ErrAlreadyRevoked when cert already revoked",
			serial:    "rev003",
			seed:      true,
			preRevoke: true,
			reason:    "unspecified",
			wantErr:   cert.ErrAlreadyRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()

			if tt.seed {
				c := makeIssuedCert(tt.serial, cert.TypeServer, "svc.lab", false, false)
				if err := s.Save(ctx, c); err != nil {
					t.Fatalf("Save: %v", err)
				}
			}

			if tt.preRevoke {
				if err := s.Revoke(ctx, tt.serial, time.Now().UTC(), "unspecified"); err != nil {
					t.Fatalf("pre-revoke failed: %v", err)
				}
			}

			err := s.Revoke(ctx, tt.serial, time.Now().UTC(), tt.reason)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Revoke: unexpected error: %v", err)
			}

			// Verify the revocation is persisted.
			got, getErr := s.Get(ctx, tt.serial)
			if getErr != nil {
				t.Fatalf("Get after Revoke: %v", getErr)
			}
			if got.RevokedAt == nil {
				t.Error("expected RevokedAt to be set after revocation")
			}
			if got.RevocationReason != tt.reason {
				t.Errorf("RevocationReason: got %q, want %q", got.RevocationReason, tt.reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ListRevoked
// ---------------------------------------------------------------------------

// TestListRevoked verifies that ListRevoked returns all non-expired certificates
// including revoked ones. The Revoked:true filter removes the "revoked_at IS NULL"
// exclusion, so the result set includes both active and revoked non-expired certs.
func TestListRevoked(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Seed: two active certs, one revoked cert, one expired cert.
	active1 := makeIssuedCert("a1", cert.TypeServer, "active1.lab", false, false)
	active2 := makeIssuedCert("a2", cert.TypeClient, "alice", false, false)
	toRevoke := makeIssuedCert("r1", cert.TypeServer, "revoked.lab", false, false)
	expired := makeIssuedCert("e1", cert.TypeServer, "expired.lab", true, false)

	for _, c := range []cert.IssuedCert{active1, active2, toRevoke, expired} {
		if err := s.Save(ctx, c); err != nil {
			t.Fatalf("Save %s: %v", c.Serial, err)
		}
	}

	// Revoke "r1".
	if err := s.Revoke(ctx, "r1", time.Now().UTC(), "keyCompromise"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	results, err := s.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked: %v", err)
	}

	// ListRevoked uses Revoked:true, Expired:false — this includes active and
	// revoked non-expired certs. We expect active1, active2, and r1 (3 total).
	// The expired cert (e1) is excluded because Expired:false.
	if len(results) != 3 {
		t.Fatalf("expected 3 certs from ListRevoked (active + revoked, excluding expired), got %d: %v", len(results), results)
	}

	// Verify that r1 (the revoked cert) is in the results.
	found := false
	for _, r := range results {
		if r.Serial == "r1" {
			found = true
			if r.RevocationReason != "keyCompromise" {
				t.Errorf("r1 RevocationReason: got %q, want %q", r.RevocationReason, "keyCompromise")
			}
		}
	}
	if !found {
		t.Error("revoked cert r1 not found in ListRevoked results")
	}
}

func TestListRevoked_EmptyStore(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	results, err := s.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked on empty store: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results on empty store, got %d", len(results))
	}
}
