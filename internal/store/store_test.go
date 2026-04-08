package store_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/seacrt/internal/cert"
	"gitlab.aristanetworks.com/jmather/seacrt/internal/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "test.db"), testLogger())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeIssuedCert(serial string, certType cert.CertType, cn string, expired bool) cert.IssuedCert {
	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(90 * 24 * time.Hour)
	if expired {
		expiresAt = issuedAt.Add(-24 * time.Hour)
	}
	return cert.IssuedCert{
		Serial:         serial,
		Type:           certType,
		CommonName:     cn,
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		PrivateKeyPEM:  "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
	}
}

func TestSaveAndGet(t *testing.T) {
	tests := []struct {
		name     string
		input    cert.IssuedCert
	}{
		{
			name:  "server cert round-trips",
			input: makeIssuedCert("aabbcc", cert.TypeServer, "svc.lab", false),
		},
		{
			name:  "client cert round-trips",
			input: makeIssuedCert("ddeeff", cert.TypeClient, "alice", false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()

			if err := s.Save(ctx, tt.input); err != nil {
				t.Fatalf("Save: %v", err)
			}

			got, err := s.Get(ctx, tt.input.Serial)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			if got.Serial != tt.input.Serial {
				t.Errorf("Serial: got %q, want %q", got.Serial, tt.input.Serial)
			}
			if got.Type != tt.input.Type {
				t.Errorf("Type: got %q, want %q", got.Type, tt.input.Type)
			}
			if got.CommonName != tt.input.CommonName {
				t.Errorf("CommonName: got %q, want %q", got.CommonName, tt.input.CommonName)
			}
			if got.CertificatePEM != tt.input.CertificatePEM {
				t.Errorf("CertificatePEM mismatch")
			}
			if got.PrivateKeyPEM != tt.input.PrivateKeyPEM {
				t.Errorf("PrivateKeyPEM mismatch")
			}
			if !got.IssuedAt.Equal(tt.input.IssuedAt) {
				t.Errorf("IssuedAt: got %v, want %v", got.IssuedAt, tt.input.IssuedAt)
			}
			if !got.ExpiresAt.Equal(tt.input.ExpiresAt) {
				t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, tt.input.ExpiresAt)
			}
		})
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Seed: two server certs, one client cert, one expired server cert.
	certs := []cert.IssuedCert{
		makeIssuedCert("s1", cert.TypeServer, "svc1.lab", false),
		makeIssuedCert("s2", cert.TypeServer, "svc2.lab", false),
		makeIssuedCert("c1", cert.TypeClient, "alice", false),
		makeIssuedCert("s3-expired", cert.TypeServer, "old.lab", true),
	}
	for _, c := range certs {
		if err := s.Save(ctx, c); err != nil {
			t.Fatalf("Save %s: %v", c.Serial, err)
		}
	}

	tests := []struct {
		name      string
		filter    cert.ListFilter
		wantCount int
	}{
		{
			name:      "no filter returns non-expired certs",
			filter:    cert.ListFilter{},
			wantCount: 3,
		},
		{
			name:      "include expired returns all",
			filter:    cert.ListFilter{IncludeExpired: true},
			wantCount: 4,
		},
		{
			name: "type=server excludes client",
			filter: cert.ListFilter{
				Type: certTypePtr(cert.TypeServer),
			},
			wantCount: 2,
		},
		{
			name: "type=client returns one",
			filter: cert.ListFilter{
				Type: certTypePtr(cert.TypeClient),
			},
			wantCount: 1,
		},
		{
			name: "type=server with expired",
			filter: cert.ListFilter{
				Type:           certTypePtr(cert.TypeServer),
				IncludeExpired: true,
			},
			wantCount: 3,
		},
		{
			name:      "limit=1 returns one result",
			filter:    cert.ListFilter{Limit: 1},
			wantCount: 1,
		},
		{
			name:      "offset beyond results returns empty",
			filter:    cert.ListFilter{Offset: 100},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := s.List(ctx, tt.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(results) != tt.wantCount {
				t.Errorf("got %d results, want %d", len(results), tt.wantCount)
			}
		})
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetActiveByCN(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	active := makeIssuedCert("active1", cert.TypeServer, "svc.lab", false)
	expired := makeIssuedCert("expired1", cert.TypeServer, "svc.lab", true)
	clientCert := makeIssuedCert("client1", cert.TypeClient, "svc.lab", false)

	for _, c := range []cert.IssuedCert{active, expired, clientCert} {
		if err := s.Save(ctx, c); err != nil {
			t.Fatalf("Save %s: %v", c.Serial, err)
		}
	}

	tests := []struct {
		name      string
		certType  cert.CertType
		cn        string
		wantFound bool
		wantSerial string
	}{
		{
			name:       "finds active server cert",
			certType:   cert.TypeServer,
			cn:         "svc.lab",
			wantFound:  true,
			wantSerial: "active1",
		},
		{
			name:      "does not find expired cert",
			certType:  cert.TypeServer,
			cn:        "old.lab",
			wantFound: false,
		},
		{
			name:       "finds client cert separately from server cert",
			certType:   cert.TypeClient,
			cn:         "svc.lab",
			wantFound:  true,
			wantSerial: "client1",
		},
		{
			name:      "returns not found for unknown CN",
			certType:  cert.TypeServer,
			cn:        "unknown.lab",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.GetActiveByCN(ctx, tt.certType, tt.cn)
			if tt.wantFound {
				if err != nil {
					t.Fatalf("GetActiveByCN: unexpected error: %v", err)
				}
				if got.Serial != tt.wantSerial {
					t.Errorf("Serial: got %q, want %q", got.Serial, tt.wantSerial)
				}
				if got.PrivateKeyPEM == "" {
					t.Error("PrivateKeyPEM should not be empty")
				}
			} else {
				if err == nil {
					t.Fatalf("expected error, got cert with serial %q", got.Serial)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	tests := []struct {
		name      string
		serial    string
		seed      bool // whether to seed the cert before deleting
		wantErr   bool
	}{
		{
			name:    "deletes existing certificate",
			serial:  "del1",
			seed:    true,
			wantErr: false,
		},
		{
			name:    "returns ErrNotFound for unknown serial",
			serial:  "nope",
			seed:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()

			if tt.seed {
				c := makeIssuedCert(tt.serial, cert.TypeServer, "svc.lab", false)
				if err := s.Save(ctx, c); err != nil {
					t.Fatalf("Save: %v", err)
				}
			}

			err := s.Delete(ctx, tt.serial)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Delete: %v", err)
			}

			// Verify the record is gone.
			if _, err := s.Get(ctx, tt.serial); err == nil {
				t.Error("expected ErrNotFound after delete, got nil")
			}
		})
	}
}

func certTypePtr(ct cert.CertType) *cert.CertType {
	return &ct
}
