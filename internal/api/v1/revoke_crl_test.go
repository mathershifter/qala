package v1

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// ---------------------------------------------------------------------------
// POST /certs/{serial}/revoke
// ---------------------------------------------------------------------------

func TestRevokeCert_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fullSvc := &fullMockCertService{
		revokeFn: func(ctx context.Context, serial string, reason string) (cert.Summary, error) {
			return cert.Summary{
				Serial:           serial,
				RevokedAt:        now,
				RevocationReason: reason,
			}, nil
		},
	}

	h := newTestServer(fullSvc, defaultCA(), defaultCRL())

	body := jsonBody(t, map[string]any{"reason": "keyCompromise"})
	rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", body)

	assertStatus(t, rr, http.StatusOK)

	var resp RevokeResponse
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != testSerial {
		t.Errorf("expected serial %q, got %v", testSerial, resp.Serial)
	}
	if resp.Reason == nil || *resp.Reason != RevocationReason("keyCompromise") {
		t.Errorf("expected reason keyCompromise, got %v", resp.Reason)
	}
}

func TestRevokeCert_EmptyBodyDefaultsToUnspecified(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fullSvc := &fullMockCertService{
		revokeFn: func(ctx context.Context, serial string, reason string) (cert.Summary, error) {
			return cert.Summary{
				Serial:           serial,
				RevokedAt:        now,
				RevocationReason: reason,
			}, nil
		},
	}

	h := newTestServer(fullSvc, defaultCA(), defaultCRL())

	// Empty body — JSON decode of {} gives empty Reason, which defaults to unspecified.
	rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", bytes.NewReader([]byte(`{}`)))

	assertStatus(t, rr, http.StatusOK)
}

func TestRevokeCert_InvalidReason(t *testing.T) {
	h := newTestServer(&fullMockCertService{}, defaultCA(), defaultCRL())

	body := jsonBody(t, map[string]any{"reason": "notARealReason"})
	rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", body)

	assertStatus(t, rr, http.StatusBadRequest)
	assertJSONError(t, rr)
}

func TestRevokeCert_AllValidReasons(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{"unspecified", "unspecified"},
		{"keyCompromise", "keyCompromise"},
		{"affiliationChanged", "affiliationChanged"},
		{"superseded", "superseded"},
		{"cessationOfOperation", "cessationOfOperation"},
		{"certificateHold", "certificateHold"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now().UTC()
			fullSvc := &fullMockCertService{
				revokeFn: func(ctx context.Context, serial string, reason string) (cert.Summary, error) {
					return cert.Summary{
						Serial:           serial,
						RevokedAt:        now,
						RevocationReason: reason,
					}, nil
				},
			}
			h := newTestServer(fullSvc, defaultCA(), defaultCRL())

			body := jsonBody(t, map[string]any{"reason": tt.reason})
			rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", body)

			assertStatus(t, rr, http.StatusOK)
		})
	}
}

func TestRevokeCert_NotFound(t *testing.T) {
	fullSvc := &fullMockCertService{
		revokeFn: func(ctx context.Context, serial string, reason string) (cert.Summary, error) {
			return cert.Summary{}, cert.ErrNotFound
		},
	}
	h := newTestServer(fullSvc, defaultCA(), defaultCRL())

	body := jsonBody(t, map[string]any{"reason": "unspecified"})
	rr := do(t, h, http.MethodPost, "/certs/missing/revoke", body)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestRevokeCert_AlreadyRevoked(t *testing.T) {
	fullSvc := &fullMockCertService{
		revokeFn: func(ctx context.Context, serial string, reason string) (cert.Summary, error) {
			return cert.Summary{}, cert.ErrAlreadyRevoked
		},
	}
	h := newTestServer(fullSvc, defaultCA(), defaultCRL())

	body := jsonBody(t, map[string]any{"reason": "unspecified"})
	rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", body)
	assertStatus(t, rr, http.StatusConflict)
}

func TestRevokeCert_InvalidJSON(t *testing.T) {
	h := newTestServer(&fullMockCertService{}, defaultCA(), defaultCRL())

	// Send a body that is not valid JSON.
	rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", bytes.NewReader([]byte(`{not-json`)))
	assertStatus(t, rr, http.StatusBadRequest)
}

// ---------------------------------------------------------------------------
// GET /crl
// ---------------------------------------------------------------------------

func TestGetCRL_ReturnsDER(t *testing.T) {
	crlBytes := []byte{0x30, 0x82, 0x01, 0x00} // fake DER prefix
	cs := &mockCRLService{crl: crlBytes}
	h := newTestServer(&mockCertService{}, defaultCA(), cs)

	rr := do(t, h, http.MethodGet, "/crl", nil)

	assertStatus(t, rr, http.StatusOK)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/pkix-crl" {
		t.Errorf("expected Content-Type application/pkix-crl, got %q", ct)
	}

	body := rr.Body.Bytes()
	if len(body) != len(crlBytes) {
		t.Errorf("expected %d bytes, got %d", len(crlBytes), len(body))
	}
	for i, b := range crlBytes {
		if body[i] != b {
			t.Errorf("body[%d]: got %x, want %x", i, body[i], b)
		}
	}
}

func TestGetCRL_EmptyDER(t *testing.T) {
	cs := &mockCRLService{crl: []byte{}}
	h := newTestServer(&mockCertService{}, defaultCA(), cs)

	rr := do(t, h, http.MethodGet, "/crl", nil)
	assertStatus(t, rr, http.StatusOK)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/pkix-crl" {
		t.Errorf("expected Content-Type application/pkix-crl, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// GET /crl.pem
// ---------------------------------------------------------------------------

func TestGetCRLPEM_ReturnsPEM(t *testing.T) {
	// Use a non-empty DER payload so pem.Encode has something to work with.
	crlBytes := []byte("fake-der-content")
	cs := &mockCRLService{crl: crlBytes}
	h := newTestServer(&mockCertService{}, defaultCA(), cs)

	rr := do(t, h, http.MethodGet, "/crl.pem", nil)

	assertStatus(t, rr, http.StatusOK)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/x-pem-file" {
		t.Errorf("expected Content-Type application/x-pem-file, got %q", ct)
	}

	bodyStr := rr.Body.String()
	if len(bodyStr) == 0 {
		t.Error("expected non-empty PEM body")
	}
	// PEM encoding should include the header/footer.
	if !contains(bodyStr, "-----BEGIN X509 CRL-----") {
		t.Errorf("expected PEM header in body, got: %s", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// handleServiceError — uncovered branches
// ---------------------------------------------------------------------------

func TestHandleServiceError_ErrUnknownReason(t *testing.T) {
	fullSvc := &fullMockCertService{
		revokeFn: func(ctx context.Context, serial string, reason string) (cert.Summary, error) {
			return cert.Summary{}, cert.ErrUnknownReason
		},
	}
	h := newTestServer(fullSvc, defaultCA(), defaultCRL())

	body := jsonBody(t, map[string]any{"reason": "unspecified"})
	rr := do(t, h, http.MethodPost, "/certs/"+testSerial+"/revoke", body)
	assertStatus(t, rr, http.StatusBadRequest)
}

// ---------------------------------------------------------------------------
// ListCerts — revoked filter
// ---------------------------------------------------------------------------

func TestListCerts_RevokedFilter(t *testing.T) {
	var capturedFilter cert.ListFilter
	svc := &mockCertService{
		list: func(_ context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
			capturedFilter = filter
			return []cert.Summary{}, nil
		},
	}
	h := newTestServer(svc, defaultCA(), defaultCRL())
	rr := do(t, h, http.MethodGet, "/certs?revoked=true", nil)

	assertStatus(t, rr, http.StatusOK)

	if !capturedFilter.Revoked {
		t.Errorf("expected Revoked=true, got false")
	}
}

func TestListCerts_LimitAndOffset(t *testing.T) {
	var capturedFilter cert.ListFilter
	svc := &mockCertService{
		list: func(_ context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
			capturedFilter = filter
			return []cert.Summary{}, nil
		},
	}
	h := newTestServer(svc, defaultCA(), defaultCRL())
	rr := do(t, h, http.MethodGet, "/certs?limit=10&offset=5", nil)

	assertStatus(t, rr, http.StatusOK)

	if capturedFilter.Limit != 10 {
		t.Errorf("expected limit=10, got %d", capturedFilter.Limit)
	}
	if capturedFilter.Offset != 5 {
		t.Errorf("expected offset=5, got %d", capturedFilter.Offset)
	}
}

func TestListCerts_ClientTypeFilter(t *testing.T) {
	var capturedFilter cert.ListFilter
	svc := &mockCertService{
		list: func(_ context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
			capturedFilter = filter
			return []cert.Summary{}, nil
		},
	}
	h := newTestServer(svc, defaultCA(), defaultCRL())
	rr := do(t, h, http.MethodGet, "/certs?type=client", nil)

	assertStatus(t, rr, http.StatusOK)

	if capturedFilter.Type == nil {
		t.Fatal("expected Type filter to be set, got nil")
	}
	if *capturedFilter.Type != cert.TypeClient {
		t.Errorf("expected filter type %q, got %q", cert.TypeClient, *capturedFilter.Type)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// fullMockCertService provides a complete CertService implementation where
// only the revokeFn is typically populated; other methods return zero values.
type fullMockCertService struct {
	revokeFn func(ctx context.Context, serial string, reason string) (cert.Summary, error)
}

func (f *fullMockCertService) IssueServer(ctx context.Context, req cert.ServerRequest) (cert.IssuedCert, error) {
	return cert.IssuedCert{}, errors.New("not implemented")
}

func (f *fullMockCertService) IssueClient(ctx context.Context, req cert.ClientRequest) (cert.IssuedCert, error) {
	return cert.IssuedCert{}, errors.New("not implemented")
}

func (f *fullMockCertService) List(ctx context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
	return nil, errors.New("not implemented")
}

func (f *fullMockCertService) Get(ctx context.Context, serial string) (cert.IssuedCert, error) {
	return cert.IssuedCert{}, errors.New("not implemented")
}

func (f *fullMockCertService) GetByCN(ctx context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error) {
	return cert.IssuedCert{}, errors.New("not implemented")
}

func (f *fullMockCertService) Delete(ctx context.Context, serial string) error {
	return errors.New("not implemented")
}

func (f *fullMockCertService) Revoke(ctx context.Context, serial string, reason string) (cert.Summary, error) {
	if f.revokeFn != nil {
		return f.revokeFn(ctx, serial, reason)
	}
	return cert.Summary{}, errors.New("not implemented")
}

