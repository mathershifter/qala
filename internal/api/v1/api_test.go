package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockCertService struct {
	issueServer func(ctx context.Context, req cert.ServerRequest) (cert.IssuedCert, error)
	issueClient func(ctx context.Context, req cert.ClientRequest) (cert.IssuedCert, error)
	list        func(ctx context.Context, filter cert.ListFilter) ([]cert.Summary, error)
	get         func(ctx context.Context, serial string) (cert.IssuedCert, error)
	getByCN     func(ctx context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error)
	delete      func(ctx context.Context, serial string) error
}

func (m *mockCertService) IssueServer(ctx context.Context, req cert.ServerRequest) (cert.IssuedCert, error) {
	return m.issueServer(ctx, req)
}

func (m *mockCertService) IssueClient(ctx context.Context, req cert.ClientRequest) (cert.IssuedCert, error) {
	return m.issueClient(ctx, req)
}

func (m *mockCertService) List(ctx context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
	return m.list(ctx, filter)
}

func (m *mockCertService) Get(ctx context.Context, serial string) (cert.IssuedCert, error) {
	return m.get(ctx, serial)
}

func (m *mockCertService) GetByCN(ctx context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error) {
	return m.getByCN(ctx, certType, cn)
}

func (m *mockCertService) Delete(ctx context.Context, serial string) error {
	return m.delete(ctx, serial)
}

type mockCAChainer struct {
	chainPEM string
}

func (m *mockCAChainer) ChainPEM() string {
	return m.chainPEM
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

var (
	testNow        = time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	testExpires    = time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	testChainPEM   = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"
	testCertPEM    = "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
	testSerial     = "0a1b2c3d"
	testCommonName = "example.com"
)

// newTestServer builds a handler wired to the provided mocks.
func newTestServer(svc CertService, ca CAChainer) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewCertsService(svc, ca, logger)
	return HandlerWithOptions(server, StdHTTPServerOptions{
		ErrorHandlerFunc: JSONErrorHandler,
	})
}

// defaultCA returns a simple mock CAChainer.
func defaultCA() *mockCAChainer {
	return &mockCAChainer{chainPEM: testChainPEM}
}

// sampleIssuedCert returns a populated IssuedCert for reuse in tests.
func sampleIssuedCert(certType cert.CertType) cert.IssuedCert {
	return cert.IssuedCert{
		Serial:         testSerial,
		Type:           certType,
		CommonName:     testCommonName,
		CertificatePEM: testCertPEM,
		PrivateKeyPEM:  "-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----",
		ChainPEM:       testChainPEM,
		IssuedAt:       testNow,
		ExpiresAt:      testExpires,
	}
}

// do fires an HTTP request against the handler and returns the recorded response.
func do(t *testing.T, h http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// decodeJSON is a helper that unmarshals the response body into v.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(v); err != nil {
		t.Fatalf("failed to decode response body: %v\nbody was: %s", err, rr.Body.String())
	}
}

// jsonBody marshals v to an io.Reader suitable for a request body.
func jsonBody(t *testing.T, v any) io.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	return bytes.NewReader(b)
}

// assertStatus fails the test if the response code does not match want.
func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Errorf("expected status %d, got %d; body: %s", want, rr.Code, rr.Body.String())
	}
}

func assertJSONError(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] == "" {
		t.Errorf("expected non-empty error field in JSON body, got %v", body)
	}
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

func TestGetHealth(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodGet, "/health", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp HealthResponse
	decodeJSON(t, rr, &resp)

	if resp.Status == nil {
		t.Fatal("expected status field, got nil")
	}
	if *resp.Status != Ok {
		t.Errorf("expected status %q, got %q", Ok, *resp.Status)
	}
}

// ---------------------------------------------------------------------------
// GET /ca-chain
// ---------------------------------------------------------------------------

func TestGetCAChain(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodGet, "/ca-chain", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp CAChainResponse
	decodeJSON(t, rr, &resp)

	if resp.ChainPem == nil {
		t.Fatal("expected chain_pem field, got nil")
	}
	if *resp.ChainPem != testChainPEM {
		t.Errorf("expected chain_pem %q, got %q", testChainPEM, *resp.ChainPem)
	}
}

// ---------------------------------------------------------------------------
// POST /sign/server
// ---------------------------------------------------------------------------

func TestSignServer_HappyPath(t *testing.T) {
	issued := sampleIssuedCert(cert.TypeServer)
	svc := &mockCertService{
		issueServer: func(_ context.Context, req cert.ServerRequest) (cert.IssuedCert, error) {
			if req.CommonName != testCommonName {
				t.Errorf("expected CommonName %q, got %q", testCommonName, req.CommonName)
			}
			return issued, nil
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{
		"common_name": testCommonName,
		"dns_names":   []string{"example.com"},
	})
	rr := do(t, h, http.MethodPost, "/sign/server", body)

	assertStatus(t, rr, http.StatusCreated)

	var resp IssuedCertStored
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != testSerial {
		t.Errorf("expected serial %q, got %v", testSerial, resp.Serial)
	}
	if resp.CommonName == nil || *resp.CommonName != testCommonName {
		t.Errorf("expected common_name %q, got %v", testCommonName, resp.CommonName)
	}
	if resp.Type == nil || *resp.Type != Server {
		t.Errorf("expected type %q, got %v", Server, resp.Type)
	}
	if resp.CertificatePem == nil || *resp.CertificatePem != testCertPEM {
		t.Errorf("expected certificate_pem %q, got %v", testCertPEM, resp.CertificatePem)
	}
	if resp.ChainPem == nil || *resp.ChainPem != testChainPEM {
		t.Errorf("expected chain_pem %q, got %v", testChainPEM, resp.ChainPem)
	}
}

func TestSignServer_InvalidJSON(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodPost, "/sign/server", strings.NewReader("not-json{{{"))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestSignServer_CNConflict(t *testing.T) {
	conflictErr := &cert.CNConflictError{CommonName: testCommonName, Serial: testSerial}
	svc := &mockCertService{
		issueServer: func(_ context.Context, _ cert.ServerRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, conflictErr
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": testCommonName, "dns_names": []string{"example.com"}})
	rr := do(t, h, http.MethodPost, "/sign/server", body)

	assertStatus(t, rr, http.StatusConflict)

	var resp ConflictResponse
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != testSerial {
		t.Errorf("expected serial %q in conflict response, got %v", testSerial, resp.Serial)
	}
	if resp.Error == nil || *resp.Error == "" {
		t.Errorf("expected non-empty error field in conflict response")
	}
}

func TestSignServer_InvalidRequest(t *testing.T) {
	svc := &mockCertService{
		issueServer: func(_ context.Context, _ cert.ServerRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, fmt.Errorf("dns_names required: %w", cert.ErrInvalidRequest)
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": testCommonName})
	rr := do(t, h, http.MethodPost, "/sign/server", body)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestSignServer_ServiceError(t *testing.T) {
	svc := &mockCertService{
		issueServer: func(_ context.Context, _ cert.ServerRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, errors.New("unexpected storage failure")
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": testCommonName, "dns_names": []string{"example.com"}})
	rr := do(t, h, http.MethodPost, "/sign/server", body)
	assertStatus(t, rr, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// POST /sign/client
// ---------------------------------------------------------------------------

func TestSignClient_HappyPath(t *testing.T) {
	issued := sampleIssuedCert(cert.TypeClient)
	svc := &mockCertService{
		issueClient: func(_ context.Context, req cert.ClientRequest) (cert.IssuedCert, error) {
			if req.CommonName != testCommonName {
				t.Errorf("expected CommonName %q, got %q", testCommonName, req.CommonName)
			}
			return issued, nil
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": testCommonName})
	rr := do(t, h, http.MethodPost, "/sign/client", body)

	assertStatus(t, rr, http.StatusCreated)

	var resp IssuedCertStored
	decodeJSON(t, rr, &resp)

	if resp.Type == nil || *resp.Type != Client {
		t.Errorf("expected type %q, got %v", Client, resp.Type)
	}
	if resp.Serial == nil || *resp.Serial != testSerial {
		t.Errorf("expected serial %q, got %v", testSerial, resp.Serial)
	}
}

func TestSignClient_InvalidJSON(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodPost, "/sign/client", strings.NewReader("{bad"))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestSignClient_CNConflict(t *testing.T) {
	conflictErr := &cert.CNConflictError{CommonName: "alice", Serial: "deadbeef"}
	svc := &mockCertService{
		issueClient: func(_ context.Context, _ cert.ClientRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, conflictErr
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": "alice"})
	rr := do(t, h, http.MethodPost, "/sign/client", body)

	assertStatus(t, rr, http.StatusConflict)

	var resp ConflictResponse
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != "deadbeef" {
		t.Errorf("expected serial %q, got %v", "deadbeef", resp.Serial)
	}
}

func TestSignClient_InvalidRequest(t *testing.T) {
	svc := &mockCertService{
		issueClient: func(_ context.Context, _ cert.ClientRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, fmt.Errorf("validity_days out of range: %w", cert.ErrInvalidRequest)
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": testCommonName})
	rr := do(t, h, http.MethodPost, "/sign/client", body)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestSignClient_ServiceError(t *testing.T) {
	svc := &mockCertService{
		issueClient: func(_ context.Context, _ cert.ClientRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, errors.New("disk full")
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": testCommonName})
	rr := do(t, h, http.MethodPost, "/sign/client", body)
	assertStatus(t, rr, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// GET /certs
// ---------------------------------------------------------------------------

func TestListCerts_HappyPath(t *testing.T) {
	summaries := []cert.Summary{
		{
			Serial:     testSerial,
			Type:       cert.TypeServer,
			CommonName: testCommonName,
			IssuedAt:   testNow,
			ExpiresAt:  testExpires,
		},
	}
	svc := &mockCertService{
		list: func(_ context.Context, _ cert.ListFilter) ([]cert.Summary, error) {
			return summaries, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp CertListResponse
	decodeJSON(t, rr, &resp)

	if resp.Total == nil {
		t.Fatal("expected total field, got nil")
	}
	if *resp.Total != 1 {
		t.Errorf("expected total=1, got %d", *resp.Total)
	}
	if resp.Certs == nil || len(*resp.Certs) != 1 {
		t.Fatalf("expected 1 cert in list, got %v", resp.Certs)
	}
	s := (*resp.Certs)[0]
	if s.Serial == nil || *s.Serial != testSerial {
		t.Errorf("expected serial %q, got %v", testSerial, s.Serial)
	}
	if s.Type == nil || *s.Type != Server {
		t.Errorf("expected type %q, got %v", Server, s.Type)
	}
}

func TestListCerts_EmptyList(t *testing.T) {
	svc := &mockCertService{
		list: func(_ context.Context, _ cert.ListFilter) ([]cert.Summary, error) {
			return []cert.Summary{}, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp CertListResponse
	decodeJSON(t, rr, &resp)

	if resp.Total == nil || *resp.Total != 0 {
		t.Errorf("expected total=0, got %v", resp.Total)
	}
}

func TestListCerts_TypeFilter(t *testing.T) {
	var capturedFilter cert.ListFilter
	svc := &mockCertService{
		list: func(_ context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
			capturedFilter = filter
			return []cert.Summary{}, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs?type=server", nil)

	assertStatus(t, rr, http.StatusOK)

	if capturedFilter.Type == nil {
		t.Fatal("expected Type filter to be set, got nil")
	}
	if *capturedFilter.Type != cert.TypeServer {
		t.Errorf("expected filter type %q, got %q", cert.TypeServer, *capturedFilter.Type)
	}
}

func TestListCerts_ExpiredFilter(t *testing.T) {
	var capturedFilter cert.ListFilter
	svc := &mockCertService{
		list: func(_ context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
			capturedFilter = filter
			return []cert.Summary{}, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs?expired=true", nil)

	assertStatus(t, rr, http.StatusOK)

	if !capturedFilter.IncludeExpired {
		t.Errorf("expected IncludeExpired=true, got false")
	}
}

func TestListCerts_ServiceError(t *testing.T) {
	svc := &mockCertService{
		list: func(_ context.Context, _ cert.ListFilter) ([]cert.Summary, error) {
			return nil, errors.New("database unavailable")
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs", nil)
	assertStatus(t, rr, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// GET /certs/by-cn
// ---------------------------------------------------------------------------

func TestGetCertByCN_HappyPath(t *testing.T) {
	issued := sampleIssuedCert(cert.TypeServer)
	svc := &mockCertService{
		getByCN: func(_ context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error) {
			if certType != cert.TypeServer {
				t.Errorf("expected type %q, got %q", cert.TypeServer, certType)
			}
			if cn != testCommonName {
				t.Errorf("expected cn %q, got %q", testCommonName, cn)
			}
			return issued, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/by-cn?type=server&cn="+testCommonName, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp IssuedCertStored
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != testSerial {
		t.Errorf("expected serial %q, got %v", testSerial, resp.Serial)
	}
	if resp.Type == nil || *resp.Type != Server {
		t.Errorf("expected type %q, got %v", Server, resp.Type)
	}
}

func TestGetCertByCN_MissingType(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/by-cn?cn="+testCommonName, nil)
	assertStatus(t, rr, http.StatusBadRequest)
	assertJSONError(t, rr)
}

func TestGetCertByCN_MissingCN(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/by-cn?type=server", nil)
	assertStatus(t, rr, http.StatusBadRequest)
	assertJSONError(t, rr)
}

func TestGetCertByCN_InvalidType(t *testing.T) {
	h := newTestServer(&mockCertService{}, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/by-cn?type=invalid&cn=foo", nil)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestGetCertByCN_NotFound(t *testing.T) {
	svc := &mockCertService{
		getByCN: func(_ context.Context, _ cert.CertType, _ string) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, cert.ErrNotFound
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/by-cn?type=server&cn=nobody", nil)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestGetCertByCN_ClientType(t *testing.T) {
	issued := sampleIssuedCert(cert.TypeClient)
	svc := &mockCertService{
		getByCN: func(_ context.Context, certType cert.CertType, _ string) (cert.IssuedCert, error) {
			if certType != cert.TypeClient {
				t.Errorf("expected type %q, got %q", cert.TypeClient, certType)
			}
			return issued, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/by-cn?type=client&cn=alice", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp IssuedCertStored
	decodeJSON(t, rr, &resp)

	if resp.Type == nil || *resp.Type != Client {
		t.Errorf("expected type %q, got %v", Client, resp.Type)
	}
}

// ---------------------------------------------------------------------------
// GET /certs/{serial}
// ---------------------------------------------------------------------------

func TestGetCert_HappyPath(t *testing.T) {
	issued := sampleIssuedCert(cert.TypeServer)
	svc := &mockCertService{
		get: func(_ context.Context, serial string) (cert.IssuedCert, error) {
			if serial != testSerial {
				t.Errorf("expected serial %q, got %q", testSerial, serial)
			}
			return issued, nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/"+testSerial, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp IssuedCertStored
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != testSerial {
		t.Errorf("expected serial %q, got %v", testSerial, resp.Serial)
	}
	if resp.CertificatePem == nil || *resp.CertificatePem != testCertPEM {
		t.Errorf("expected certificate_pem %q, got %v", testCertPEM, resp.CertificatePem)
	}
	if resp.ChainPem == nil || *resp.ChainPem != testChainPEM {
		t.Errorf("expected chain_pem %q, got %v", testChainPEM, resp.ChainPem)
	}
	if resp.IssuedAt == nil || !resp.IssuedAt.Equal(testNow) {
		t.Errorf("expected issued_at %v, got %v", testNow, resp.IssuedAt)
	}
	if resp.ExpiresAt == nil || !resp.ExpiresAt.Equal(testExpires) {
		t.Errorf("expected expires_at %v, got %v", testExpires, resp.ExpiresAt)
	}
}

func TestGetCert_NotFound(t *testing.T) {
	svc := &mockCertService{
		get: func(_ context.Context, _ string) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, cert.ErrNotFound
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/nonexistent", nil)
	assertStatus(t, rr, http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// DELETE /certs/{serial}
// ---------------------------------------------------------------------------

func TestDeleteCert_HappyPath(t *testing.T) {
	svc := &mockCertService{
		delete: func(_ context.Context, serial string) error {
			if serial != testSerial {
				t.Errorf("expected serial %q, got %q", testSerial, serial)
			}
			return nil
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodDelete, "/certs/"+testSerial, nil)
	assertStatus(t, rr, http.StatusNoContent)
}

func TestDeleteCert_NotFound(t *testing.T) {
	svc := &mockCertService{
		delete: func(_ context.Context, _ string) error {
			return cert.ErrNotFound
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodDelete, "/certs/nonexistent", nil)
	assertStatus(t, rr, http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// Content-Type header checks
// ---------------------------------------------------------------------------

func TestResponsesHaveJSONContentType(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   io.Reader
		setup  func() CertService
	}{
		{
			name:   "health",
			method: http.MethodGet,
			path:   "/health",
			setup:  func() CertService { return &mockCertService{} },
		},
		{
			name:   "ca-chain",
			method: http.MethodGet,
			path:   "/ca-chain",
			setup:  func() CertService { return &mockCertService{} },
		},
		{
			name:   "list certs",
			method: http.MethodGet,
			path:   "/certs",
			setup: func() CertService {
				return &mockCertService{
					list: func(_ context.Context, _ cert.ListFilter) ([]cert.Summary, error) {
						return nil, nil
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestServer(tc.setup(), defaultCA())
			rr := do(t, h, tc.method, tc.path, tc.body)
			ct := rr.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				t.Errorf("expected Content-Type application/json, got %q", ct)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error response shape checks
// ---------------------------------------------------------------------------

func TestErrorResponseShape_NotFound(t *testing.T) {
	svc := &mockCertService{
		get: func(_ context.Context, _ string) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, cert.ErrNotFound
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/missing", nil)

	assertStatus(t, rr, http.StatusNotFound)

	var resp ErrorResponse
	decodeJSON(t, rr, &resp)

	if resp.Error == nil || *resp.Error == "" {
		t.Errorf("expected non-empty error field in 404 response")
	}
}

func TestErrorResponseShape_InternalError(t *testing.T) {
	svc := &mockCertService{
		get: func(_ context.Context, _ string) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, errors.New("boom")
		},
	}
	h := newTestServer(svc, defaultCA())
	rr := do(t, h, http.MethodGet, "/certs/any", nil)

	assertStatus(t, rr, http.StatusInternalServerError)

	var resp ErrorResponse
	decodeJSON(t, rr, &resp)

	if resp.Error == nil || *resp.Error == "" {
		t.Errorf("expected non-empty error field in 500 response")
	}
}

// ---------------------------------------------------------------------------
// Conflict response carries serial
// ---------------------------------------------------------------------------

func TestConflictResponseCarriesSerial(t *testing.T) {
	wantSerial := "cafebabe"
	svc := &mockCertService{
		issueServer: func(_ context.Context, _ cert.ServerRequest) (cert.IssuedCert, error) {
			return cert.IssuedCert{}, &cert.CNConflictError{CommonName: "web.internal", Serial: wantSerial}
		},
	}
	h := newTestServer(svc, defaultCA())

	body := jsonBody(t, map[string]any{"common_name": "web.internal", "dns_names": []string{"web.internal"}})
	rr := do(t, h, http.MethodPost, "/sign/server", body)

	assertStatus(t, rr, http.StatusConflict)

	var resp ConflictResponse
	decodeJSON(t, rr, &resp)

	if resp.Serial == nil || *resp.Serial != wantSerial {
		t.Errorf("expected serial %q in conflict response, got %v", wantSerial, resp.Serial)
	}
}
