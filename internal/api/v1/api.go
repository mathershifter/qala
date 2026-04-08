package v1

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../api/v1/openapi.yaml

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"gitlab.aristanetworks.com/jmather/seacrt/internal/cert"
)

// CertService is the interface the Server requires for certificate operations.
type CertService interface {
	IssueServer(ctx context.Context, req cert.ServerRequest) (cert.IssuedCert, error)
	IssueClient(ctx context.Context, req cert.ClientRequest) (cert.IssuedCert, error)
	List(ctx context.Context, filter cert.ListFilter) ([]cert.Summary, error)
	Get(ctx context.Context, serial string) (cert.IssuedCert, error)
	GetByCN(ctx context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error)
	Delete(ctx context.Context, serial string) error
}

// CAChainer provides the CA certificate chain PEM for the /ca-chain endpoint.
type CAChainer interface {
	ChainPEM() string
}

var _ ServerInterface = (*CertsServer)(nil)

// Server holds the HTTP handler dependencies.
type CertsServer struct {
	certs  CertService
	ca     CAChainer
	logger *slog.Logger
}

// NewServer constructs a Server.
func NewCertsService(svc CertService, ca CAChainer, logger *slog.Logger) *CertsServer {
	return &CertsServer{certs: svc, ca: ca, logger: logger}
}

// Retrieve the CA certificate chain
// (GET /ca-chain)
func (s *CertsServer) GetCAChain(w http.ResponseWriter, r *http.Request) {
	cp := s.ca.ChainPEM()
	resp := CAChainResponse{
		ChainPem: &cp,
	}
	writeJSON(w, http.StatusOK, resp)
}

// List issued certificates
// (GET /certs)
func (s *CertsServer) ListCerts(w http.ResponseWriter, r *http.Request, params ListCertsParams) {
	limit := 100
	offset := 0
	expired := false

	if params.Limit != nil {
		if *params.Limit > 0 {
			limit = *params.Limit
		}
	}

	if params.Offset != nil {
		offset = max(*params.Offset, offset)
	}

	if params.Expired != nil {
		expired = *params.Expired
	}

	filter := cert.ListFilter{
		IncludeExpired: expired,
		Limit:          limit,
		Offset:         offset,
	}

	if t := params.Type; t != nil && *t != "" {
		ct := cert.CertType(*t)
		filter.Type = &ct
	}

	res, err := s.certs.List(r.Context(), filter)
	if err != nil {
		s.handleServiceError(w, err)
		return
	}
	cl := make([]Summary, len(res))
	for i, cert := range res {
		cl[i] = Summary{
			CommonName: &cert.CommonName,
			ExpiresAt:  &cert.ExpiresAt,
			IssuedAt:   &cert.IssuedAt,
			Serial:     &cert.Serial,
			Type:       new(CertType(cert.Type)),
		}
	}
	writeJSON(w, http.StatusOK, CertListResponse{
		Certs: &cl,
		Total: new(len(cl)),
	})
}

// Look up a certificate by common name
// (GET /certs/by-cn)
func (s *CertsServer) GetCertByCN(w http.ResponseWriter, r *http.Request, params GetCertByCNParams) {
	certType := cert.CertType(params.Type)

	if certType != cert.TypeServer && certType != cert.TypeClient {
		writeError(w, http.StatusBadRequest, `type must be "server" or "client"`)
		return
	}

	c, err := s.certs.GetByCN(r.Context(), cert.CertType(params.Type), params.Cn)
	if err != nil {
		s.handleServiceError(w, err)
		return
	}

	resp := IssuedCertStored{
		CertificatePem: &c.CertificatePEM,
		ChainPem:       new(s.ca.ChainPEM()),
		CommonName:     &c.CommonName,
		ExpiresAt:      &c.ExpiresAt,
		IssuedAt:       &c.IssuedAt,
		Serial:         &c.Serial,
		Type:           new(CertType(c.Type)),
	}

	writeJSON(w, http.StatusOK, resp)
}

// Delete a certificate record
// (DELETE /certs/{serial})
func (s *CertsServer) DeleteCert(w http.ResponseWriter, r *http.Request, serial SerialPath) {
	if err := s.certs.Delete(r.Context(), serial); err != nil {
		s.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Get a certificate by serial number
// (GET /certs/{serial})
func (s *CertsServer) GetCert(w http.ResponseWriter, r *http.Request, serial SerialPath) {
	c, err := s.certs.Get(r.Context(), serial)
	if err != nil {
		s.handleServiceError(w, err)
		return
	}

	resp := IssuedCertStored{
		CertificatePem: &c.CertificatePEM,
		ChainPem:       &c.ChainPEM,
		CommonName:     &c.CommonName,
		ExpiresAt:      &c.ExpiresAt,
		IssuedAt:       &c.IssuedAt,
		Serial:         &c.Serial,
		Type:           new(CertType(c.Type)),
	}

	writeJSON(w, http.StatusOK, resp)
}

// Health check
// (GET /health)
func (s *CertsServer) GetHealth(w http.ResponseWriter, r *http.Request) {
	var status HealthResponseStatus = "ok"
	resp := &HealthResponse{
		Status: &status,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Issue a client authentication certificate
// (POST /sign/client)
func (s *CertsServer) SignClient(w http.ResponseWriter, r *http.Request) {
	var req cert.ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	issued, err := s.certs.IssueClient(r.Context(), req)
	if err != nil {
		s.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, &IssuedCertStored{
		CertificatePem: &issued.CertificatePEM,
		ChainPem:       new(s.ca.ChainPEM()),
		CommonName:     &issued.CommonName,
		PrivateKeyPem:  &issued.PrivateKeyPEM,
		ExpiresAt:      &issued.ExpiresAt,
		IssuedAt:       &issued.IssuedAt,
		Serial:         &issued.Serial,
		Type:           new(CertType(issued.Type)),
	})
}

// Issue a TLS server certificate
// (POST /sign/server)
func (s *CertsServer) SignServer(w http.ResponseWriter, r *http.Request) {
	var req cert.ServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	issued, err := s.certs.IssueServer(r.Context(), req)
	if err != nil {
		s.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, &IssuedCertStored{
		CertificatePem: &issued.CertificatePEM,
		PrivateKeyPem:  &issued.PrivateKeyPEM,
		ChainPem:       new(s.ca.ChainPEM()),
		CommonName:     &issued.CommonName,
		ExpiresAt:      &issued.ExpiresAt,
		IssuedAt:       &issued.IssuedAt,
		Serial:         &issued.Serial,
		Type:           new(CertType(issued.Type)),
	})
}

// --- helpers ---

// JSONErrorHandler is a StdHTTPServerOptions.ErrorHandlerFunc that writes
// parameter binding errors as JSON {"error":"..."} instead of plain text.
func JSONErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	writeError(w, http.StatusBadRequest, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *CertsServer) handleServiceError(w http.ResponseWriter, err error) {
	var conflict *cert.CNConflictError
	switch {
	case errors.As(err, &conflict):
		// e := err.Error()
		writeJSON(w, http.StatusConflict, ConflictResponse{
			Error:  new(err.Error()),
			Serial: &conflict.Serial,
		})
	case errors.Is(err, cert.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, cert.ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.logger.Error("internal error", slog.Any("err", err))
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
