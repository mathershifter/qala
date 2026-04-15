package cert

import (
	"errors"
	"time"
)

// KeyAlgorithm identifies the key algorithm for a certificate.
type KeyAlgorithm string

const (
	AlgorithmECDSA KeyAlgorithm = "ecdsa"
	AlgorithmRSA   KeyAlgorithm = "rsa"
)

// CertType distinguishes server from client certificates.
type CertType string

const (
	TypeServer CertType = "server"
	TypeClient CertType = "client"
)

type RevocationInfo struct {
	RevokedAt time.Time
	Reason    string
}

type RevokeRequest struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

type RevokeResponse struct {
	Serial    string
	RevokedAt time.Time
	Reason    string
}

// New sentinel errors
var ErrAlreadyRevoked = errors.New("certificate is already revoked")
var ErrUnknownReason = errors.New("unknown revocation reason")

// ServerRequest carries the parameters for issuing a TLS server certificate.
type ServerRequest struct {
	CommonName   string       `json:"common_name"`
	DNSNames     []string     `json:"dns_names"`
	IPAddresses  []string     `json:"ip_addresses"`
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm"`
	ValidityDays int          `json:"validity_days"`
}

// ClientRequest carries the parameters for issuing a client auth certificate.
type ClientRequest struct {
	CommonName   string       `json:"common_name"`
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm"`
	ValidityDays int          `json:"validity_days"`
}

// IssuedCert is the result of a successful certificate issuance.
// PrivateKeyPEM is returned exactly once at issuance and is never persisted.
type IssuedCert struct {
	Serial           string     `json:"serial"`
	Type             CertType   `json:"type"`
	CommonName       string     `json:"common_name"`
	CertificatePEM   string     `json:"certificate_pem"`
	PrivateKeyPEM    string     `json:"private_key_pem"`
	ChainPEM         string     `json:"chain_pem"`
	IssuedAt         time.Time  `json:"issued_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at"`
	RevocationReason string     `json:"revocation_reason"`
}

// Summary is the list-view projection of an issued certificate. No PEM fields.
type Summary struct {
	Serial           string    `json:"serial"`
	Type             CertType  `json:"type"`
	CommonName       string    `json:"common_name"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RevokedAt        time.Time `json:"revoked_at"`
	RevocationReason string    `json:"revocation_reason"`
}

// CertDefaults holds service-level defaults applied when per-request values are absent.
// Organization is added to the certificate Subject when non-empty.
// ValidityDays is used when the per-request ValidityDays is 0; if also 0, the built-in default (90) applies.
type CertDefaults struct {
	Organization string
	ValidityDays int
}

// ListFilter controls which certificates are returned by List.
type ListFilter struct {
	Type    *CertType
	All     bool
	Expired bool
	Revoked bool
	Limit   int
	Offset  int
}
