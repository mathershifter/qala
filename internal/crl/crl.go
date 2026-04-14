package crl

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	crlFile = "crl.pem"
)

type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
)

func (rr RevocationReason) String() string {
	switch rr {
	case ReasonKeyCompromise:
		return "keyCompromise"
	case ReasonAffiliationChanged:
		return "affiliationChanged"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ReasonCertificateHold:
		return "certificateHold"
	default:
		return "unspecified"
	}
}

func ReasonFromStr(r string) RevocationReason {
	switch r {
	case "keyCompromise":
		return ReasonKeyCompromise
	case "affiliationChanged":
		return ReasonAffiliationChanged
	case "superseded":
		return ReasonSuperseded
	case "cessationOfOperation":
		return ReasonCessationOfOperation
	case "certificateHold":
		return ReasonCertificateHold
	default:
		return ReasonUnspecified
	}
}

type Signer interface {
	SignCRL(*x509.RevocationList) (*x509.RevocationList, error)
	CheckSignatureWith(fn func(*x509.Certificate) error) error
}

type Service struct {
	mu      sync.RWMutex
	ca      Signer
	dataDir string
	crl     *x509.RevocationList
}

func LoadOrInitCRL(dataDir string, ca Signer) (*Service, error) {
	svc := &Service{ca: ca, dataDir: dataDir}
	err := svc.read(dataDir)
	if err != nil {
		template := &x509.RevocationList{
			Number:                    big.NewInt(1),
			ThisUpdate:                time.Now(),
			NextUpdate:                time.Now().Add(7 * 24 * time.Hour), // Valid for 1 week
			RevokedCertificateEntries: []x509.RevocationListEntry{},
		}
		crl, err := ca.SignCRL(template)
		if err != nil {
			return nil, err
		}
		svc.crl = crl
	}
	return svc, nil
}

func (s *Service) read(dataDir string) error {
	s.mu.RLock() // Multiple goroutines can read at once
	defer s.mu.RUnlock()
	data, err := os.ReadFile(filepath.Join(dataDir, crlFile))
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		return fmt.Errorf("failed to decode PEM block containing CRL: %#v", block.Type)
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse: %s", err.Error())
	}
	s.crl = crl
	return nil
}

func (s *Service) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.crl == nil {
		return fmt.Errorf("crl is not loaded")
	}
	return os.WriteFile(filepath.Join(s.dataDir, crlFile), s.crl.Raw, 0644)
}

func (s *Service) revoke(serial string, revokeAt time.Time, reasonCode int) error {
	if s.crl == nil {
		return fmt.Errorf("crl is not loaded")
	}

	ser, err := strconv.ParseInt(serial, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid serial %s, must be numeric", serial)
	}
	s.crl.RevokedCertificateEntries = append(s.crl.RevokedCertificateEntries, x509.RevocationListEntry{
		SerialNumber:   big.NewInt(ser),
		RevocationTime: revokeAt,
		ReasonCode:     reasonCode,
	})

	signed, err := s.ca.SignCRL(s.crl)
	if err != nil {
		return err
	}
	s.crl = signed
	return s.save()
}

func (s *Service) CurrentCRL() []byte {
	if s.crl == nil {
		return []byte{}
	}
	return s.crl.Raw
}

func (s *Service) Revoke(serial string, revokedAt time.Time, reason string) {
	s.revoke(serial, revokedAt, int(ReasonFromStr(reason)))
}

func (s *Service) Check() error {
	return s.ca.CheckSignatureWith(func(parent *x509.Certificate) error {
		return s.crl.CheckSignatureFrom(parent)
	})
}

func (s *Service) List() []x509.RevocationListEntry {
	if s.crl == nil {
		return []x509.RevocationListEntry{}
	}

	return s.crl.RevokedCertificateEntries
}
