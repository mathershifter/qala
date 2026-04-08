package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitlab.aristanetworks.com/jmather/seacrt/internal/cert"
)

func newSignCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Issue a certificate",
	}
	cmd.AddCommand(newSignServerCmd(opts), newSignClientCmd(opts))
	return cmd
}

func newSignServerCmd(opts *rootOptions) *cobra.Command {
	var (
		cn     string
		dns    []string
		ips    []string
		algo   string
		days   int
		outDir string
		reuse  bool
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Issue a server certificate",
		Long: `Issue a server certificate. If an active certificate already exists for
the given CN, the command exits with an error unless --reuse is set, in which
case the existing certificate and key are retrieved instead.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := cert.ServerRequest{
				CommonName:   cn,
				DNSNames:     dns,
				IPAddresses:  ips,
				KeyAlgorithm: cert.KeyAlgorithm(algo),
				ValidityDays: days,
			}
			var issued cert.IssuedCert

			err := postJSON(opts.APIURL+"/sign/server", req, &issued)
			if err != nil {
				if !reuse {
					return err
				}
				serial, parseErr := serialFromConflict(opts.APIURL+"/sign/server", req)
				if parseErr != nil {
					return err // return original error if we can't parse a serial
				}
				err = getJSON(opts.APIURL+"/certs/"+serial, &issued)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Reusing existing server certificate\n")
			}

			if err := writeFiles(outDir, issued.CertificatePEM, issued.PrivateKeyPEM, issued.ChainPEM); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "  serial:  %s\n  expires: %s\n  files:   %s/{cert,key,chain}.pem\n",
				issued.Serial, issued.ExpiresAt.Format("2006-01-02"), outDir)
			return nil
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name (required)")
	cmd.Flags().StringArrayVar(&dns, "dns", nil, "DNS SAN (repeatable)")
	cmd.Flags().StringArrayVar(&ips, "ip", nil, "IP SAN (repeatable)")
	cmd.Flags().StringVar(&algo, "algo", "ecdsa", "key algorithm: ecdsa or rsa")
	cmd.Flags().IntVar(&days, "days", 365, "validity in days (1-365)")
	cmd.Flags().StringVar(&outDir, "out", ".", "output directory for PEM files")
	cmd.Flags().BoolVar(&reuse, "reuse", false, "retrieve existing certificate if CN is already active")
	cmd.MarkFlagRequired("cn") //nolint:errcheck

	return cmd
}

func newSignClientCmd(opts *rootOptions) *cobra.Command {
	var (
		cn     string
		algo   string
		days   int
		outDir string
		reuse  bool
	)

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Issue a client authentication certificate",
		Long: `Issue a client authentication certificate. If an active certificate already
exists for the given CN, the command exits with an error unless --reuse is set,
in which case the existing certificate and key are retrieved instead.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := cert.ClientRequest{
				CommonName:   cn,
				KeyAlgorithm: cert.KeyAlgorithm(algo),
				ValidityDays: days,
			}

			var issued cert.IssuedCert

			err := postJSON(opts.APIURL+"/sign/client", req, &issued)
			if err != nil {
				if !reuse {
					return err
				}
				serial, parseErr := serialFromConflict(opts.APIURL+"/sign/client", req)
				if parseErr != nil {
					return err
				}
				err = getJSON(opts.APIURL+"/certs/"+serial, issued)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Reusing existing client certificate\n")
			}

			if err := writeFiles(outDir, issued.CertificatePEM, issued.PrivateKeyPEM, issued.ChainPEM); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "  serial:  %s\n  cn:      %s\n  expires: %s\n  files:   %s/{cert,key,chain}.pem\n",
				issued.Serial, issued.CommonName, issued.ExpiresAt.Format("2006-01-02"), outDir)
			return nil
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name / identity (required)")
	cmd.Flags().StringVar(&algo, "algo", "ecdsa", "key algorithm: ecdsa or rsa")
	cmd.Flags().IntVar(&days, "days", 365, "validity in days (1-365)")
	cmd.Flags().StringVar(&outDir, "out", ".", "output directory for PEM files")
	cmd.Flags().BoolVar(&reuse, "reuse", false, "retrieve existing certificate if CN is already active")
	cmd.MarkFlagRequired("cn") //nolint:errcheck

	return cmd
}

func writeFiles(outDir, certPEM, keyPEM, chainPEM string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	files := []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"cert.pem", certPEM, 0644},
		{"key.pem", keyPEM, 0600},
		{"chain.pem", chainPEM, 0644},
	}

	for _, f := range files {
		path := filepath.Join(outDir, f.name)
		if err := os.WriteFile(path, []byte(f.data), f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}

	return nil
}

// serialFromConflict re-issues the POST to extract the serial from a 409 body.
// This is used by --reuse to find the existing cert's serial without a separate lookup.
func serialFromConflict(url string, body any) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data)) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		return "", fmt.Errorf("expected 409 Conflict, got %d", resp.StatusCode)
	}

	var conflict struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&conflict); err != nil {
		return "", fmt.Errorf("decode conflict response: %w", err)
	}
	if conflict.Serial == "" {
		return "", fmt.Errorf("conflict response missing serial")
	}

	return conflict.Serial, nil
}
