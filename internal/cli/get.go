package cli

import (
	"github.com/spf13/cobra"
)

func newGetCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get an issued certificate",
	}
	cmd.AddCommand(newGetServerCmd(opts), newGetClientCmd(opts))
	return cmd
}

func newGetServerCmd(opts *rootOptions) *cobra.Command {
	var (
		cn     string
		outDir string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Get an issued server certificate",
		Long: `Get a previously issued TLS server certificate.
If an active certificate does not exist for the given CN, the command 
exits with an error`,
		RunE: func(cmd *cobra.Command, args []string) error {
			issued, err := getIssuedCert(opts.APIURL, "server", cn)
			if err != nil {
				return err
			}

			if err := writeFiles(outDir, issued.CertificatePEM, issued.PrivateKeyPEM, issued.ChainPEM); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name (required)")
	cmd.Flags().StringVar(&outDir, "out", ".", "output directory for PEM files")
	cmd.MarkFlagRequired("cn") //nolint:errcheck

	return cmd
}

func newGetClientCmd(opts *rootOptions) *cobra.Command {
	var (
		cn     string
		outDir string
	)

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Get an issued client certificate",
		Long: `Get a previously issued TLS client certificate.
If an active certificate does not exist for the given CN, the command 
exits with an error`,
		RunE: func(cmd *cobra.Command, args []string) error {

			issued, err := getIssuedCert(opts.APIURL, "client", cn)
			if err != nil {
				return err
			}
			// if outDir != "" {
			if err := writeFiles(outDir, issued.CertificatePEM, issued.PrivateKeyPEM, issued.ChainPEM); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "common name (required)")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory for PEM files")

	cmd.MarkFlagRequired("cn") //nolint:errcheck
	return cmd
}
