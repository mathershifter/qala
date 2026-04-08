package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gitlab.aristanetworks.com/jmather/seacrt/internal/ca"
)

func newInitCmd(opts *rootOptions) *cobra.Command {
	var (
		cn  string
		org string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate Root and Intermediate CA",
		Long: `Generates the Root CA and Intermediate CA key pairs and certificates,
writing PEM files to the data directory. Run this once before starting the server.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := buildLogger(opts)

			if err := ca.Init(opts.DataDir, logger); err != nil {
				return fmt.Errorf("init CA: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "CA initialized in %s\n", opts.DataDir)
			fmt.Fprintln(cmd.OutOrStdout(), "Keep root-ca.key.pem offline after moving intermediate files to production.")
			return nil
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "SELab Root CA", "common name")
	cmd.Flags().StringVar(&org, "org", "SELab CA", "organization")

	return cmd
}
