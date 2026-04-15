package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"gitlab.aristanetworks.com/jmather/qala/internal/ca"
	"gitlab.aristanetworks.com/jmather/qala/internal/config"
)

func newInitCmd(opts *rootOptions) *cobra.Command {
	d := config.Defaults()
	var (
		caOrg              string
		caCNRoot           string
		caCNIntermediate   string
		certOrg            string
		defaultValidityStr string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate Root and Intermediate CA",
		Long: `Generates the Root CA and Intermediate CA key pairs and certificates,
writing PEM files to the data directory. Run this once before starting the server.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := buildLogger(opts)

			caCfg := ca.CAConfig{
				RootCN:         caCNRoot,
				IntermediateCN: caCNIntermediate,
				Organization:   caOrg,
			}

			if err := ca.Init(opts.DataDir, caCfg, logger); err != nil {
				return fmt.Errorf("init CA: %w", err)
			}

			var defaultValidity int
			if defaultValidityStr != "" {
				v, err := strconv.Atoi(defaultValidityStr)
				if err != nil || v < 1 || v > 365 {
					return fmt.Errorf("--default-validity-days must be an integer between 1 and 365")
				}
				defaultValidity = v
			}

			cfg := config.Config{
				CAOrg:               caOrg,
				CACNRoot:            caCNRoot,
				CACNIntermediate:    caCNIntermediate,
				CertOrg:             certOrg,
				DefaultValidityDays: defaultValidity,
			}
			if err := config.Save(opts.DataDir, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "CA initialized in %s\n", opts.DataDir)
			fmt.Fprintln(cmd.OutOrStdout(), "Keep root-ca.key.pem offline after moving intermediate files to production.")
			return nil
		},
	}

	cmd.Flags().StringVar(&caOrg, "ca-org",
		envOrDefault("QALA_CA_ORG", d.CAOrg), "organization name used in Root CA and Intermediate CA subjects")
	cmd.Flags().StringVar(&caCNRoot, "ca-cn-root",
		envOrDefault("QALA_CA_CN_ROOT", d.CACNRoot), "common name for Root CA")
	cmd.Flags().StringVar(&caCNIntermediate, "ca-cn-intermediate",
		envOrDefault("QALA_CA_CN_INTERMEDIATE", d.CACNIntermediate), "common name for Intermediate CA")
	cmd.Flags().StringVar(&certOrg, "cert-org",
		envOrDefault("QALA_CERT_ORG", d.CertOrg), "default Organization for issued leaf certificates")
	cmd.Flags().StringVar(&defaultValidityStr, "default-validity-days",
		envOrDefault("QALA_DEFAULT_VALIDITY_DAYS", fmt.Sprintf("%d", d.DefaultValidityDays)), "default validity days for issued certificates (1–365)")

	return cmd
}
