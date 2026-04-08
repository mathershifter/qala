package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newCAChainCmd(opts *rootOptions) *cobra.Command {
	var outFile string

	cmd := &cobra.Command{
		Use:   "ca-chain",
		Short: "Fetch the CA certificate chain",
		Long:  "Fetches the CA chain PEM (intermediate + root) and writes it to a file or stdout.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var result struct {
				ChainPEM string `json:"chain_pem"`
			}
			if err := getJSON(opts.APIURL+"/ca-chain", &result); err != nil {
				return err
			}

			if outFile == "" {
				fmt.Fprint(cmd.OutOrStdout(), result.ChainPEM)
				return nil
			}

			if err := os.WriteFile(outFile, []byte(result.ChainPEM), 0644); err != nil {
				return fmt.Errorf("write %s: %w", outFile, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "CA chain written to %s\n", outFile)
			return nil
		},
	}

	cmd.Flags().StringVar(&outFile, "out", "", "output file (default: stdout)")

	return cmd
}
