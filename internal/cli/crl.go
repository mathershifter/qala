package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func newCRLCmd(opts *rootOptions) *cobra.Command {
	var (
		format string
		out    string
	)

	cmd := &cobra.Command{
		Use:   "crl",
		Short: "Fetch the current Certificate Revocation List",
		Long:  `Fetch the current CRL from the server. Default format is PEM.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var url string
			switch format {
			case "der":
				url = opts.APIURL + "/crl"
			default:
				url = opts.APIURL + "/crl.pem"
			}

			resp, err := http.Get(url) //nolint:noctx
			if err != nil {
				return fmt.Errorf("GET %s: %w", url, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 400 {
				return fmt.Errorf("server error: %d", resp.StatusCode)
			}

			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}

			if out != "" {
				if err := os.WriteFile(out, data, 0644); err != nil {
					return fmt.Errorf("write %s: %w", out, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "CRL written to %s\n", out)
				return nil
			}

			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}

	cmd.Flags().StringVar(&format, "format", "pem", "output format: pem or der")
	cmd.Flags().StringVar(&out, "out", "", "output file path (default: stdout)")

	return cmd
}
