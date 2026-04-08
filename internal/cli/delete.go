package cli

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

func newDeleteCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <serial>",
		Short: "Delete a certificate by serial",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serial := args[0]

			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodDelete,
				opts.APIURL+"/certs/"+serial, nil)
			if err != nil {
				return fmt.Errorf("build request: %w", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("DELETE /certs/%s: %w", serial, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				return fmt.Errorf("certificate not found: %s", serial)
			}
			if resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("unexpected status %d", resp.StatusCode)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Deleted certificate %s\n", serial)
			return nil
		},
	}
}
