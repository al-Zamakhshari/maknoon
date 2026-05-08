package commands

import (
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// AggregateCmd returns the cobra command for aggregating signatures.
func AggregateCmd() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "aggregate [sig1] [sig2] ...",
		Short: "Aggregate multiple signatures into a threshold signature",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			var sigs [][]byte
			for _, path := range args {
				if err := validatePath(path); err != nil {
					p.RenderError(err)
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					p.RenderError(err)
					return err
				}
				sigs = append(sigs, data)
			}

			agg, err := GlobalContext.Engine.Aggregate(nil, sigs)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if outputFile == "" {
				outputFile = "multi.sig"
			}

			if err := os.WriteFile(outputFile, agg, 0600); err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(crypto.SignResult{
					Status:        "success",
					SignaturePath: outputFile,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("Signatures aggregated successfully into %s", outputFile))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "multi.sig", "Output path for the aggregate signature")
	return cmd
}
