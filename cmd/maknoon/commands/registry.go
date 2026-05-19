package commands

import (
	"context"
	"fmt"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// RegistryCmd returns the registry management command group.
func RegistryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Identity registry operations (health, status)",
	}
	cmd.AddCommand(registryHealthCmd())
	return cmd
}

func registryHealthCmd() *cobra.Command {
	var discover bool
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check connectivity of configured Nostr relays",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()

			conf, err := crypto.LoadConfig()
			if err != nil {
				conf = crypto.DefaultConfig()
			}

			relays := conf.Nostr.Relays
			if discover {
				relays = deduplicateRelays(append(relays, crypto.WellKnownRelays...))
			}

			reg := &crypto.NostrRegistry{Relays: relays}
			results := reg.HealthCheck(context.Background())

			if GlobalContext.UI.JSON {
				p.RenderSuccess(results)
				return nil
			}

			fmt.Printf("%-50s %-10s %s\n", "RELAY", "STATUS", "LATENCY")
			fmt.Printf("%s\n", "────────────────────────────────────────────────────────────────────")
			reachable := 0
			for _, h := range results {
				status := "✅ OK"
				lat := fmt.Sprintf("%dms", h.LatencyMs)
				if !h.Reachable {
					status = "❌ FAIL"
					lat = "-"
				} else {
					reachable++
				}
				fmt.Printf("%-50s %-10s %s\n", h.URL, status, lat)
				if h.Error != "" {
					fmt.Printf("  └─ %s\n", h.Error)
				}
			}
			fmt.Printf("\n%d/%d relays reachable\n", reachable, len(results))
			if reachable == 0 {
				return fmt.Errorf("no Nostr relays are reachable")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&discover, "discover", false, "Also probe well-known public relays beyond the configured set")
	return cmd
}

func deduplicateRelays(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
