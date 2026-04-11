package commands

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// ProfilesCmd returns the cobra command for listing or generating cryptographic profiles.
func ProfilesCmd() *cobra.Command {
	var generate bool
	var secret bool

	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List built-in profiles or generate a random custom profile",
		Run: func(_ *cobra.Command, _ []string) {
			if generate {
				var id byte
				if secret {
					// Secret ID between 3 and 127
					r, _ := rand.Int(rand.Reader, big.NewInt(125))
					id = 3 + byte(r.Uint64())
				} else {
					// Portable ID between 128 and 255
					r, _ := rand.Int(rand.Reader, big.NewInt(128))
					id = 128 + byte(r.Uint64())
				}

				dp := crypto.GenerateRandomProfile(id)
				raw, _ := json.MarshalIndent(dp, "", "  ")
				fmt.Println(string(raw))
				return
			}

			fmt.Println("🛡️  Maknoon Cryptographic Profiles")
			fmt.Println("\nBuilt-in Profiles:")
			fmt.Println("  ID 1: NIST PQC (Kyber1024 + Dilithium87) + XChaCha20-Poly1305 (Default)")
			fmt.Println("  ID 2: NIST PQC (Kyber1024 + Dilithium87) + AES-256-GCM")

			fmt.Println("\n🛠️  Custom Profile Construction (JSON Schema)")
			fmt.Println("  {")
			fmt.Println("    \"id\": 3-255,")
			fmt.Println("    \"cipher\": <0, 1, or 2>,")
			fmt.Println("    \"kdf\": 0,")
			fmt.Println("    \"kdf_iterations\": <min 1>,")
			fmt.Println("    \"kdf_memory\": <min 1024 KB>,")
			fmt.Println("    \"kdf_threads\": <1-N>,")
			fmt.Println("    \"salt_size\": <min 8>,")
			fmt.Println("    \"nonce_size\": <required by cipher>")
			fmt.Println("  }")

			fmt.Println("\nAvailable Algorithms:")
			fmt.Println("  Ciphers:")
			fmt.Printf("    %d: XChaCha20-Poly1305 (nonce_size: 24)\n", crypto.AlgoXChaCha20Poly1305)
			fmt.Printf("    %d: AES-256-GCM         (nonce_size: 12)\n", crypto.AlgoAES256GCM)
			fmt.Printf("    %d: AES-256-GCM-SIV     (nonce_size: 12)\n", crypto.AlgoAES256GCMSIV)
			fmt.Println("  KDFs:")
			fmt.Printf("    %d: Argon2id\n", crypto.KdfArgon2id)

			fmt.Println("\nStorage Modes:")
			fmt.Println("  IDs 3-127:   'Secret' mode (profile file required for decryption)")
			fmt.Println("  IDs 128-255: 'Portable' mode (profile parameters stored in file header)")
			fmt.Println("\nUse --generate to create a random custom profile.")
		},
	}

	cmd.Flags().BoolVarP(&generate, "generate", "g", false, "Generate a random secure custom profile JSON")
	cmd.Flags().BoolVar(&secret, "secret", false, "Generate a 'Secret' profile (ID < 128) instead of a 'Portable' one")
	return cmd
}
