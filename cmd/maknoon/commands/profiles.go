package commands

import (
	"fmt"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// ProfilesCmd returns the cobra command for listing available cryptographic profiles.
func ProfilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List built-in profiles and supported algorithms for custom profiles",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("🛡️  Maknoon Cryptographic Profiles")
			fmt.Println("\nBuilt-in Profiles:")
			fmt.Println("  ID 1: NIST PQC (Kyber1024 + Dilithium87) + XChaCha20-Poly1305 (Default)")
			fmt.Println("  ID 2: NIST PQC (Kyber1024 + Dilithium87) + AES-256-GCM")

			fmt.Println("\n🛠️  Custom Profile Construction (JSON Schema)")
			fmt.Println("  {")
			fmt.Println("    \"id\": 3-255,")
			fmt.Println("    \"cipher\": <0 or 1>,")
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
			fmt.Println("  KDFs:")
			fmt.Printf("    %d: Argon2id\n", crypto.KdfArgon2id)

			fmt.Println("\nStorage Modes:")
			fmt.Println("  IDs 3-127:   'Secret' mode (profile file required for decryption)")
			fmt.Println("  IDs 128-255: 'Portable' mode (profile parameters stored in file header)")
		},
	}
}
