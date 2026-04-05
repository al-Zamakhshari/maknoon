package commands

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"go.etcd.io/bbolt"
	"golang.org/x/term"
)

const (
	vaultBucket = "secrets"
	metaBucket  = "metadata"
	saltKey     = "salt"
)

var vaultName string

func VaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage secure password vaults",
	}

	cmd.PersistentFlags().StringVarP(&vaultName, "vault", "v", "default", "Name or full path of the vault to use")

	cmd.AddCommand(vaultSetCmd())
	cmd.AddCommand(vaultGetCmd())
	cmd.AddCommand(vaultListCmd())

	return cmd
}

// openVault opens the vault DB and derives the master key.
func openVault() (*bbolt.DB, []byte, error) {
	home, _ := os.UserHomeDir()
	vaultDir := filepath.Join(home, ".maknoon", "vaults")
	os.MkdirAll(vaultDir, 0700)

	dbPath := vaultName
	// If it's just a name (no path separators), put it in the vaults directory
	if !strings.Contains(vaultName, string(os.PathSeparator)) {
		dbPath = filepath.Join(vaultDir, vaultName+".db")
	}

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, nil, err
	}

	var salt []byte
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(metaBucket))
		if err != nil { return err }
		tx.CreateBucketIfNotExists([]byte(vaultBucket))

		salt = b.Get([]byte(saltKey))
		if salt == nil {
			// Initialize new vault
			salt = make([]byte, 32)
			rand.Read(salt)
			b.Put([]byte(saltKey), salt)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	// Get Master Password
	var passphrase []byte
	if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
		passphrase = []byte(envPass)
	} else {
		fmt.Print("Enter Vault Master Passphrase: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			db.Close()
			return nil, nil, err
		}
		passphrase = p
	}

	masterKey := crypto.DeriveVaultKey(passphrase, salt)
	
	// Memory Hygiene
	defer func() {
		for i := range passphrase { passphrase[i] = 0 }
	}()

	return db, masterKey, nil
}

func vaultSetCmd() *cobra.Command {
	var user string
	var note string

	cmd := &cobra.Command{
		Use:   "set [service] [password]",
		Short: "Store a password in the vault",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			service := args[0]
			var password string
			if len(args) > 1 {
				password = args[1]
			} else {
				fmt.Print("Enter password for ", service, ": ")
				p, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				password = string(p)
			}

			db, key, err := openVault()
			if err != nil { return err }
			defer db.Close()
			defer func() {
				for i := range key { key[i] = 0 }
			}()

			entry := &crypto.VaultEntry{
				Service:  service,
				Username: user,
				Password: password,
				Note:     note,
			}

			ciphertext, err := crypto.SealEntry(entry, key)
			if err != nil { return err }

			// Key = SHA256(Service Name) for zero-knowledge lookup
			h := sha256.Sum256([]byte(strings.ToLower(service)))
			indexKey := hex.EncodeToString(h[:])

			return db.Update(func(tx *bbolt.Tx) error {
				return tx.Bucket([]byte(vaultBucket)).Put([]byte(indexKey), ciphertext)
			})
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "Username for this service")
	cmd.Flags().StringVarP(&note, "note", "n", "", "Optional note")
	return cmd
}

func vaultGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get [service]",
		Short: "Retrieve a password from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service := args[0]
			db, key, err := openVault()
			if err != nil { return err }
			defer db.Close()
			defer func() {
				for i := range key { key[i] = 0 }
			}()

			h := sha256.Sum256([]byte(strings.ToLower(service)))
			indexKey := hex.EncodeToString(h[:])

			var ciphertext []byte
			db.View(func(tx *bbolt.Tx) error {
				ciphertext = tx.Bucket([]byte(vaultBucket)).Get([]byte(indexKey))
				return nil
			})

			if ciphertext == nil {
				return fmt.Errorf("service '%s' not found in vault", service)
			}

			entry, err := crypto.OpenEntry(ciphertext, key)
			if err != nil { return err }

			fmt.Printf("Service:  %s\n", entry.Service)
			fmt.Printf("Username: %s\n", entry.Username)
			fmt.Printf("Password: %s\n", entry.Password)
			if entry.Note != "" {
				fmt.Printf("Note:     %s\n", entry.Note)
			}

			return nil
		},
	}
}

func vaultListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all services stored in the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, key, err := openVault()
			if err != nil { return err }
			defer db.Close()
			defer func() {
				for i := range key { key[i] = 0 }
			}()

			fmt.Println("Stored Services:")
			return db.View(func(tx *bbolt.Tx) error {
				b := tx.Bucket([]byte(vaultBucket))
				return b.ForEach(func(k, v []byte) error {
					entry, err := crypto.OpenEntry(v, key)
					if err == nil {
						fmt.Printf(" - %s (%s)\n", entry.Service, entry.Username)
					}
					return nil
				})
			})
		},
	}
}
