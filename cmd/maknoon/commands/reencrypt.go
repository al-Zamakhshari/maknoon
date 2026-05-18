package commands

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// ReencryptCmd returns the cobra command for in-place profile migration.
func ReencryptCmd() *cobra.Command {
	var outputPath string
	var targetProfile int
	var passFlag string
	var isDir bool
	var workers int
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "reencrypt <file>",
		Short: "Re-encrypt a file with a different cryptographic profile",
		Long: `Re-encrypt an existing .makn file using a different profile ID.

The file is decrypted using its current profile, then immediately re-encrypted
with the target profile. This enables migration from the default NIST profile (1)
to the conservative non-lattice profile (3) or any custom profile.

Example:
  maknoon reencrypt secret.makn --profile 3 --passphrase oldpass`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			p := GlobalContext.UI.GetPresenter()

			inputPath := args[0]

			// Detect directory mode automatically or via flag
			if isDir || isDirPath(inputPath) {
				return reencryptDir(inputPath, targetProfile, passFlag, workers, dryRun, p)
			}

			// Peek at the header to show the current profile ID
			f, err := os.Open(inputPath)
			if err != nil {
				return fmt.Errorf("cannot open input file: %w", err)
			}
			_, currentProfile, _, _, err := crypto.ReadHeader(f, false)
			f.Close()
			if err != nil {
				return fmt.Errorf("cannot read file header: %w", err)
			}

			if int(currentProfile) == targetProfile {
				if JSONOutput {
					printJSON(map[string]any{
						"status":  "noop",
						"message": fmt.Sprintf("file is already using profile %d", targetProfile),
					})
				} else {
					fmt.Printf("ℹ️  File is already using profile %d — nothing to do.\n", targetProfile)
				}
				return nil
			}

			// Collect passphrase (flag or interactive prompt)
			var passphrase []byte
			if passFlag != "" {
				passphrase = []byte(passFlag)
			} else {
				var err2 error
				passphrase, _, err2 = getPassphrase("Enter passphrase: ")
				if err2 != nil {
					return fmt.Errorf("failed to read passphrase: %w", err2)
				}
			}
			defer crypto.SafeClear(passphrase)

			// Step 1: Decrypt to a memory buffer
			in, err := os.Open(inputPath)
			if err != nil {
				return fmt.Errorf("cannot open input file: %w", err)
			}
			defer in.Close()

			var plaintext bytes.Buffer
			if _, err := GlobalContext.Engine.Unprotect(nil, in, &plaintext, "", crypto.Options{
				Passphrase: passphrase,
			}); err != nil {
				return fmt.Errorf("decryption failed: %w", err)
			}
			in.Close()

			// Step 2: Determine output path
			dest := outputPath
			if dest == "" {
				dest = inputPath // overwrite in-place
			}
			// Write atomically via a temp file in the same directory
			dir := filepath.Dir(dest)
			tmpFile, err := os.CreateTemp(dir, ".reencrypt-*.tmp")
			if err != nil {
				return fmt.Errorf("cannot create temp file: %w", err)
			}
			tmpPath := tmpFile.Name()
			defer os.Remove(tmpPath) // cleaned up on error

			profileID := byte(targetProfile)
			_, err = GlobalContext.Engine.Protect(nil, inputPath, bytes.NewReader(plaintext.Bytes()), tmpFile, crypto.Options{
				Passphrase: passphrase,
				ProfileID:  &profileID,
			})
			tmpFile.Close()
			if err != nil {
				return fmt.Errorf("re-encryption failed: %w", err)
			}

			// Atomic rename
			if err := os.Rename(tmpPath, dest); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}

			result := map[string]any{
				"status":       "success",
				"input":        inputPath,
				"output":       dest,
				"from_profile": currentProfile,
				"to_profile":   targetProfile,
			}

			p.RenderSuccess(result)

			if !JSONOutput {
				fmt.Printf("✅ Re-encrypted: profile %d → %d\n    Input:  %s\n    Output: %s\n",
					currentProfile, targetProfile, inputPath, dest)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: overwrite input in-place)")
	cmd.Flags().IntVarP(&targetProfile, "profile", "p", 3, "Target profile ID (1=NIST, 3=Conservative/FrodoKEM)")
	cmd.Flags().StringVar(&passFlag, "passphrase", "", "Passphrase (omit for interactive prompt)")
	cmd.Flags().BoolVar(&isDir, "dir", false, "Reencrypt all .makn files in a directory (recursive)")
	cmd.Flags().IntVar(&workers, "workers", 4, "Parallel worker count for directory reencrypt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List files that would be reencrypted without doing it")

	return cmd
}

func isDirPath(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// reencryptDir walks a directory and reencrypts all .makn files in parallel.
func reencryptDir(dirPath string, targetProfile int, passFlag string, numWorkers int, dryRun bool, p interface{ RenderSuccess(any) }) error {
	var files []string
	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".makn") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("directory walk failed: %w", err)
	}

	if len(files) == 0 {
		fmt.Println("No .makn files found.")
		return nil
	}

	if dryRun {
		fmt.Printf("Would reencrypt %d file(s) to profile %d:\n", len(files), targetProfile)
		for _, f := range files {
			fmt.Printf("  %s\n", f)
		}
		return nil
	}

	var passphrase []byte
	if passFlag != "" {
		passphrase = []byte(passFlag)
	} else {
		var err2 error
		passphrase, _, err2 = getPassphrase("Enter passphrase for all files: ")
		if err2 != nil {
			return fmt.Errorf("failed to read passphrase: %w", err2)
		}
	}
	defer crypto.SafeClear(passphrase)

	total := len(files)
	var done int64
	var failed int64
	failedFiles := make([]string, 0)
	var mu sync.Mutex

	if numWorkers < 1 {
		numWorkers = 1
	}
	sem := make(chan struct{}, numWorkers)
	var wg sync.WaitGroup

	for i, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, path string) {
			defer wg.Done()
			defer func() { <-sem }()

			n := atomic.AddInt64(&done, 1)
			fmt.Printf("Reencrypting [%d/%d] %s\n", n, total, path)

			if err := reencryptSingleFile(path, passphrase, byte(targetProfile)); err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				failedFiles = append(failedFiles, fmt.Sprintf("%s: %v", path, err))
				mu.Unlock()
				fmt.Printf("  ❌ FAILED: %v\n", err)
			}
		}(i, f)
	}
	wg.Wait()

	fmt.Printf("\nSummary: %d reencrypted, %d failed (out of %d)\n", int64(total)-failed, failed, total)
	if len(failedFiles) > 0 {
		for _, msg := range failedFiles {
			fmt.Printf("  • %s\n", msg)
		}
		return fmt.Errorf("%d file(s) failed to reencrypt", failed)
	}
	return nil
}

// reencryptSingleFile performs atomic in-place reencrypt of a single file.
func reencryptSingleFile(path string, passphrase []byte, targetProfileID byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	_, currentProfile, _, _, err := crypto.ReadHeader(f, false)
	f.Close()
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if currentProfile == targetProfileID {
		return nil // already on target profile
	}

	in, err := os.Open(path)
	if err != nil {
		return err
	}
	var plaintext bytes.Buffer
	if _, err := GlobalContext.Engine.Unprotect(nil, in, &plaintext, "", crypto.Options{
		Passphrase: passphrase,
	}); err != nil {
		in.Close()
		return fmt.Errorf("decrypt: %w", err)
	}
	in.Close()

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".reencrypt-*.tmp")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	_, err = GlobalContext.Engine.Protect(nil, path, bytes.NewReader(plaintext.Bytes()), tmpFile, crypto.Options{
		Passphrase: passphrase,
		ProfileID:  &targetProfileID,
	})
	tmpFile.Close()
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return os.Rename(tmpPath, path)
}

// reencryptReader is a helper used by the REST handler.
func reencryptReader(r io.Reader, passphrase []byte, targetProfileID byte) (io.Reader, error) {
	var plaintext bytes.Buffer
	if _, err := GlobalContext.Engine.Unprotect(nil, r, &plaintext, "", crypto.Options{
		Passphrase: passphrase,
	}); err != nil {
		return nil, err
	}

	var reenc bytes.Buffer
	if _, err := GlobalContext.Engine.Protect(nil, "reencrypt", bytes.NewReader(plaintext.Bytes()), &reenc, crypto.Options{
		Passphrase: passphrase,
		ProfileID:  &targetProfileID,
	}); err != nil {
		return nil, err
	}
	return &reenc, nil
}
