package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureDelete(t *testing.T) {
	// 1. Test single file
	tmpFile, err := os.CreateTemp("", "maknoon-shred-test")
	if err != nil {
		t.Fatal(err)
	}
	tmpFilePath := tmpFile.Name()
	content := []byte("highly sensitive data")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	if err := SecureDelete(tmpFilePath); err != nil {
		t.Fatalf("SecureDelete(file) failed: %v", err)
	}

	if _, err := os.Stat(tmpFilePath); !os.IsNotExist(err) {
		t.Errorf("File still exists after SecureDelete: %s", tmpFilePath)
	}

	// 2. Test directory
	tmpDir, err := os.MkdirTemp("", "maknoon-shred-dir-test")
	if err != nil {
		t.Fatal(err)
	}

	// Add some files and subdirs
	file1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("data1"), 0600); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0700); err != nil {
		t.Fatal(err)
	}
	file2 := filepath.Join(subDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("data2"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := SecureDelete(tmpDir); err != nil {
		t.Fatalf("SecureDelete(dir) failed: %v", err)
	}

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Errorf("Directory still exists after SecureDelete: %s", tmpDir)
	}
}
