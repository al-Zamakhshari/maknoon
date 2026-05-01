package crypto

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestP2PFlowCorruption(t *testing.T) {
	passphrase := []byte("p2p-test-pass")
	text := "This is a top secret P2P message"
	var encrypted bytes.Buffer

	// 1. Encrypt with compression
	flags, err := Protect("-", bytes.NewReader([]byte(text)), &encrypted, Options{
		Passphrase: passphrase,
		Compress:   BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	// 2. Decrypt using full pipeline
	var decrypted bytes.Buffer
	_, err = Unprotect(&encrypted, &decrypted, "", Options{
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if decrypted.String() != text {
		t.Errorf("Corruption STILL detected!\n\tExpected: %s\n\tGot: %s\n\tFlags: %d", text, decrypted.String(), flags)
	}
}

func TestP2PDirectoryFlow(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "p2p-dir-test-*")
	defer os.RemoveAll(tmpDir)

	srcDir := filepath.Join(tmpDir, "source")
	_ = os.MkdirAll(srcDir, 0755)
	_ = os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("data1"), 0644)

	passphrase := []byte("p2p-dir-pass")
	var encrypted bytes.Buffer

	// 1. Protect directory
	_, err := Protect(srcDir, nil, &encrypted, Options{
		Passphrase: passphrase,
		IsArchive:  true,
		Compress:   BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	// 2. Unprotect to new directory
	restoredDir := filepath.Join(tmpDir, "restored")
	reader := bytes.NewReader(encrypted.Bytes())
	_, err = Unprotect(reader, nil, restoredDir, Options{Passphrase: passphrase})
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	// 3. Verify
	data, err := os.ReadFile(filepath.Join(restoredDir, "source", "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read restored file: %v", err)
	}
	if string(data) != "data1" {
		t.Errorf("Content mismatch: got %s, want data1", string(data))
	}
}

func TestP2PTextTransfer(t *testing.T) {
	passphrase := []byte("text-pass")
	text := "top-secret-p2p-text"
	var encrypted bytes.Buffer

	_, err := Protect("-", bytes.NewReader([]byte(text)), &encrypted, Options{Passphrase: passphrase, Compress: BoolPtr(true)})
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = Unprotect(&encrypted, &decrypted, "", Options{Passphrase: passphrase})
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if decrypted.String() != text {
		t.Errorf("Decrypted text mismatch. Expected: %s, Got: %q", text, decrypted.String())
	}
}

func TestP2PAsymmetric(t *testing.T) {
	kemPub, kemPriv, _, _, _, _, _ := GeneratePQKeyPair(0)
	payload := "asymmetric-p2p-payload"
	var encrypted bytes.Buffer

	_, err := Protect("-", bytes.NewReader([]byte(payload)), &encrypted, Options{
		PublicKey: kemPub,
		Compress:  BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = Unprotect(&encrypted, &decrypted, "", Options{
		LocalPrivateKey: kemPriv,
	})
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if decrypted.String() != payload {
		t.Errorf("Decrypted content mismatch. Expected: %s, Got: %q", payload, decrypted.String())
	}
}

func TestP2PCustomIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// 1. Setup clean env
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	ResetGlobalConfig()
	engine, err := NewEngine(nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()
	ctx := &EngineContext{Context: context.Background()}

	// 2. Generate a custom identity
	idName := "custom-peer"
	_, err = engine.Identities.CreateIdentity(idName, nil, "", false, "nist")
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// 3. Attempt to start P2P with this identity
	peerID, _, err := engine.P2PSend(ctx, idName, "test.txt", bytes.NewReader([]byte("test")), P2PSendOptions{
		Passphrase: nil,
		To:         "12D3KooWHPWp3WStj3cEoNyUxH8mmDJaGGkU3YDw2t3rf9YHGPso", // Dummy
	})

	if err != nil {
		t.Fatalf("P2PSend failed with custom identity: %v", err)
	}

	if peerID == "" {
		t.Error("Expected valid PeerID from custom identity")
	}
}
