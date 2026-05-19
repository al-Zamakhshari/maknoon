package crypto

import (
	"strings"
	"testing"
	"unicode"
)

// --- GeneratePassword ---

func TestGeneratePasswordLength(t *testing.T) {
	for _, n := range []int{8, 16, 32, 64} {
		p, err := GeneratePassword(n, false)
		if err != nil {
			t.Fatalf("GeneratePassword(%d): %v", n, err)
		}
		if len(p) != n {
			t.Errorf("GeneratePassword(%d) returned len=%d", n, len(p))
		}
	}
}

func TestGeneratePasswordUnique(t *testing.T) {
	p1, _ := GeneratePassword(24, false)
	p2, _ := GeneratePassword(24, false)
	if p1 == p2 {
		t.Error("two GeneratePassword calls returned identical passwords")
	}
}

func TestGeneratePasswordNoSymbols(t *testing.T) {
	p, err := GeneratePassword(32, true)
	if err != nil {
		t.Fatalf("GeneratePassword noSymbols: %v", err)
	}
	for _, r := range p {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			t.Errorf("noSymbols password contains non-alphanumeric character: %q", r)
		}
	}
}

func TestGeneratePasswordWithSymbols(t *testing.T) {
	// Run many trials to ensure symbols actually appear.
	found := false
	symbols := "!@#$%^&*()-_=+[]{}|;:,.<>?"
	for i := 0; i < 20; i++ {
		p, _ := GeneratePassword(32, false)
		if strings.ContainsAny(p, symbols) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one password with symbols over 20 trials")
	}
}

func TestGeneratePasswordZeroLength(t *testing.T) {
	_, err := GeneratePassword(0, false)
	if err == nil {
		t.Error("expected error for length=0")
	}
}

func TestGeneratePasswordNegativeLength(t *testing.T) {
	_, err := GeneratePassword(-5, false)
	if err == nil {
		t.Error("expected error for negative length")
	}
}

// --- GeneratePassphrase ---

func TestGeneratePassphraseWordCount(t *testing.T) {
	for _, n := range []int{3, 5, 8} {
		phrase, err := GeneratePassphrase(n, " ")
		if err != nil {
			t.Fatalf("GeneratePassphrase(%d): %v", n, err)
		}
		words := strings.Fields(phrase)
		if len(words) != n {
			t.Errorf("GeneratePassphrase(%d) returned %d words", n, len(words))
		}
	}
}

func TestGeneratePassphraseCustomSeparator(t *testing.T) {
	phrase, err := GeneratePassphrase(4, "-")
	if err != nil {
		t.Fatalf("GeneratePassphrase: %v", err)
	}
	parts := strings.Split(phrase, "-")
	if len(parts) != 4 {
		t.Errorf("expected 4 parts with '-' separator, got %d: %q", len(parts), phrase)
	}
}

func TestGeneratePassphraseWordsFromWordList(t *testing.T) {
	phrase, _ := GeneratePassphrase(6, " ")
	words := strings.Fields(phrase)
	wordSet := make(map[string]bool, len(WordList))
	for _, w := range WordList {
		wordSet[w] = true
	}
	for _, w := range words {
		if !wordSet[w] {
			t.Errorf("word %q not in WordList", w)
		}
	}
}

func TestGeneratePassphraseUnique(t *testing.T) {
	p1, _ := GeneratePassphrase(6, " ")
	p2, _ := GeneratePassphrase(6, " ")
	if p1 == p2 {
		t.Error("two GeneratePassphrase calls returned identical passphrases")
	}
}

func TestGeneratePassphraseZeroWords(t *testing.T) {
	_, err := GeneratePassphrase(0, " ")
	if err == nil {
		t.Error("expected error for words=0")
	}
}
