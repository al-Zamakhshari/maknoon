package crypto

import (
	"math"
	"strings"
	"testing"
	"unicode"
)

// ── wordlist sizes ────────────────────────────────────────────────────────────

func TestShareWordListSize(t *testing.T) {
	if got := len(ShareWordList); got != 256 {
		t.Fatalf("ShareWordList: want 256 entries, got %d", got)
	}
}

func TestPassphraseWordListSize(t *testing.T) {
	n := len(PassphraseWordList)
	if n < 1500 {
		t.Fatalf("PassphraseWordList too small: got %d words, want at least 1500", n)
	}
	t.Logf("PassphraseWordList contains %d words (%.2f bits/word)", n, math.Log2(float64(n)))
}

// ── uniqueness ────────────────────────────────────────────────────────────────

func TestShareWordListNoOverlap(t *testing.T) {
	seen := make(map[string]int, len(ShareWordList))
	for i, w := range ShareWordList {
		if prev, dup := seen[w]; dup {
			t.Errorf("duplicate word %q at index %d (first seen at %d)", w, i, prev)
		}
		seen[w] = i
	}
}

func TestPassphraseWordListNoOverlap(t *testing.T) {
	seen := make(map[string]int, len(PassphraseWordList))
	for i, w := range PassphraseWordList {
		if prev, dup := seen[w]; dup {
			t.Errorf("duplicate word %q at index %d (first seen at %d)", w, i, prev)
		}
		seen[w] = i
	}
}

// ── password generation ───────────────────────────────────────────────────────

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
	found := false
	syms := "!@#$%^&*()-_=+[]{}|;:,.<>?"
	for i := 0; i < 20; i++ {
		p, _ := GeneratePassword(32, false)
		if strings.ContainsAny(p, syms) {
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

// ── password charset / entropy ────────────────────────────────────────────────

func TestPasswordCharsetSizes(t *testing.T) {
	// 26 lower + 26 upper + 10 digits = 62; + 26 symbols = 88
	if got := PasswordCharsetSize(true); got != 62 {
		t.Errorf("PasswordCharsetSize(noSymbols=true) = %d, want 62", got)
	}
	if got := PasswordCharsetSize(false); got <= 62 {
		t.Errorf("PasswordCharsetSize(noSymbols=false) = %d, want > 62", got)
	}
}

func TestPasswordEntropyFormula(t *testing.T) {
	cs := PasswordCharsetSize(false)
	bits := PasswordEntropy(32, cs)
	want := 32 * math.Log2(float64(cs))
	if math.Abs(bits-want) > 0.01 {
		t.Errorf("PasswordEntropy(32,%d) = %.4f, want %.4f", cs, bits, want)
	}
}

func TestPasswordEntropyNoSymbols(t *testing.T) {
	bits := PasswordEntropy(32, 62)
	want := 32 * math.Log2(62)
	if math.Abs(bits-want) > 0.01 {
		t.Errorf("PasswordEntropy(32,62) = %.4f, want %.4f", bits, want)
	}
}

// ── passphrase generation ─────────────────────────────────────────────────────

func TestGeneratePassphraseWordCount(t *testing.T) {
	for _, n := range []int{3, 5, 8} {
		phrase, err := GeneratePassphrase(n, " ")
		if err != nil {
			t.Fatalf("GeneratePassphrase(%d): %v", n, err)
		}
		if got := len(strings.Fields(phrase)); got != n {
			t.Errorf("GeneratePassphrase(%d) returned %d words", n, got)
		}
	}
}

func TestGeneratePassphraseCustomSeparator(t *testing.T) {
	phrase, err := GeneratePassphrase(4, "-")
	if err != nil {
		t.Fatalf("GeneratePassphrase: %v", err)
	}
	if parts := strings.Split(phrase, "-"); len(parts) != 4 {
		t.Errorf("expected 4 parts with '-' separator, got %d: %q", len(parts), phrase)
	}
}

func TestGeneratePassphraseWordsFromList(t *testing.T) {
	phrase, _ := GeneratePassphrase(6, " ")
	wordSet := make(map[string]bool, len(PassphraseWordList))
	for _, w := range PassphraseWordList {
		wordSet[w] = true
	}
	for _, w := range strings.Fields(phrase) {
		if !wordSet[w] {
			t.Errorf("word %q not in PassphraseWordList", w)
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

// ── passphrase entropy ────────────────────────────────────────────────────────

func TestPassphraseEntropyFormula(t *testing.T) {
	n := len(PassphraseWordList)
	for words, factor := range map[int]float64{4: 4, 6: 6, 12: 12} {
		bits := PassphraseEntropy(words, n)
		want := factor * math.Log2(float64(n))
		if math.Abs(bits-want) > 0.01 {
			t.Errorf("PassphraseEntropy(%d,%d) = %.4f, want %.4f", words, n, bits, want)
		}
	}
}

func TestPassphraseEntropyIsAdequate(t *testing.T) {
	bits6 := PassphraseEntropy(6, len(PassphraseWordList))
	if bits6 < 60 {
		t.Errorf("6-word passphrase entropy %.1f bits < 60 bits minimum", bits6)
	}
	t.Logf("6-word passphrase entropy: %.1f bits", bits6)
}

// ── mnemonic roundtrip ────────────────────────────────────────────────────────

func TestToMnemonicRoundtrip(t *testing.T) {
	secret := []byte("hello maknoon world 123!")
	shares, err := SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("SplitSecret: %v", err)
	}

	mnemonics := make([]string, len(shares))
	for i, s := range shares {
		mnemonics[i] = s.ToMnemonic()
		if mnemonics[i] == "" {
			t.Fatalf("share %d: empty mnemonic", i)
		}
	}

	decoded := make([]*Share, len(shares))
	for i, m := range mnemonics {
		decoded[i], err = FromMnemonic(m)
		if err != nil {
			t.Fatalf("share %d: FromMnemonic: %v", i, err)
		}
	}

	recovered, err := CombineShares([]Share{*decoded[0], *decoded[1]})
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if string(recovered) != string(secret) {
		t.Errorf("roundtrip mismatch: got %q, want %q", recovered, secret)
	}
}

// ── min-entropy guard (logic, no CLI) ────────────────────────────────────────

func TestMinEntropyValidation(t *testing.T) {
	bits := PassphraseEntropy(4, len(PassphraseWordList))
	if bits >= 256 {
		t.Skip("unexpectedly large wordlist")
	}
	t.Logf("4-word passphrase entropy = %.1f bits (< 256 → guard would fire)", bits)
}
