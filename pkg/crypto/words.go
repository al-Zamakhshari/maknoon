package crypto

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const (
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits       = "0123456789"
	symbols      = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// PasswordCharsetSize returns the number of distinct characters in the password
// charset for the given noSymbols setting. Useful for entropy calculations.
func PasswordCharsetSize(noSymbols bool) int {
	if noSymbols {
		return len(lowerLetters) + len(upperLetters) + len(digits) // 62
	}
	return len(lowerLetters) + len(upperLetters) + len(digits) + len(symbols) // 90
}

// PasswordEntropy returns the Shannon entropy in bits for a random password.
func PasswordEntropy(length, charsetSize int) float64 {
	return float64(length) * math.Log2(float64(charsetSize))
}

// PassphraseEntropy returns the Shannon entropy in bits for a random passphrase.
func PassphraseEntropy(words, wordlistSize int) float64 {
	return float64(words) * math.Log2(float64(wordlistSize))
}

// GeneratePassword generates a high-entropy secure password.
func GeneratePassword(length int, noSymbols bool) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}

	charset := lowerLetters + upperLetters + digits
	if !noSymbols {
		charset += symbols
	}

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("entropy failure: %w", err)
		}
		password[i] = charset[num.Int64()]
	}

	result := string(password)

	// Memory Hygiene: Zero out the password bytes immediately after use
	for i := range password {
		password[i] = 0
	}

	return result, nil
}

// ShareWordList is a fixed 256-word list used exclusively for encoding Shamir
// secret-sharing shards as human-readable mnemonics. Each entry maps to one
// byte value (0–255). Do NOT change the order or count — doing so would
// invalidate all existing encoded shares.
var ShareWordList = []string{
	"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
	"access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
	"action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
	"adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
	"agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
	"alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
	"always", "amaze", "ambition", "amount", "amuse", "analysis", "anchor", "ancient", "anger", "angle",
	"angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
	"any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area",
	"arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive",
	"arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
	"assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
	"august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware",
	"away", "awesome", "awful", "awkward", "axis",
	"baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
	"banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach",
	"beam", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind",
	"believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond",
	"bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
	"blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue",
	"blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book",
	"boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket",
	"brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
	"bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble",
	"buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden",
	"burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
	"cabbage", "cabin", "cable",
}

// GeneratePassphrase generates a high-entropy mnemonic passphrase drawn from
// PassphraseWordList (1885 words, ≈ 10.88 bits/word).
func GeneratePassphrase(words int, separator string) (string, error) {
	if words <= 0 {
		return "", fmt.Errorf("number of words must be greater than 0")
	}
	var passphrase []string
	for i := 0; i < words; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(PassphraseWordList))))
		if err != nil {
			return "", fmt.Errorf("entropy failure: %w", err)
		}
		passphrase = append(passphrase, PassphraseWordList[num.Int64()])
	}

	result := strings.Join(passphrase, separator)

	// Clear the slice from memory (best effort)
	for i := range passphrase {
		passphrase[i] = ""
	}
	return result, nil
}
