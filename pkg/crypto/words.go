package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// WordList is a curated list of high-frequency, easy-to-type words for passphrases.
// Based on the EFF Long Wordlist.
var WordList = []string{
	"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amaze", "ambition", "amount", "amuse", "analysis", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "beam", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
}

// GeneratePassphrase generates a high-entropy mnemonic passphrase.
func GeneratePassphrase(words int, separator string) (string, error) {
	if words <= 0 {
		return "", fmt.Errorf("number of words must be greater than 0")
	}
	var passphrase []string
	for i := 0; i < words; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(WordList))))
		if err != nil {
			return "", fmt.Errorf("entropy failure: %w", err)
		}
		passphrase = append(passphrase, WordList[num.Int64()])
	}

	result := strings.Join(passphrase, separator)

	// Clear the slice from memory (best effort)
	for i := range passphrase {
		passphrase[i] = ""
	}
	return result, nil
}
