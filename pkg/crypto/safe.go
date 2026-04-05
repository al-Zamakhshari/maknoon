package crypto

// SafeClear overwrites a byte slice with zeros to ensure sensitive data
// does not persist in memory.
func SafeClear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SafeClearString clears a string slice by setting each element to empty.
func SafeClearString(s []string) {
	for i := range s {
		s[i] = ""
	}
}
