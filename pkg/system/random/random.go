package random

import (
	"crypto/rand"
	"encoding/hex"
)

// HexString returns a random hex string backed by byteLength bytes.
func HexString(byteLength int) string {
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "68850df5a87d863a78a4c838"
	}
	return hex.EncodeToString(buf)
}
