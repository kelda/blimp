package hash

import (
	"crypto/sha256"
	"fmt"
)

// DnsCompliantHash hashes the given string and encodes it into base16.
func DnsCompliant(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}
