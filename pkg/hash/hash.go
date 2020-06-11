package hash

import (
	"crypto/sha256"
	"fmt"
)

// DnsCompliantHash hashes the given string and encodes it into base16.
func DnsCompliant(str string) string {
	return Bytes([]byte(str))
}

func Bytes(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}
