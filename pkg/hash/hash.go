package hash

import (
	"crypto/sha256"
	"fmt"
)

// DnsCompliantHash hashes the given string and encodes it into base16.
func DNSCompliant(str string) string {
	return Bytes([]byte(str))
}

func Bytes(b []byte) string {
	h := sha256.New()
	_, err := h.Write(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}
