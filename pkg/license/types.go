package license

import "time"

type License struct {
	Customer string
	// A zero value indicates no seat limit.
	Seats      int
	ExpiryTime time.Time

	// verified indicates whether this license has had a validated signature.
	verified bool
}

type SignedLicense struct {
	// LicenseJSON is a string instead of a []byte so that it is easier to read
	// the marshalled SignedLicense.
	LicenseJSON string
	// Signature is the ed25519 signature of the exact byte sequence stored as
	// LicenseJSON.
	Signature []byte
}
