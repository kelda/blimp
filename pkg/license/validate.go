package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/kelda/blimp/pkg/errors"
)

var (
	// LicensePublicKeyBase64 is expected to be set at build time.
	LicensePublicKeyBase64 string

	// LicensePublicKey is the public key that we use to validate license
	// signatures.
	LicensePublicKey ed25519.PublicKey = ed25519.PublicKey(mustDecodeBase64(LicensePublicKeyBase64))
)

func Unmarshal(signedLicenseJSON []byte) (*License, error) {
	var signedLicense SignedLicense
	err := json.Unmarshal(signedLicenseJSON, &signedLicense)
	if err != nil {
		return nil, errors.WithContext("unmarshal signed license", err)
	}

	licenseBytes := []byte(signedLicense.LicenseJSON)
	var license License
	err = json.Unmarshal(licenseBytes, &license)
	if err != nil {
		return nil, errors.WithContext("unmarshal license", err)
	}

	if ed25519.Verify(LicensePublicKey, licenseBytes, signedLicense.Signature) {
		license.verified = true
	} else {
		return nil, errors.New("failed to verify license signature")
	}


	return &license, nil
}

// numSandboxes should include any sandbox currently being created when Validate
// is called.
func (l *License) Validate(numSandboxes int) error {
	if l == nil {
		// There's no license. Without a license, we cap the number of seats at
		// two.
		if numSandboxes <= 2 {
			return nil
		}
		return errors.NewFriendlyError("Please purchase a license to support more than 2 sandboxes. %d are currently active.", numSandboxes)
	}

	if !l.verified {
		// We would not expect to arrive here in normal operation.
		return errors.New("called Validate() on an unverified license")
	}

	if time.Now().After(l.ExpiryTime) {
		return errors.NewFriendlyError("Your Blimp license expired at %s.", l.ExpiryTime.Format(time.RFC822))
	}

	if l.Seats != 0 && numSandboxes > l.Seats {
		return errors.NewFriendlyError("Your Blimp license is only valid for %d seats, but %d are active.", l.Seats, numSandboxes)
	}

	return nil
}

func mustDecodeBase64(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return string(decoded)
}
