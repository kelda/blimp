package names

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kelda/blimp/pkg/hash"
)

// ToDNS1123 returns the name that should be used to refer to the given identifier.
// This is necessary because Docker Compose allows service names that don't
// comply with Kubernetes's naming requirements. For example, Compose allows
// services to have underscores in their names.
// DNS-1123 is defined as:
// 1) Lowercase alphanumeric.
// 2) The `-` character can also be used in any interior character
//    of the string.
// 3) Max of 63 characters.
func ToDNS1123(id string) string {
	// Use a sanitized version of the service name as a prefix for readibility
	// when working directly with pods.
	sanitized := strings.ToLower(id)
	invalidChars := regexp.MustCompile(`[^-a-z0-9]`)
	sanitized = invalidChars.ReplaceAllString(sanitized, "")
	sanitized = strings.TrimLeft(sanitized, "-")
	sanitized = strings.TrimRight(sanitized, "-")

	// Don't use the full permitted name length so that we have room for the
	// hash. The final name must be less than 64 characters.
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}

	// If the service name consists purely of prohibited characters, we make
	// sure the sanitized name is nonempty. If sanitized == "", the generated
	// name would start with a "-", which is not DNS-1123 compliant.
	if len(sanitized) == 0 {
		sanitized = "empty"
	}

	// Also append a hash to distinguish between services that are identitical
	// after being sanitized.
	h := hash.DNSCompliant(id)
	if len(h) > 10 {
		h = h[:10]
	}

	return fmt.Sprintf("%s-%s", sanitized, h)
}
