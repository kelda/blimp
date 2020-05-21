package kube

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kelda-inc/blimp/pkg/hash"
)

// VolumeFinalizer is the finalizer used to signal that the given node needs to
// clean up the namespace's volumes.
func VolumeFinalizer(node string) string {
	return fmt.Sprintf("volume.blimp.kelda.io/%s", node)
}

// PodName returns the name that should be used to refer to the given service.
// This is necessary because Docker Compose allows service names that don't
// comply with Kubernetes's naming requirements. For example, Compose allows
// services to have underscores in their names.
// DNS-1123 is defined as:
// 1) Lowercase alphanumeric.
// 2) The `-` character can also be used in any interior character
//    of the string.
// 3) Max of 63 characters.
func PodName(serviceName string) string {
	// Use a sanitized version of the service name as a prefix for readibility
	// when working directly with pods.
	sanitized := strings.ToLower(serviceName)
	invalidChars := regexp.MustCompile(`[^-a-z0-9]`)
	sanitized = invalidChars.ReplaceAllString(sanitized, "")
	sanitized = strings.TrimLeft(sanitized, "-")
	sanitized = strings.TrimRight(sanitized, "-")

	// Don't use the full permitted name length so that we have room for the
	// hash. The final name must be less than 64 characters.
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}

	// Also append a hash to distinguish between services that are identitical
	// after being sanitized.
	h := hash.DnsCompliant(serviceName)
	if len(h) > 10 {
		h = h[:10]
	}

	return fmt.Sprintf("%s-%s", sanitized, h)
}
