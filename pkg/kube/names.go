package kube

import (
	"fmt"

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
func PodName(serviceName string) string {
	return hash.DnsCompliant(serviceName)
}
