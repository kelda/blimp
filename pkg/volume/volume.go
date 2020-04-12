package volume

import (
	"fmt"

	"github.com/compose-spec/compose-go/types"

	"github.com/kelda-inc/blimp/pkg/hash"
)

func ID(namespace string, v types.ServiceVolumeConfig) string {
	return hash.DnsCompliant(namespace + v.Type + v.Source)
}

// HostPath returns the path on the Kubernetes node backing the given volume.
func HostPath(namespace, id string) string {
	return fmt.Sprintf("/var/blimp/volumes/%s/%s", namespace, id)
}
