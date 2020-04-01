package volume

import (
	"github.com/compose-spec/compose-go/types"

	"github.com/kelda-inc/blimp/pkg/hash"
)

func ID(namespace string, v types.ServiceVolumeConfig) string {
	return hash.DnsCompliant(namespace + v.Type + v.Source)
}
