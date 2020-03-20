package volume

import (
	"github.com/kelda-inc/blimp/pkg/hash"
)

type V struct {
	Type   string
	Source string
	Target string
}

func (v *V) Id(namespace string) string {
	return hash.DnsCompliant(namespace + v.Type + v.Source)
}
