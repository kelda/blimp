package volume

import (
	"path/filepath"

	corev1 "k8s.io/api/core/v1"

	"github.com/kelda/blimp/pkg/hash"
)

const (
	// PersistentVolumeClaimName is the name used for the PVC backing all Blimp
	// volumes in a namespace.
	PersistentVolumeClaimName = "blimp-volume"
)

var (
	// PersistentVolume is the volume definition that pods should use to mount
	// the PV backing all Blimp volumes in a namespace.
	PersistentVolume = corev1.Volume{
		Name: "volume",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: PersistentVolumeClaimName,
			},
		},
	}
)

// NamedVolumeDir returns the path within the PV that's used to back the given
// volume.
func NamedVolumeDir(name string) string {
	return filepath.Join("volume", hash.DNSCompliant(name))
}

// NamedVolumeDir returns the path within the PV that's used to back the given
// path on the CLI.
func BindVolumeDir(cliPath string) string {
	return filepath.Join("bind", cliPath)
}
