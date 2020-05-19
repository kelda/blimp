package volume

import (
	"path/filepath"

	corev1 "k8s.io/api/core/v1"

	"github.com/kelda-inc/blimp/pkg/hash"
)

const VolumeRoot = "/var/blimp/volumes"

func NamespaceRoot(namespace string) string {
	return filepath.Join(VolumeRoot, namespace)
}

func GetVolume(namespace, volume string) corev1.Volume {
	return hostPathVolume(namespace, volume)
}

func BindVolumeRoot(namespace string) corev1.Volume {
	return hostPathVolume(namespace, "bind")
}

func hostPathVolume(namespace, id string) corev1.Volume {
	id = hash.DnsCompliant(id)
	hostPathType := corev1.HostPathDirectoryOrCreate
	return corev1.Volume{
		Name: id,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: filepath.Join(NamespaceRoot(namespace), id),
				Type: &hostPathType,
			},
		},
	}
}
