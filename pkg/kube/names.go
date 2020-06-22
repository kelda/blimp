package kube

import (
	"fmt"
)

const (
	ContainerNameCopyBusybox               = "copy-busybox"
	ContainerNameCopyVCP                   = "copy-vcp"
	ContainerNameInitializeVolumeFromImage = "vcp"
	ContainerNameWaitDependsOn             = "wait-depends-on"
	ContainerNameWaitInitialSync           = "wait-sync"
	ContainerNameWaitInitializedVolumes    = "wait-initialized-volumes"
)

// VolumeFinalizer is the finalizer used to signal that the given node needs to
// clean up the namespace's volumes.
func VolumeFinalizer(node string) string {
	return fmt.Sprintf("volume.blimp.kelda.io/%s", node)
}
