package kube

const (
	ContainerNameCopyVCP                   = "copy-vcp"
	ContainerNameInitializeVolumeFromImage = "vcp"
	ContainerNameWaitDependsOn             = "wait-depends-on"
	ContainerNameWaitInitialSync           = "wait-sync"
	ContainerNameWaitInitializedVolumes    = "wait-initialized-volumes"

	BlimpNamespace      = "blimp-system"
	PreviewCLINamespace = "blimp-cli"

	ExposeAnnotation            = "blimp.exposed"
	NodePublicAddressAnnotation = "blimp.public-address"

	PodNameSyncthing = "syncthing"
	PodNameBuildkitd = "buildkitd"
)
