package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/hash"
	"github.com/kelda-inc/blimp/pkg/metadata"
	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda-inc/blimp/pkg/volume"
)

type podBuilder struct {
	namespace   string
	managerIP   string
	builtImages map[string]string

	image      string
	pod        corev1.Pod
	configMaps []corev1.ConfigMap
}

func newPodBuilder(namespace, managerIP string, builtImages map[string]string) *podBuilder {
	return &podBuilder{
		namespace:   namespace,
		managerIP:   managerIP,
		builtImages: builtImages,
	}
}

func (b *podBuilder) ToPod(svc composeTypes.ServiceConfig) (corev1.Pod, []corev1.ConfigMap, error) {
	b.image = svc.Image
	if svc.Build != nil {
		b.image = b.builtImages[svc.Name]
		// TODO: Error if image DNE.
	}

	var nativeVolumes []composeTypes.ServiceVolumeConfig
	var bindVolumes []string
	for _, v := range svc.Volumes {
		switch v.Type {
		case composeTypes.VolumeTypeVolume:
			nativeVolumes = append(nativeVolumes, v)
		case composeTypes.VolumeTypeBind:
			bindVolumes = append(bindVolumes, v.Source)
		}
	}

	if len(nativeVolumes) != 0 {
		b.addVolumeSeeder(nativeVolumes)
	}

	if len(svc.DependsOn) != 0 {
		b.addWaiter(svc.Name, ContainerNameWaitDependsOn, sandbox.WaitSpec{DependsOn: marshalDependencies(svc.DependsOn, svc.Links)})
	}

	if len(bindVolumes) != 0 {
		b.addWaiter(svc.Name, ContainerNameWaitInitialSync, sandbox.WaitSpec{BindVolumes: bindVolumes})
	}

	if err := b.addRuntimeContainer(svc); err != nil {
		return corev1.Pod{}, nil, err
	}
	b.sanitize()
	return b.pod, b.configMaps, nil
}

func (b *podBuilder) addVolumeSeeder(volumes []composeTypes.ServiceVolumeConfig) {
	// Write blimp-cp and cp to a volume so that we can access them from the
	// user's image.
	b.addVolume(corev1.Volume{
		Name: "vcpbin",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	vcpBinMount := []corev1.VolumeMount{{
		Name:      "vcpbin",
		MountPath: "/vcpbin",
	}}

	b.addInitContainers(
		corev1.Container{
			Name:            ContainerNameCopyBusybox,
			Image:           version.InitImage,
			ImagePullPolicy: "Always",
			Command:         []string{"/bin/cp", "/bin/busybox.static", "/vcpbin/cp"},
			VolumeMounts:    vcpBinMount,
		},
		corev1.Container{
			Name:            ContainerNameCopyVCP,
			Image:           version.InitImage,
			ImagePullPolicy: "Always",
			Command:         []string{"/bin/cp", "/bin/blimp-vcp", "/vcpbin/blimp-cp"},
			VolumeMounts:    vcpBinMount,
		},
	)

	// Configure the container that executes the copy from the image filesystem
	// into the volume.
	var vcpMounts []corev1.VolumeMount
	var vcpArgs []string
	for _, v := range volumes {
		kubeVol := volume.GetVolume(b.namespace, v.Source)
		b.addVolume(kubeVol)

		// vcpTarget needs to account for the volume's source and target to avoid
		// conflicts if the container mounts the same volume to two different
		// paths.
		vcpTarget := "/vcp-mount" + hash.DnsCompliant(v.Source+v.Target)
		vcpMounts = append(vcpMounts, corev1.VolumeMount{
			Name:      kubeVol.Name,
			MountPath: vcpTarget,
		})
		vcpArgs = append(vcpArgs, fmt.Sprintf("%s/.:%s", v.Target, vcpTarget))
	}

	b.addInitContainers(
		corev1.Container{
			Name:            ContainerNameInitializeVolumeFromImage,
			Image:           b.image,
			ImagePullPolicy: "Always",
			Command:         append([]string{"/vcpbin/blimp-cp", "/vcpbin/cp"}, vcpArgs...),
			VolumeMounts:    append(vcpBinMount, vcpMounts...),
		},
	)
}

func (b *podBuilder) addRuntimeContainer(svc composeTypes.ServiceConfig) error {
	b.pod.Namespace = b.namespace
	b.pod.Name = svc.Name
	b.pod.Labels = map[string]string{
		"blimp.service":     svc.Name,
		"blimp.customerPod": "true",
		"blimp.customer":    b.namespace,
	}

	bindVolumeRoot := volume.BindVolumeRoot(b.namespace)
	b.addVolume(bindVolumeRoot)

	var volumeMounts []corev1.VolumeMount
	for _, v := range svc.Volumes {
		switch v.Type {
		case composeTypes.VolumeTypeVolume:
			kubeVol := volume.GetVolume(b.namespace, v.Source)
			b.addVolume(kubeVol)
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      kubeVol.Name,
				MountPath: v.Target,
			})
		case composeTypes.VolumeTypeBind:
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      bindVolumeRoot.Name,
				MountPath: v.Target,
				SubPath:   strings.TrimPrefix(v.Source, "/"),
			})
		}
	}

	var securityContext *corev1.SecurityContext
	if svc.User != "" {
		securityContext = &corev1.SecurityContext{}
		var ids []int
		for _, idStr := range strings.Split(svc.User, ":") {
			id, err := strconv.Atoi(idStr)
			if err != nil {
				return errors.NewFriendlyError("Invalid user field (%s) for service %s.\n"+
					"Only numeric IDs are allowed. Please convert the user and group name to a numeric ID.",
					svc.User, svc.Name)
			}

			ids = append(ids, id)
		}

		// The first ID is the user, and the second (optional) ID is the group.
		switch len(ids) {
		case 1:
			user := int64(ids[0])
			securityContext.RunAsUser = &user
		case 2:
			user := int64(ids[0])
			group := int64(ids[1])
			securityContext.RunAsUser = &user
			securityContext.RunAsGroup = &group
		default:
			return errors.NewFriendlyError("Invalid user field (%s) for service %s.\n" +
				"Expected at most two values.")
		}
	}

	b.pod.Spec.Containers = []corev1.Container{
		{
			Args:            svc.Command,
			Command:         svc.Entrypoint,
			Env:             toEnvVars(svc.Environment),
			Image:           b.image,
			ImagePullPolicy: "Always",
			Name:            svc.Name,
			SecurityContext: securityContext,
			Stdin:           svc.StdinOpen,
			TTY:             svc.Tty,
			VolumeMounts:    volumeMounts,
			WorkingDir:      svc.WorkingDir,
			ReadinessProbe:  toReadinessProbe(svc.HealthCheck),
		},
	}

	// Blimp doesn't support multiple networks, so just aggregate the
	// aliases from all of them.
	var aliases []string
	for _, network := range svc.Networks {
		if network == nil {
			continue
		}
		aliases = append(aliases, network.Aliases...)
	}

	b.pod.Annotations = map[string]string{}
	if len(aliases) > 0 {
		b.pod.Annotations[metadata.AliasesKey] = metadata.Aliases(aliases)
	}

	// Set the pod's hostname.
	b.pod.Spec.Hostname = svc.Name
	if svc.Hostname != "" {
		b.pod.Spec.Hostname = svc.Hostname
	}

	// Collect a map of ips to their aliases.
	aliasMap := map[string][]string{}
	for _, hostAlias := range svc.ExtraHosts {
		aliasParts := strings.Split(hostAlias, ":")
		if len(aliasParts) != 2 {
			return errors.NewFriendlyError("Malformed extra_hosts alias: %s.\n"+
				"Expected format hostname:ip", hostAlias)
		}

		hostname := aliasParts[0]
		ip := aliasParts[1]
		aliasMap[ip] = append(aliasMap[ip], hostname)
	}

	var hostAliases []corev1.HostAlias
	for ip, hostnames := range aliasMap {
		hostAliases = append(hostAliases, corev1.HostAlias{
			IP:        ip,
			Hostnames: hostnames,
		})
	}

	// Sort for consistency.
	sort.Slice(hostAliases, func(i, j int) bool { return hostAliases[i].IP < hostAliases[j].IP })
	b.pod.Spec.HostAliases = hostAliases

	// Set the pod's restart policy.
	b.pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	switch svc.Restart {
	case "no":
		b.pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	case "always":
		b.pod.Spec.RestartPolicy = corev1.RestartPolicyAlways
	case "on-failure":
		b.pod.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
	}

	// Setup DNS.
	b.pod.Spec.DNSPolicy = corev1.DNSNone
	b.pod.Spec.DNSConfig = &corev1.PodDNSConfig{
		Nameservers: []string{b.managerIP},
		// TODO: There's Searches and Options, look into how to replicate these.
	}

	// Setup image credentials.
	b.pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
		{Name: "registry-auth"},
	}
	b.pod.Spec.ServiceAccountName = "pod-runner"
	b.pod.Spec.Affinity = sameNodeAffinity(b.namespace)

	// Disable the environment variables that are automatically
	// added by Kubernetes (e.g. SANDBOX_SERVICE_PORT).
	b.pod.Spec.EnableServiceLinks = falsePtr()

	return nil
}

func toEnvVars(vars composeTypes.MappingWithEquals) (kubeVars []corev1.EnvVar) {
	for k, vPtr := range vars {
		// vPtr may be nil if only the key is specified.
		var v string
		if vPtr != nil {
			v = *vPtr
		}

		// Escape dollar signs to disable interpolation by Kubernetes. Any variable
		// interpolation will have occured by now during the initial parsing of
		// the Docker Compose file.
		v = strings.Replace(v, "$", "$$", -1)

		kubeVars = append(kubeVars, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	// Sort for consistency to avoid unnecessary pod restarts.
	sort.Slice(kubeVars, func(i, j int) bool {
		return kubeVars[i].Name < kubeVars[j].Name
	})
	return
}

func toReadinessProbe(healthCheck *composeTypes.HealthCheckConfig) *corev1.Probe {
	if healthCheck == nil || len(healthCheck.Test) <= 1 {
		return nil
	}

	var command []string
	switch healthCheck.Test[0] {
	case "NONE":
		return nil
	case "CMD":
		command = healthCheck.Test[1:]
	case "CMD-SHELL":
		command = []string{"sh", "-c", healthCheck.Test[1]}
	default:
		// XXX: We should really inform the user that we failed to parse the
		// healthcheck, but we currently don't have a way of sending warnings
		// back to the CLI.
		log.WithField("command", command).Warn("Ignoring healthcheck with unrecognized command")
		return nil
	}

	probe := &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: command,
			},
		},
	}

	if healthCheck.Timeout != nil {
		probe.TimeoutSeconds = int32(time.Duration(*healthCheck.Timeout).Seconds())
	}
	if healthCheck.Interval != nil {
		probe.PeriodSeconds = int32(time.Duration(*healthCheck.Interval).Seconds())
	}
	if healthCheck.StartPeriod != nil {
		probe.InitialDelaySeconds = int32(time.Duration(*healthCheck.StartPeriod).Seconds())
	}
	if healthCheck.Retries != nil {
		probe.FailureThreshold = int32(*healthCheck.Retries)
	}

	return probe
}

func marshalDependencies(dependsOn composeTypes.DependsOnConfig, links []string) map[string]*sandbox.ServiceCondition {
	pbDeps := map[string]*sandbox.ServiceCondition{}
	for name, condition := range dependsOn {
		pbDeps[name] = &sandbox.ServiceCondition{Condition: condition.Condition}
	}

	for _, link := range links {
		var service string
		switch linkParts := strings.Split(link, ":"); len(linkParts) {
		case 1, 2:
			service = linkParts[0]
		default:
			log.WithField("link", link).Warn("Malformed link. Ignoring.")
			continue
		}

		// Any dependency conditions specified in `depends_on` take precedence.
		if _, ok := pbDeps[service]; !ok {
			pbDeps[service] = &sandbox.ServiceCondition{Condition: composeTypes.ServiceConditionStarted}
		}
	}

	return pbDeps
}

func (b *podBuilder) sanitize() {
	// Retain the same order to avoid unnecessary changes to the pod spec.
	var volumes []corev1.Volume
	volumesSet := map[string]struct{}{}
	for _, volume := range b.pod.Spec.Volumes {
		if _, ok := volumesSet[volume.Name]; ok {
			continue
		}

		volumes = append(volumes, volume)
		volumesSet[volume.Name] = struct{}{}
	}

	b.pod.Spec.Volumes = volumes
}

// Each pod has a corresponding ConfigMap containing the dependencies
// it requires before it should boot. This ConfigMap is mounted as a
// volume into the pod's init container. The init container passes it
// to the sandbox controller, which blocks boot until the requirements
// are met.
func (b *podBuilder) addWaiter(svcName, waitType string, spec sandbox.WaitSpec) error {
	waitSpecBytes, err := proto.Marshal(&spec)
	if err != nil {
		return errors.WithContext("marshal wait spec", err)
	}

	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: b.namespace,
			Name:      fmt.Sprintf("wait-spec-%s-%s", waitType, svcName),
		},
		BinaryData: map[string][]byte{
			"wait-spec": waitSpecBytes,
		},
	}
	b.addConfigMap(configMap)

	volume := corev1.Volume{
		Name: fmt.Sprintf("wait-spec-%s-%s", waitType, svcName),
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configMap.Name,
				},
				Items: []corev1.KeyToPath{
					{Key: "wait-spec", Path: "wait-spec"},
				},
			},
		},
	}
	b.addVolume(volume)

	container := corev1.Container{
		Name:            waitType,
		Image:           version.InitImage,
		ImagePullPolicy: "Always",
		Env: []corev1.EnvVar{
			{
				Name:  "SANDBOX_MANAGER_HOST",
				Value: b.managerIP,
			},

			// Trigger a restart if the wait spec changes.
			{
				Name:  "WAIT_SPEC_HASH",
				Value: hash.Bytes(waitSpecBytes),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      volume.Name,
				MountPath: "/etc/blimp",
			},
		},
	}
	b.addInitContainers(container)

	return nil
}

func (b *podBuilder) addVolume(v corev1.Volume) {
	b.pod.Spec.Volumes = append(b.pod.Spec.Volumes, v)
}

func (b *podBuilder) addInitContainers(containers ...corev1.Container) {
	b.pod.Spec.InitContainers = append(b.pod.Spec.InitContainers, containers...)
}

func (b *podBuilder) addConfigMap(cm corev1.ConfigMap) {
	b.configMaps = append(b.configMaps, cm)
}

func falsePtr() *bool {
	f := false
	return &f
}
