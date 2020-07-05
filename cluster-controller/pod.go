package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kelda-inc/blimp/cluster-controller/volume"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/metadata"
	"github.com/kelda-inc/blimp/pkg/proto/wait"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/hash"
	"github.com/kelda/blimp/pkg/names"
	"github.com/kelda/blimp/pkg/strs"
)

const (
	cpuRequest         = 20
	cpuRequestUnits    = "m"
	memoryRequest      = 50
	memoryRequestUnits = "Mi"
)

type podBuilder struct {
	namespace        string
	dnsIP            string
	nodeControllerIP string
	builtImages      map[string]string
	// builtTags maps custom tags defined in the docker-compose.yml to the
	// corresponding pushed images. For instance, if a service is defined with a
	// build context and `image: myimage:v3`, then builtTags will map
	// "myimage:v3" to the builtImage for the service.
	builtTags         map[string]string
	svcAliasesMapping map[string][]string
	volumeToServices  map[string][]string
}

type podSpec struct {
	namespace  string
	image      string
	pod        corev1.Pod
	configMaps []corev1.ConfigMap
}

func newPodBuilder(namespace, dnsIP, nodeControllerIP string, builtImages map[string]string,
	services []composeTypes.ServiceConfig) (podBuilder, error) {

	serviceToAliases := make(map[string][]string)
	aliasToService := make(map[string]string)
	for _, svc := range services {
		for _, link := range svc.Links {
			var svcToBeAliased, alias string
			switch linkParts := strings.Split(link, ":"); len(linkParts) {
			// A link without an alias. Nothing for us to do.
			case 1:
				continue
			case 2:
				svcToBeAliased = linkParts[0]
				alias = linkParts[1]
			default:
				log.WithField("link", link).Warn("Link in unexpected format. Skipping.")
				continue
			}

			// Error if two services are using the same alias for different services.
			if svcPresent, added := aliasToService[alias]; added && svcPresent != svcToBeAliased {
				return podBuilder{}, errors.NewFriendlyError(
					"links error: service %s and %s are using %s to refer to different services",
					svcPresent, svcToBeAliased, alias)
			}

			aliasToService[alias] = svcToBeAliased
			serviceToAliases[svcToBeAliased] = append(serviceToAliases[svcToBeAliased], alias)
		}
	}

	builtTags := map[string]string{}
	for _, svc := range services {
		if svc.Build != nil && svc.Image != "" {
			builtTags[svc.Image] = builtImages[svc.Name]
		}
	}

	volumeToServices := map[string][]string{}
	for _, svc := range services {
		for _, v := range svc.Volumes {
			if v.Type != composeTypes.VolumeTypeVolume {
				continue
			}
			volumeToServices[v.Source] = append(volumeToServices[v.Source], svc.Name)
		}
	}

	return podBuilder{
		namespace:         namespace,
		dnsIP:             dnsIP,
		nodeControllerIP:  nodeControllerIP,
		builtImages:       builtImages,
		builtTags:         builtTags,
		svcAliasesMapping: serviceToAliases,
		volumeToServices:  volumeToServices,
	}, nil
}

func (b podBuilder) ToPod(svc composeTypes.ServiceConfig) (corev1.Pod, []corev1.ConfigMap, error) {
	spec := podSpec{namespace: b.namespace}
	if svc.Build != nil {
		spec.image = b.builtImages[svc.Name]
		// TODO: Error if image DNE.
	} else {
		spec.image = svc.Image
		if builtTag, ok := b.builtTags[spec.image]; ok {
			spec.image = builtTag
		}
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
		spec.addVolumeSeeder(nativeVolumes)

		var servicesSharingVolumes []string
		for _, volume := range nativeVolumes {
			servicesSharingVolumes = append(servicesSharingVolumes, b.volumeToServices[volume.Source]...)
		}
		servicesSharingVolumes = remove(strs.Unique(servicesSharingVolumes), svc.Name)
		if len(servicesSharingVolumes) != 0 {
			err := spec.addWaiter(b.nodeControllerIP, svc.Name, kube.ContainerNameWaitInitializedVolumes,
				wait.WaitSpec{FinishedVolumeInit: servicesSharingVolumes})
			if err != nil {
				return corev1.Pod{}, nil, err
			}
		}
	}

	if len(svc.DependsOn) != 0 {
		err := spec.addWaiter(b.nodeControllerIP, svc.Name, kube.ContainerNameWaitDependsOn,
			wait.WaitSpec{DependsOn: marshalDependencies(svc.DependsOn, svc.Links)})
		if err != nil {
			return corev1.Pod{}, nil, err
		}
	}

	if len(bindVolumes) != 0 {
		err := spec.addWaiter(b.nodeControllerIP, svc.Name, kube.ContainerNameWaitInitialSync,
			wait.WaitSpec{BindVolumes: bindVolumes})
		if err != nil {
			return corev1.Pod{}, nil, err
		}
	}

	if err := spec.addRuntimeContainer(svc, b.dnsIP, b.svcAliasesMapping); err != nil {
		return corev1.Pod{}, nil, err
	}
	spec.sanitize()
	return spec.pod, spec.configMaps, nil
}

func (p *podSpec) addVolumeSeeder(volumes []composeTypes.ServiceVolumeConfig) {
	// Write blimp-cp and cp to a volume so that we can access them from the
	// user's image.
	p.addVolume(corev1.Volume{
		Name: "vcpbin",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	vcpBinMount := []corev1.VolumeMount{{
		Name:      "vcpbin",
		MountPath: "/vcpbin",
	}}

	p.addInitContainers(
		corev1.Container{
			Name:  kube.ContainerNameCopyVCP,
			Image: version.InitImage,
			Command: []string{"sh", "-c",
				"/bin/cp /bin/busybox.static /vcpbin/cp && " +
					"/bin/cp /bin/blimp-vcp /vcpbin/blimp-cp"},
			VolumeMounts: vcpBinMount,
		},
	)

	// Mount all the volumes for the namespace so that vcp can copy into them.
	p.addVolume(volume.PersistentVolume)

	// Configure the container that executes the copy from the image filesystem
	// into the volume.
	var vcpArgs []string
	for _, v := range volumes {
		vcpTarget := filepath.Join("/pv", volume.NamedVolumeDir(v.Source))
		vcpArgs = append(vcpArgs, fmt.Sprintf("%s:%s", v.Target, vcpTarget))
	}

	// In GKE, host path volumes are created as root.
	hostPathOwner := int64(0)
	p.addInitContainers(
		corev1.Container{
			Name:    kube.ContainerNameInitializeVolumeFromImage,
			Image:   p.image,
			Command: append([]string{"/vcpbin/blimp-cp", "/vcpbin/cp"}, vcpArgs...),
			SecurityContext: &corev1.SecurityContext{
				// Run the container as the directory's owner so that vcp can
				// write to it. Note that this UID doesn't need to exist within
				// the container -- it just needs to match up with the UID in
				// the host's filesystem.
				RunAsUser: &hostPathOwner,
			},
			VolumeMounts: append(vcpBinMount, corev1.VolumeMount{
				Name:      volume.PersistentVolume.Name,
				MountPath: "/pv",
			}),
			Env: []corev1.EnvVar{
				{
					Name: "NAMESPACE",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.namespace",
						},
					},
				},
			},
		},
	)
}

func (p *podSpec) addRuntimeContainer(svc composeTypes.ServiceConfig, dnsIP string,
	svcAliasesMapping map[string][]string) error {

	p.pod.Namespace = p.namespace
	p.pod.Name = names.PodName(svc.Name)
	p.pod.Labels = map[string]string{
		"blimp.service":     svc.Name,
		"blimp.customerPod": "true",
		"blimp.customer":    p.namespace,
	}

	var volumeMounts []corev1.VolumeMount
	for _, v := range svc.Volumes {
		switch v.Type {
		case composeTypes.VolumeTypeVolume:
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      volume.PersistentVolume.Name,
				SubPath:   volume.NamedVolumeDir(v.Source),
				MountPath: v.Target,
			})
		case composeTypes.VolumeTypeBind:
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      volume.PersistentVolume.Name,
				MountPath: v.Target,
				SubPath:   volume.BindVolumeDir(v.Source),
			})
		}
	}

	if len(volumeMounts) != 0 {
		p.addVolume(volume.PersistentVolume)
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
			return errors.NewFriendlyError("Invalid user field (%s) for service %s.\n"+
				"Expected at most two values.", svc.User, svc.Name)
		}
	}

	p.pod.Spec.Containers = []corev1.Container{
		{
			Args:            svc.Command,
			Command:         svc.Entrypoint,
			Env:             toEnvVars(svc.Environment),
			Image:           p.image,
			ImagePullPolicy: "Always",
			Name:            names.PodName(svc.Name),
			SecurityContext: securityContext,
			Stdin:           svc.StdinOpen,
			TTY:             svc.Tty,
			VolumeMounts:    volumeMounts,
			WorkingDir:      svc.WorkingDir,
			ReadinessProbe:  toReadinessProbe(svc.HealthCheck),
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("4"),
					"memory": resource.MustParse("16Gi"),
				},
				// If Requests are not set, they will default to the
				// same as the Limits, which are too high.
				Requests: corev1.ResourceList{
					"cpu": resource.MustParse(
						fmt.Sprintf("%d%s", cpuRequest, cpuRequestUnits)),
					"memory": resource.MustParse(
						fmt.Sprintf("%d%s", memoryRequest, memoryRequestUnits)),
				},
			},
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

	aliases = append(aliases, svcAliasesMapping[svc.Name]...)
	if svc.ContainerName != "" {
		aliases = append(aliases, svc.ContainerName)
	}

	p.pod.Annotations = map[string]string{}
	if len(aliases) > 0 {
		p.pod.Annotations[metadata.AliasesKey] = metadata.Aliases(aliases)
	}

	// Set the pod's hostname.
	// Ignore the hostname setting if it's not a valid Kubernetes hostname.
	// Although this may break some applications, it's better than aborting the deployment entirely since
	// most applications don't seem to rely on the container's hostname.
	if svc.Hostname != "" && !strings.Contains(svc.Hostname, "_") {
		p.pod.Spec.Hostname = svc.Hostname
	} else if !strings.Contains(svc.Name, "_") {
		p.pod.Spec.Hostname = svc.Name
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
	p.pod.Spec.HostAliases = hostAliases

	// Set the pod's restart policy.
	p.pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	switch svc.Restart {
	case "no":
		p.pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	case "always", "unless-stopped":
		p.pod.Spec.RestartPolicy = corev1.RestartPolicyAlways
	case "on-failure":
		p.pod.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
	}

	// Setup DNS.
	p.pod.Spec.DNSPolicy = corev1.DNSNone
	p.pod.Spec.DNSConfig = &corev1.PodDNSConfig{
		Nameservers: []string{dnsIP},
		// TODO: There's Searches and Options, look into how to replicate these.
	}

	// Setup image credentials.
	p.pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
		{Name: "registry-auth"},
	}
	p.pod.Spec.ServiceAccountName = "pod-runner"
	p.pod.Spec.Affinity = sameNodeAffinity(p.namespace)

	// Disable the environment variables that are automatically
	// added by Kubernetes (e.g. SANDBOX_SERVICE_PORT).
	p.pod.Spec.EnableServiceLinks = falsePtr()

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
		// interpolation will have occurred by now during the initial parsing of
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

		// We use the Docker defaults for the healthcheck settings, rather than
		// the Kubernetes defaults.
		// By default, Kubernetes checks more aggressively (e.g. its default
		// check interval is 10 seconds), which exacerbates Docker performance
		// issues with exec probes.
		//
		// We don't know the root cause of the performance issues, but for some
		// possible related issues see:
		// * https://github.com/kubernetes/kubernetes/issues/82440
		// * https://serverfault.com/questions/973817/google-cloud-kuberbetes-run-away-systemd-100-cpu-usage
		TimeoutSeconds:      30,
		PeriodSeconds:       30,
		InitialDelaySeconds: 0,
		FailureThreshold:    3,
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

func marshalDependencies(dependsOn composeTypes.DependsOnConfig, links []string) []*wait.ServiceCondition {
	pbDeps := []*wait.ServiceCondition{}
	for name, condition := range dependsOn {
		pbDeps = append(pbDeps, &wait.ServiceCondition{
			Service:   name,
			Condition: condition.Condition,
		})
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

		depExists := func() bool {
			for _, dep := range pbDeps {
				if dep.Service == service {
					return true
				}
			}
			return false
		}

		// Any dependency conditions specified in `depends_on` take precedence.
		if !depExists() {
			pbDeps = append(pbDeps, &wait.ServiceCondition{
				Service:   service,
				Condition: composeTypes.ServiceConditionStarted,
			})
		}
	}

	sort.Slice(pbDeps, func(i, j int) bool {
		return strings.Compare(pbDeps[i].Service, pbDeps[j].Service) > 0
	})

	return pbDeps
}

func (p *podSpec) sanitize() {
	// Retain the same order to avoid unnecessary changes to the pod spec.
	var volumes []corev1.Volume
	volumesSet := map[string]struct{}{}
	for _, volume := range p.pod.Spec.Volumes {
		if _, ok := volumesSet[volume.Name]; ok {
			continue
		}

		volumes = append(volumes, volume)
		volumesSet[volume.Name] = struct{}{}
	}

	p.pod.Spec.Volumes = volumes
}

// Each pod has a corresponding ConfigMap containing the dependencies
// it requires before it should boot. This ConfigMap is mounted as a
// volume into the pod's init container. The init container passes it
// to the node controller, which blocks boot until the requirements
// are met.
func (p *podSpec) addWaiter(nodeControllerIP, svcName, waitType string, spec wait.WaitSpec) error {
	waitSpecBytes, err := proto.Marshal(&spec)
	if err != nil {
		return errors.WithContext("marshal wait spec", err)
	}

	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: p.namespace,
			Name:      names.PodName(fmt.Sprintf("wait-spec-%s-%s", waitType, svcName)),
		},
		BinaryData: map[string][]byte{
			"wait-spec": waitSpecBytes,
		},
	}
	p.addConfigMap(configMap)

	volume := corev1.Volume{
		Name: configMap.Name,
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
	p.addVolume(volume)

	container := corev1.Container{
		Name:  waitType,
		Image: version.InitImage,
		Env: []corev1.EnvVar{
			{
				Name:  "NODE_CONTROLLER_HOST",
				Value: nodeControllerIP,
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
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
	p.addInitContainers(container)

	return nil
}

func (p *podSpec) addVolume(v corev1.Volume) {
	p.pod.Spec.Volumes = append(p.pod.Spec.Volumes, v)
}

func (p *podSpec) addInitContainers(containers ...corev1.Container) {
	p.pod.Spec.InitContainers = append(p.pod.Spec.InitContainers, containers...)
}

func (p *podSpec) addConfigMap(cm corev1.ConfigMap) {
	p.configMaps = append(p.configMaps, cm)
}

func falsePtr() *bool {
	f := false
	return &f
}

func remove(strs []string, toRemove string) (removed []string) {
	for _, str := range strs {
		if str != toRemove {
			removed = append(removed, str)
		}
	}
	return removed
}
