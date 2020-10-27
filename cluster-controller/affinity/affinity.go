package affinity

import (
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kelda/blimp/pkg/auth"
)

const (
	// ColocateNamespaceKey is the pod label that's used to colocate pods in
	// the same namespace onto the same node. It should be set to sandbox's
	// namespace.
	ColocateNamespaceKey = "blimp.customer"

	// buildkitNodeKey is the node label used to designate that a node should
	// only run buildkit containers. These nodes should use Ubuntu as the host
	// OS rather than COS because rootless buildkit doesn't work on COS:
	// https://github.com/moby/buildkit/issues/879.
	buildkitNodeKey = "blimp.buildkit"
)

func OnBuilderNode() *corev1.Affinity {
	isolateBuildkit, ok := os.LookupEnv("ISOLATE_BUILDKIT")
	if ok && isolateBuildkit == "false" {
		// Let buildkit run on any node.
		return &corev1.Affinity{}
	}

	return newAffinity(onNode(buildkitNodeKey))
}

func ForUser(user auth.User) *corev1.Affinity {
	opts := []affinityOption{
		withPods(ColocateNamespaceKey, user.Namespace),
	}

	isolateBuildkit, ok := os.LookupEnv("ISOLATE_BUILDKIT")
	if !ok || isolateBuildkit != "false" {
		opts = append(opts, notNode(buildkitNodeKey))
	}

	return newAffinity(opts...)
}

func newAffinity(opts ...affinityOption) *corev1.Affinity {
	affinity := &corev1.Affinity{}
	for _, opt := range opts {
		opt(affinity)
	}
	return affinity
}

type affinityOption func(*corev1.Affinity)

func onNode(key string) affinityOption {
	return func(affinity *corev1.Affinity) {
		addNodeSelector(affinity, corev1.NodeSelectorRequirement{
			Key:      key,
			Operator: corev1.NodeSelectorOpExists,
		})
	}
}

func notNode(key string) affinityOption {
	return func(affinity *corev1.Affinity) {
		addNodeSelector(affinity, corev1.NodeSelectorRequirement{
			Key:      key,
			Operator: corev1.NodeSelectorOpDoesNotExist,
		})
	}
}

func withPods(key, value string) affinityOption {
	return func(affinity *corev1.Affinity) {
		addPodAffinity(affinity, corev1.PodAffinityTerm{
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					key: value,
				},
			},
			TopologyKey: corev1.LabelHostname,
		})
	}
}

func addNodeSelector(affinity *corev1.Affinity, req corev1.NodeSelectorRequirement) {
	if affinity.NodeAffinity == nil {
		affinity.NodeAffinity = &corev1.NodeAffinity{}
	}
	if affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = &corev1.NodeSelector{}
	}
	if len(affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms) == 0 {
		affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = []corev1.NodeSelectorTerm{{}}
	}
	affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions = append(
		affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions,
		req)
}

func addPodAffinity(affinity *corev1.Affinity, req corev1.PodAffinityTerm) {
	if affinity.PodAffinity == nil {
		affinity.PodAffinity = &corev1.PodAffinity{}
	}
	affinity.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution = append(
		affinity.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
		req)
}
