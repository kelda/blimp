package volume

import (
	"context"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/kubewait"
)

const (
	// pvNamespaceLabel is the label used to associate a PersistentVolume with
	// a user namespace.
	pvNamespaceLabel = "blimp.kelda.io/namespace"

	// pvSize is the size of the PersistentVolume allocated to each user. The
	// user will experience out of disk errors if the combined size of all bind
	// and named volumes exceeds this amount.
	pvSize = "25Gi"
)

// CreatePVC ensures that the namespace's PersistentVolumeClaim exists, and is
// bound to user's PersistentVolume. This PVC can then be referenced by other
// pods in the namespace to mount specific volumes.
func CreatePVC(ctx context.Context, kubeClient kubernetes.Interface, namespace string) error {
	persistentFs := corev1.PersistentVolumeFilesystem
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      PersistentVolumeClaimName,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(pvSize),
				},
			},
			VolumeMode: &persistentFs,
		},
	}

	// If the PVC already exists, there's nothing more for us to do.
	pvcClient := kubeClient.CoreV1().PersistentVolumeClaims(namespace)
	if _, err := pvcClient.Get(pvc.Name, metav1.GetOptions{}); err == nil {
		return nil
	} else if !kerrors.IsNotFound(err) {
		return errors.WithContext("get pvc", err)
	}

	// Get the PV for the namespace. Create it if it doesn't already exist.
	var pvName string
	switch pv, err := getPersistentVolume(kubeClient, namespace); err {
	case nil:
		// PersistentVolumes enter the Released phase when their associated
		// PersistentVolumeClaim is deleted (i.e. when `blimp down` is run).
		// When this happens, we make the volume available for the PVC we're
		// about to create.
		if pv.Status.Phase == corev1.VolumeReleased {
			if err := updatePersistentVolume(kubeClient, pv.Name, makeAvailable); err != nil {
				return errors.WithContext("make persistent volume available", err)
			}
		}
		pvName = pv.Name
	case errNoPersistentVolume:
		pvName, err = createPersistentVolume(ctx, kubeClient, namespace, pvc.Spec)
		if err != nil {
			return errors.WithContext("create persistent volume", err)
		}
	default:
		return errors.WithContext("get current persistent volume", err)
	}

	// Create the PVC attached to the namespace's PV.
	pvc.Spec.VolumeName = pvName
	if _, err := pvcClient.Create(pvc); err != nil && !kerrors.IsAlreadyExists(err) {
		return errors.WithContext("create pvc", err)
	}

	// Wait for the PVC to bind so that pods that reference the PVC don't error
	// while the PVC is pending.
	err := kubewait.WaitForObject(ctx,
		pvcGetter(kubeClient, namespace, pvc.Name),
		pvcClient.Watch,
		func(pvcIntf interface{}) bool {
			return pvcIntf.(*corev1.PersistentVolumeClaim).Status.Phase == corev1.ClaimBound
		})
	if err != nil {
		return errors.WithContext("wait for pvc to bind", err)
	}

	return nil
}

// PermanentlyDeletePVC deletes the namespace's persistent volume, and its
// underlying storage.
// This function only sends the required requests to the API server. It does
// not block on the PVC actually being deleted.
// If any pods reference the PVC, Kubernetes will block the PVC and
// PV deletion until the pods have been deleted.
func PermanentlyDeletePVC(kubeClient kubernetes.Interface, namespace string) error {
	pvcClient := kubeClient.CoreV1().PersistentVolumeClaims(namespace)
	pvc, err := pvcClient.Get(PersistentVolumeClaimName, metav1.GetOptions{})
	if err != nil {
		// There's no PVC, so there's nothing more to do.
		if kerrors.IsNotFound(err) {
			return nil
		}

		return errors.WithContext("get pvc", err)
	}

	err = updatePersistentVolume(kubeClient, pvc.Spec.VolumeName,
		func(pv corev1.PersistentVolume) (corev1.PersistentVolume, bool) {
			// Don't allow this PV to be reused.
			delete(pv.Labels, pvNamespaceLabel)

			// Signal to the PersistentVolume controller that the
			// PV, and its underlying storage, should be deleted
			// once its corresponding PVC is deleted.
			pv.Spec.PersistentVolumeReclaimPolicy = corev1.PersistentVolumeReclaimDelete
			return pv, true
		})
	if err != nil {
		return errors.WithContext("update pv reclaim policy", err)
	}

	// Signal to Kubernetes that we want to delete the PVC. Note that deletion
	// won't happen immediately because of the Kubernetes finalizer which
	// blocks PVC deletion until pods that reference the PVC have been deleted.
	if err := pvcClient.Delete(PersistentVolumeClaimName, &metav1.DeleteOptions{}); err != nil {
		return errors.WithContext("delete pvc", err)
	}
	return nil
}

// createPersistentVolume creates a new PersistentVolume for the given namespace.
func createPersistentVolume(ctx context.Context, kubeClient kubernetes.Interface,
	namespace string, spec corev1.PersistentVolumeClaimSpec) (string, error) {

	// Create a new PersistentVolume by creating a PersistentVolumeClaim. The
	// namespace that we create it in doesn't matter as long as it's
	// consistent, since the resulting PV isn't namespaced.
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kube.BlimpNamespace,
			Name:      namespace,
		},
		Spec: spec,
	}
	pvcClient := kubeClient.CoreV1().PersistentVolumeClaims(pvc.Namespace)
	if _, err := pvcClient.Create(pvc); err != nil && !kerrors.IsAlreadyExists(err) {
		return "", errors.WithContext("create seed pvc", err)
	}

	// Wait for the corresponding PV to be created.
	var pvName string
	err := kubewait.WaitForObject(ctx,
		pvcGetter(kubeClient, pvc.Namespace, pvc.Name),
		pvcClient.Watch,
		func(pvcIntf interface{}) bool {
			pvName = pvcIntf.(*corev1.PersistentVolumeClaim).Spec.VolumeName
			return pvName != ""
		})
	if err != nil {
		return "", errors.WithContext("wait for seed pvc to bind", err)
	}

	// Set the reclaim policy to Retain so that the volume isn't deleted when
	// the PVC is deleted.
	err = updatePersistentVolume(kubeClient, pvName,
		func(pv corev1.PersistentVolume) (corev1.PersistentVolume, bool) {
			pv.Spec.PersistentVolumeReclaimPolicy = corev1.PersistentVolumeReclaimRetain
			return pv, true
		})
	if err != nil {
		return "", errors.WithContext("update pv reclaim policy", err)
	}

	// Delete the PVC used to generate the PV.
	if err := pvcClient.Delete(pvc.Name, &metav1.DeleteOptions{}); err != nil {
		return "", errors.WithContext("delete seed pvc", err)
	}

	err = kubewait.WaitForObject(ctx,
		pvGetter(kubeClient, pvName),
		kubeClient.CoreV1().PersistentVolumes().Watch,
		func(pvIntf interface{}) bool {
			return pvIntf.(*corev1.PersistentVolume).Status.Phase == corev1.VolumeReleased
		})
	if err != nil {
		return "", errors.WithContext("wait for pvc to release claim", err)
	}

	// Claim the PV so that it's associated with the given namespace.
	err = updatePersistentVolume(kubeClient, pvName,
		func(pv corev1.PersistentVolume) (corev1.PersistentVolume, bool) {
			// Label the PV so that getPersistentVolume will return it in the
			// future.
			if pv.Labels == nil {
				pv.Labels = map[string]string{}
			}
			pv.Labels[pvNamespaceLabel] = namespace

			// Make the PV available for the namespace's PVC to mount.
			return makeAvailable(pv)
		})
	if err != nil {
		return "", errors.WithContext("claim pv", err)
	}

	return pvName, nil
}

// makeAvailable transforms the given PersistentVolume such that it can be
// bound by PVCs.
func makeAvailable(pv corev1.PersistentVolume) (corev1.PersistentVolume, bool) {
	// Abort if the PersistentVolume is bound. This shouldn't happen, but
	// may be possible if a bug causes someone else to steal the volume.
	if pv.Status.Phase == corev1.VolumeBound {
		log.WithField("name", pv.Name).Warn(
			"Attempted to release bound PersistentVolume. This is a sign of a race. Aborting.")
		return corev1.PersistentVolume{}, false
	}

	// Removing the claim reference causes the PV controller to change the PV's
	// status to Available.
	pv.Spec.ClaimRef = nil
	return pv, true
}

var errNoPersistentVolume = errors.New("no persistent volume")

// getPersistentVolume returns the PersistentVolume associated with the given
// namespace.
func getPersistentVolume(kubeClient kubernetes.Interface, namespace string) (
	corev1.PersistentVolume, error) {

	pvClient := kubeClient.CoreV1().PersistentVolumes()
	currPv, err := pvClient.List(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", pvNamespaceLabel, namespace),
	})
	if err != nil {
		return corev1.PersistentVolume{}, errors.WithContext("get", err)
	}

	switch len(currPv.Items) {
	case 0:
		return corev1.PersistentVolume{}, errNoPersistentVolume
	case 1:
		return currPv.Items[0], nil
	default:
		log.WithField("persistent volumes", currPv).Warn(
			"Multiple persistent volumes for the same namespace. This should never happen." +
				"Defaulting to the first volume.")
		sort.Slice(currPv.Items, func(i, j int) bool {
			return currPv.Items[i].Name < currPv.Items[j].Name
		})
		return currPv.Items[0], nil
	}
}

// pvUpdateFn specifies how to update a PersistentVolume. The update is aborted
// if the second return argument is false.
type pvUpdateFn func(corev1.PersistentVolume) (corev1.PersistentVolume, bool)

func updatePersistentVolume(kubeClient kubernetes.Interface, name string,
	fn pvUpdateFn) error {

	pvClient := kubeClient.CoreV1().PersistentVolumes()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		currPV, err := pvClient.Get(name, metav1.GetOptions{})
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil
			}
			return errors.WithContext("get", err)
		}

		newPV, ok := fn(*currPV)
		if !ok {
			return nil
		}

		_, err = pvClient.Update(&newPV)
		return err
	})
}

func pvcGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().PersistentVolumeClaims(namespace).
			Get(name, metav1.GetOptions{})
	}
}

func pvGetter(kubeClient kubernetes.Interface, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().PersistentVolumes().
			Get(name, metav1.GetOptions{})
	}
}
