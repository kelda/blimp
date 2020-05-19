package finalizer

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/volume"
)

// Start starts a watcher that watches for namespaces in the terminating state,
// and cleans up any local volumes for the namespace.
func Start(kubeClient kubernetes.Interface, myNodeName string) {
	myFinalizer := kube.VolumeFinalizer(myNodeName)
	factory := informers.NewSharedInformerFactory(kubeClient, 30*time.Second).Core().V1().Namespaces()
	informer := factory.Informer()

	sync := func(obj interface{}) {
		ns, ok := obj.(*corev1.Namespace)
		if !ok {
			log.WithField("obj", obj).
				Warn("Unexpected non-Namespace object")
			return
		}

		if ns.Status.Phase != corev1.NamespaceTerminating || !hasItem(ns.Finalizers, myFinalizer) {
			return
		}

		if err := cleanupVolumes(ns.Name); err != nil {
			log.WithError(err).WithField("namespace", ns.Name).Error("Failed to cleanup namespace's volumes")
			return
		}

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			currNs, err := kubeClient.CoreV1().Namespaces().Get(ns.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			currNs.Finalizers = removeItem(currNs.Finalizers, myFinalizer)
			_, err = kubeClient.CoreV1().Namespaces().Finalize(currNs)
			return err
		})
		if err != nil {
			log.WithError(err).Error("Failed to update namespace's status after cleaning up volumes")
		}

	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: sync,
		UpdateFunc: func(_, intf interface{}) {
			sync(intf)
		},
	})

	go informer.Run(nil)
	cache.WaitForCacheSync(nil, informer.HasSynced)
}

func cleanupVolumes(namespace string) error {
	err := os.RemoveAll(volume.NamespaceRoot(namespace))
	// The directory may not exist if the finalizer has been run already, or
	// the namespace wasn't scheduled onto this node.
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func hasItem(slc []string, exp string) bool {
	_, ok := getIndex(slc, exp)
	return ok
}

func removeItem(slc []string, exp string) []string {
	i, ok := getIndex(slc, exp)
	if !ok {
		return slc
	}
	return append(slc[:i], slc[i+1:]...)
}

func getIndex(slc []string, exp string) (int, bool) {
	for i, x := range slc {
		if x == exp {
			return i, true
		}
	}
	return -1, false
}
