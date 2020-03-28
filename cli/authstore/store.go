package authstore

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ghodss/yaml"
	"github.com/kelda-inc/blimp/pkg/cfgdir"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Store struct {
	AuthToken string

	KubeToken     string
	KubeHost      string
	KubeCACrt     string
	KubeNamespace string
}

func (store Store) KubeClient() (kubernetes.Interface, *rest.Config, error) {
	restConfig := &rest.Config{
		Host: store.KubeHost,
		// TODO: Handle decode errors.
		BearerToken: store.KubeToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
			// TODO
			//CAData: mustEncodeBase64(store.KubeCaCrt),
		},
	}

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	return kubeClient, restConfig, err
}

func (store Store) Save() error {
	configPath := getStorePath()
	configBytes, err := yaml.Marshal(store)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	if err := ioutil.WriteFile(configPath, configBytes, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func New() (store Store, err error) {
	configPath := getStorePath()
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Store{}, nil
		}
		return store, fmt.Errorf("read: %w", err)
	}

	if err := yaml.Unmarshal(configBytes, &store); err != nil {
		return store, fmt.Errorf("parse yaml: %w", err)
	}
	return store, nil
}
func getStorePath() string {
	return cfgdir.Expand("auth.yaml")
}
