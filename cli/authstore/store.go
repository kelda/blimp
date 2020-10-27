package authstore

import (
	"io/ioutil"
	"os"

	"github.com/ghodss/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/errors"
)

type Store struct {
	Username string `json:"username"`

	KubeToken     string
	KubeHost      string
	KubeCACrt     string
	KubeNamespace string
}

func (store Store) KubeClient() (kubernetes.Interface, *rest.Config, error) {
	restConfig := &rest.Config{
		Host:        store.KubeHost,
		BearerToken: store.KubeToken,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte(store.KubeCACrt),
		},
	}

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	return kubeClient, restConfig, err
}

func (store Store) Save() error {
	configPath := getStorePath()
	configBytes, err := yaml.Marshal(store)
	if err != nil {
		return errors.WithContext("marshal yaml", err)
	}

	if err := ioutil.WriteFile(configPath, configBytes, 0600); err != nil {
		return errors.WithContext("write", err)
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
		return store, errors.WithContext("read", err)
	}

	if err := yaml.Unmarshal(configBytes, &store); err != nil {
		return store, errors.WithContext("parse yaml", err)
	}
	return store, nil
}
func getStorePath() string {
	return cfgdir.Expand("auth.yaml")
}
