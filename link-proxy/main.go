package main

import (
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	// Importing cluster-controller/node seems bad...
	"github.com/kelda-inc/blimp/cluster-controller/node"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda/blimp/pkg/errors"
)

type server struct {
	kubeClient kubernetes.Interface
}

var LinkProxyBaseHostname string

func main() {
	kubeClient, _, err := kube.GetClient()
	if err != nil {
		log.WithError(err).Fatal("Failed to get kubernetes client")
	}

	s := &server{
		kubeClient: kubeClient,
	}

	handler := httputil.ReverseProxy{
		Director: director,
		Transport: &http.Transport{
			DialContext: s.dialTunnelContext,
			// These are taken from http.DefaultTransport
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	httpServer := http.Server{
		Addr:    ":8000",
		Handler: &handler,
	}

	err = httpServer.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// Adjust requests by adding namespace info to req.URL.Host, where it will be
// used by our custom transport.
func director(req *http.Request) {
	// Make sure we don't get bamboozled into doing weird things. We expect
	// "<namespace>.blimp.dev".
	hostRegexp := regexp.MustCompile("^([0-9a-f]{32})\\." + regexp.QuoteMeta(LinkProxyBaseHostname) + "$")
	matches := hostRegexp.FindAllStringSubmatch(strings.ToLower(req.Host), 1)
	if len(matches) != 1 {
		// Host header did not match what we were expecting, abort.
		req.URL.Host = ""
		log.WithField("Host", req.Host).Info("Unexpected host")
		return
	}
	// Get the regexp subgroup for the namespace, and place it in req.URL.Host
	// for our transport to use.
	req.URL.Host = matches[0][1]
	req.URL.Scheme = "http"

	// Clear RemoteAddr from request so that it is not added to X-Forwarded-For.
	req.RemoteAddr = ""
}

func (s *server) getNodeController(namespace string) (addr, cert string, err error) {
	// This could also use the cluster manager AttachToSandbox gRPC, but this
	// seeemed simpler for now.
	_, err = s.kubeClient.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return "", "", errors.New("sandbox does not exist")
		}
		return "", "", errors.WithContext("get sandbox", err)
	}

	dnsPod, err := s.kubeClient.CoreV1().Pods(namespace).Get("dns", metav1.GetOptions{})
	if err != nil {
		return "", "", errors.WithContext("get sandbox node", err)
	}

	certSecret, err := s.kubeClient.CoreV1().Secrets(node.NodeControllerNamespace).Get(
		node.CertSecretName(dnsPod.Spec.NodeName), metav1.GetOptions{})
	if err != nil {
		return "", "", errors.WithContext("get node controller cert", err)
	}

	return certSecret.Annotations["host"], string(certSecret.Data["cert.pem"]), nil
}
