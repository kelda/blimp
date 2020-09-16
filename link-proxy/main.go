package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	// Importing cluster-controller/node seems bad...
	"github.com/kelda-inc/blimp/cluster-controller/node"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda/blimp/pkg/errors"
	nodeGRPC "github.com/kelda/blimp/pkg/proto/node"
)

type server struct {
	kubeClient kubernetes.Interface

	nodeConns      map[string]nodeGRPC.ControllerClient
	nodeConnsMutex sync.Mutex
}

var LinkProxyBaseHostname string

func main() {
	kubeClient, _, err := kube.GetClient()
	if err != nil {
		log.WithError(err).Fatal("Failed to get kubernetes client")
	}

	s := &server{
		kubeClient: kubeClient,
		nodeConns:  map[string]nodeGRPC.ControllerClient{},
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

func (s *server) getNodeControllerConn(ctx context.Context, namespace string) (
	conn nodeGRPC.ControllerClient, err error) {
	// This could also use the cluster manager AttachToSandbox gRPC, but this
	// seeemed simpler for now.
	dnsPod, err := s.kubeClient.CoreV1().Pods(namespace).Get("dns", metav1.GetOptions{})
	if err != nil {
		return nil, errors.WithContext("get sandbox node", err)
	}

	certSecret, err := s.kubeClient.CoreV1().Secrets(node.NodeControllerNamespace).Get(
		node.CertSecretName(dnsPod.Spec.NodeName), metav1.GetOptions{})
	if err != nil {
		return nil, errors.WithContext("get node controller cert", err)
	}

	nodeAddr := certSecret.Annotations["host"]

	s.nodeConnsMutex.Lock()
	defer s.nodeConnsMutex.Unlock()
	conn, ok := s.nodeConns[nodeAddr]
	if ok {
		return conn, nil
	}

	// We need to create a new connection for this node.
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certSecret.Data["cert.pem"]) {
		return nil, errors.New("failed to parse node controller cert")
	}
	nodeConn, err := grpc.DialContext(ctx, nodeAddr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, "")),
		// AWS ELBs close connections that are inactive for 60s, so we set a
		// keepalive interval lower than this.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
		grpc.WithUnaryInterceptor(errors.UnaryClientInterceptor))
	if err != nil {
		return nil, errors.WithContext("dial node controller", err)
	}

	conn = nodeGRPC.NewControllerClient(nodeConn)
	s.nodeConns[nodeAddr] = conn

	return conn, nil
}
