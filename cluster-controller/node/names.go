package node

import (
	"fmt"
	"strings"
)

func nodeControllerName(node string) string {
	// Nodes on EKS may be full FQDNs including dots, but pod names cannot
	// include dots.
	sanitized := strings.ReplaceAll(node, ".", "-")
	return fmt.Sprintf("node-controller-%s", sanitized)
}

func CertSecretName(node string) string {
	return fmt.Sprintf("%s-cert", node)
}
