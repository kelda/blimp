package node

import (
	"fmt"
)

func nodeControllerName(node string) string {
	return fmt.Sprintf("node-controller-%s", node)
}

func certSecretName(node string) string {
	return fmt.Sprintf("%s-cert", node)
}
