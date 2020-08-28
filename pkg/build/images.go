package build

import (
	"fmt"
	"strings"

	"github.com/kelda/blimp/pkg/hash"
)

func BlimpServiceTag(absComposePath, svc string) string {
	return hash.DNSCompliant(fmt.Sprintf("%s-%s", absComposePath, svc))
}

func RemoteImageName(absComposePath, svc, namespace string) string {
	tag := BlimpServiceTag(absComposePath, svc)
	return fmt.Sprintf("%s/%s:%s", namespace, svc, tag)
}

func ReplaceTagWithDigest(imageName, digest string) string {
	stripped := strings.SplitN(imageName, ":", 2)[0]
	return fmt.Sprintf("%s@%s", stripped, digest)
}
