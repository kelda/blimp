package auth

import (
	"github.com/kelda/blimp/pkg/names"
)

type User struct {
	Namespace string
}

// Blimp used to use Auth0 for account management. Auth0 tokens were used to
// identify and authorize users.
// Blimp no longer does per-user authentication since only self-hosted clusters
// are supported. The "token" is used for namespacing resources, and access
// control to the cluster is controlled via a shared secret. Therefore, we
// don't do any validation on the token.
func ParseIDToken(token string) (User, error) {
	return User{Namespace: names.ToDNS1123(token)}, nil
}
