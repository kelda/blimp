package auth

import (
	"crypto/subtle"
	"os"

	"github.com/kelda/blimp/pkg/errors"
	proto "github.com/kelda/blimp/pkg/proto/auth"
)

func AuthorizeRequest(blimpAuth *proto.BlimpAuth) (User, error) {
	if clusterToken, ok := os.LookupEnv("BLIMP_CLUSTER_SECRET"); ok {
		if subtle.ConstantTimeCompare([]byte(blimpAuth.GetClusterAuth()), []byte(clusterToken)) != 1 {
			return User{}, errors.NewFriendlyError("You do not have authorization to access this cluster.")
		}
	}

	return ParseIDToken(blimpAuth.GetToken())
}

type AuthenticatedRequest interface {
	GetOldToken() string
	GetAuth() *proto.BlimpAuth
}

func GetAuth(req AuthenticatedRequest) *proto.BlimpAuth {
	if req.GetAuth() != nil {
		return req.GetAuth()
	}

	return &proto.BlimpAuth{
		Token: req.GetOldToken(),
	}
}
