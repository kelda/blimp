package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/docker/cli/cli/config/configfile"
	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types"

	// We use jsonpb rather than google.golang.org/protobuf/encoding/protojson
	// because we're still using v1 rather than v2 protobufs.
	"github.com/golang/protobuf/jsonpb"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/kelda/blimp/pkg/proto/auth"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

// JSONCredUsername is the username that we use for registry credentials to the
// Blimp registry to indicate that the password is a JSON-encoded
// auth.BlimpAuth, as opposed to a plain ID token.
const JSONCredUsername = "_json"

type RegistryCredentials map[string]types.AuthConfig

// GetLocalRegistryCredentials reads the user's registry credentials from their
// local machine.
func GetLocalRegistryCredentials(dockerConfig *configfile.ConfigFile) (RegistryCredentials, error) {
	// Get the insecure credentials that were saved directly to
	// the auths section of ~/.docker/config.json.
	creds := RegistryCredentials{}
	addCredentials := func(authConfigs map[string]clitypes.AuthConfig) {
		for host, cred := range authConfigs {
			// Don't add empty config sections.
			if cred.Username != "" ||
				cred.Password != "" ||
				cred.Auth != "" ||
				cred.Email != "" ||
				cred.IdentityToken != "" ||
				cred.RegistryToken != "" {
				creds[host] = types.AuthConfig{
					Username:      cred.Username,
					Password:      cred.Password,
					Auth:          cred.Auth,
					Email:         cred.Email,
					ServerAddress: cred.ServerAddress,
					IdentityToken: cred.IdentityToken,
					RegistryToken: cred.RegistryToken,
				}
			}
		}
	}
	addCredentials(dockerConfig.GetAuthConfigs())

	// Get the secure credentials that are set via credHelpers and credsStore.
	// These credentials take preference over any insecure credentials.
	credHelpers, err := dockerConfig.GetAllCredentials()
	if err != nil {
		return nil, err
	}
	addCredentials(credHelpers)

	return creds, nil
}

func (creds RegistryCredentials) LookupByHost(host string) (types.AuthConfig, bool) {
	// See https://github.com/moby/buildkit/blob/3aa7902d40d8a7fe911ee35488985cb58a346710/session/auth/authprovider/authprovider.go#L38-L40
	// and https://github.com/google/go-containerregistry/blob/071a121b9eeef0f64a5e1238de76ee35d2929082/pkg/authn/keychain.go#L71-L73
	if host == "registry-1.docker.io" || host == "index.docker.io" {
		host = "https://index.docker.io/v1/"
	}

	cred, ok := creds[host]
	return cred, ok
}

func (creds RegistryCredentials) LookupByImage(image string) (types.AuthConfig, bool) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return types.AuthConfig{}, false
	}

	return creds.LookupByHost(ref.Context().Registry.Name())
}

func (creds RegistryCredentials) ToProtobuf() map[string]*cluster.RegistryCredential {
	pb := map[string]*cluster.RegistryCredential{}
	for host, cred := range creds {
		pb[host] = &cluster.RegistryCredential{
			Username: cred.Username,
			Password: cred.Password,
		}
	}
	return pb
}

func RegistryAuthHeader(cred types.AuthConfig) (string, error) {
	authJSON, err := json.Marshal(types.AuthConfig{
		Username: cred.Username,
		Password: cred.Password,
	})
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(authJSON), nil
}

type BlimpRegistryAuth struct {
	Username string
	Password string
}

func BlimpRegcred(auth *auth.BlimpAuth) (BlimpRegistryAuth, error) {
	marshaller := jsonpb.Marshaler{}
	json, err := marshaller.MarshalToString(auth)
	if err != nil {
		return BlimpRegistryAuth{}, err
	}

	return BlimpRegistryAuth{
		Username: JSONCredUsername,
		Password: json,
	}, nil
}

func (regAuth BlimpRegistryAuth) ToProtobuf() *cluster.RegistryCredential {
	return &cluster.RegistryCredential{
		Username: regAuth.Username,
		Password: regAuth.Password,
	}
}

func (regAuth BlimpRegistryAuth) ToContainerRegistry() authn.Authenticator {
	return &authn.Basic{
		Username: regAuth.Username,
		Password: regAuth.Password,
	}
}

func (regAuth BlimpRegistryAuth) ToDocker() types.AuthConfig {
	return types.AuthConfig{
		Username: regAuth.Username,
		Password: regAuth.Password,
	}
}

func (regAuth BlimpRegistryAuth) ToBlimpAuth() (*auth.BlimpAuth, error) {
	if regAuth.Username == JSONCredUsername {
		var blimpAuth auth.BlimpAuth
		err := jsonpb.Unmarshal(strings.NewReader(regAuth.Password), &blimpAuth)
		if err != nil {
			return nil, err
		}
		return &blimpAuth, nil
	}

	// If Username does not match JSONCredUsername, we assume the password is
	// just a plain token. This was the old behavior.
	return &auth.BlimpAuth{Token: regAuth.Password}, nil
}
