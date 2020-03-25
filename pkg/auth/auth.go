package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc"
	dockerTypes "github.com/docker/docker/api/types"
	"golang.org/x/oauth2"
)

type User struct {
	// TODO: Do we actually need email? Not unique according to spec.
	ID string `json:"sub"`
}

const (
	ClientID     = "b87He1pQEDohVzOAYAfLIUfixO5zu6Ln"
	AuthHost     = "https://blimp-testing.auth0.com"
	AuthURL      = AuthHost + "/authorize"
	TokenURL     = AuthHost + "/oauth/token"
	RedirectHost = "localhost:8085"
	RedirectPath = "/oauth/redirect"

	// TODO: This is a key that grants everyone push and pull access to Kevin's GCR
	// registry. This is obviously insecure.
	// The final implementation will perform authentication in the registry via
	// JWT's. Each user will only be able to pull and push images under their
	// namespace. At which point this service account can be revoked.
	RegistryKey = `{
  "type": "service_account",
  "project_id": "kevin-230505",
  "private_key_id": "d0bdb41712791a6bb6c660c4b02c9daa5ab78803",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCUUJTLxGRznhE9\n/G/Zl8+CfbAzz7VpE9GaoVSuxEjn5fhjpsHOSODNtxdi4yOe351hPeSzAHZRcws6\no1BGVtNKlFVMtuaQ0+jRmICs+NSnx8bPRaLJZ3g188GWwRCyoyKkx1QsdtUMWqdC\nwk5Z+XFN11QC+R9MGs+FSeAZ6+CgRG06RQD+gWPeOmdbn+ltE+k8b9l3wl9euOaK\n7iJGSnE5zvZ4gVEmztk8sBnp7x01f41JOJYLLrizZ4f2nGikGgFOvY36RAyDKLtc\nD3/j/6Rt2b3dNGcvGJ8OE0Ej59/zMeuwjFfwoJE3YIq7kkH9wmai7OmvPQM8Q1eZ\niaMKbyr3AgMBAAECggEALTusPb8eUcKmCI0aQbcSkv4pRIv3DF5+gRXuAUUc5RjW\nmfHMTtEcOrE54S9b+ELDuVoKi2s7KpkXFiGjxGgLlcXKhBSOGiJ+8Zl8uQREuwzr\nPeDDhoBXgcDfTE6CfLDTSoT+T3dIf7WQKIShJ8CzRSXEWgnHeUr9+m0u+0jcn5P3\nzLUjwRpy8iv2Dmt6yH+YlixwVULqsRpe/ZY3DrJw4/Yr0O053ZdcyE4ew/xJwRZ7\nF9T67yXbBJXdRBIb41ckxrR2UbvtjFVuaa04nqSE4f5ohJHoSsbYdEjbBb1Qqlxg\no9TWLmdSFgd+qdqpcOywsKZIhRsKOakhcgDR4Fsk0QKBgQDQJixaTcLvy66/FolG\n6mab/iCqf1wv/8pKdHK0gzzRuRkVlyQyVfBTSQB8XmFS64ljIHd9Ao1/UkRav/1C\nX1Nsn+6TPLgsQri/64psftZs58tK8W9yKMapRVVO1boH9nc63gjRWsPBbgqa2UqW\nqikaUKWogbi8kIUbrriUPUWnkQKBgQC2aRWnkIxmKvVy0TN9F5c9JY0VoIoZauto\nEZL0iQhw69rj2Bi8FNG14JcroR8yR1iCNdFIoGnqw8EQE3PW+ZX9/F1FCYHrqQjF\nqerMrxSj+Af5bK0uSxdKQfc9OyK6QfFziiypY1kGGcnDhnsW8DT/RuLOPyB/WaIA\n/GRot782BwKBgEFkTLjOBzjoh2yW+uehijzlmIOX4XFe7cF4VfTp6fiFKyFCS2fY\n4dh4bcOkrvSq9I2EzKUkYSmnwbu05y6r3fyZPg1ZnQ6io4H/0IwHSPwL0i0oLnfx\n4X+aPZO3x2rq/kgrKyACYM9q77/4FdvBd4pB3dlTb6Mlz/uDZ4+CtFhRAoGANxT4\ncwcVPmzOfYNqtuV+x/ok5lj6Gr7MozpbU/hlUiQGjzLcFT98LB3LyGL5FqewtHEn\n53R5R2khTYdyPYJUpsOkLoq2bsE2YunyeyiLZRAq6EjG6unF+Kh+zkCjNfdfv/ID\nlorngQ4cfSyI0t5qQoPXTUyGta4NW5rbfzutQ9UCgYBb4lxwmVfmnqJ+TYWIGQMZ\nPjCoT50Z7xaWIbP+B7EUJ31RNWAjzof6Q4TWcVn/ZEMuAqhHBz8cs8tOuMlVrTXE\nU5hiy8uCqzRgxgxjcFIaczj8q5BRHguUvWczg5K2trGspxsNv6bMTxhkOiXChNHP\nZXUKsKt/XBqZ1oVodeV1jQ==\n-----END PRIVATE KEY-----\n",
  "client_email": "blimp-image-manager@kevin-230505.iam.gserviceaccount.com",
  "client_id": "105915643551407232385",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/blimp-image-manager%40kevin-230505.iam.gserviceaccount.com"
}`
)

var (
	// The base64 encoded certificate for the cluster manager. This is set at build time.
	ClusterManagerCertBase64 string

	// The PEM-encoded certificate for the cluster manager.
	ClusterManagerCert = mustDecodeBase64(ClusterManagerCertBase64)
)

var RegistryAuth = registryAuth()

var Endpoint = oauth2.Endpoint{
	AuthURL:   AuthHost + "/authorize",
	TokenURL:  AuthHost + "/oauth/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

var verifier = oidc.NewVerifier(
	"https://blimp-testing.auth0.com/",
	// TODO: Fetching over the network.. Any issues if no network connectivity?
	oidc.NewRemoteKeySet(context.Background(), "https://blimp-testing.auth0.com/.well-known/jwks.json"),
	&oidc.Config{ClientID: ClientID})

func ParseIDToken(token string) (User, error) {
	idToken, err := verifier.Verify(context.Background(), token)
	if err != nil {
		return User{}, fmt.Errorf("verify: %w", err)
	}

	var user User
	if err := idToken.Claims(&user); err != nil {
		return User{}, fmt.Errorf("parse claims: %w", err)
	}

	return user, nil
}

func registryAuth() string {
	authJSON, err := json.Marshal(dockerTypes.AuthConfig{
		Username: "_json_key",
		Password: RegistryKey,
	})
	if err != nil {
		panic(err)
	}

	return base64.URLEncoding.EncodeToString(authJSON)
}

func mustDecodeBase64(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return string(decoded)
}
