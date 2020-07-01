package docker

import (
	"github.com/docker/cli/cli/config/configfile"
	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types"
)

// GetLocalRegistryCredentials reads the user's registry credentials from their
// local machine.
func GetLocalRegistryCredentials(dockerConfig *configfile.ConfigFile) (map[string]types.AuthConfig, error) {
	// Get the insecure credentials that were saved directly to
	// the auths section of ~/.docker/config.json.
	creds := map[string]types.AuthConfig{}
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
