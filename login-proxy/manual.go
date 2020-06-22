package main

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	manualOAuthCallback = "/manual/oauth/callback"
	manualLoginURL      = "/manual/login"
)

type manualLoginServer struct {
	oauthConf *oauth2.Config
}

func newManualLoginServer(oauthConf oauth2.Config) manualLoginServer {
	oauthConf.RedirectURL = fmt.Sprintf("https://%s%s", LoginProxyHost, manualOAuthCallback)
	return manualLoginServer{oauthConf: &oauthConf}
}

func (s *manualLoginServer) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, manualLoginURL, http.StatusFound)
	})
	mux.HandleFunc(manualLoginURL, s.manualLogin)
	mux.HandleFunc(manualOAuthCallback, s.manualLoginCallback)
}

func (s *manualLoginServer) manualLogin(w http.ResponseWriter, r *http.Request) {
	log.Info("Starting manual login")
	http.Redirect(w, r, s.oauthConf.AuthCodeURL("state"), http.StatusFound)
}

func (s *manualLoginServer) manualLoginCallback(w http.ResponseWriter, r *http.Request) {
	log.Info("Received oauth code")
	idToken, err := getTokenForCode(s.oauthConf, r)
	if err != nil {
		fmt.Fprintf(w, "Login failed: %s\n", err)
		return
	}

	msgTemplate := `Successfully logged in. Run the following command to use your token:

cat <<EOF > ~/.blimp/auth.yaml
AuthToken: %s
EOF`
	fmt.Fprintf(w, msgTemplate, idToken)
}
