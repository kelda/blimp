package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"

	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/login"
)

const cliOAuthCallback = "/cli/oauth/callback"

type cliLoginServer struct {
	sessions     map[string]chan login.LoginResult
	sessionsLock sync.Mutex
	oauthConf    *oauth2.Config
}

type oauthState struct {
	Session string
}

func newCLILoginServer(oauthConf oauth2.Config) cliLoginServer {
	oauthConf.RedirectURL = fmt.Sprintf("https://%s%s", LoginProxyHost, cliOAuthCallback)
	return cliLoginServer{
		sessions:  map[string]chan login.LoginResult{},
		oauthConf: &oauthConf,
	}
}

// The gRPC server coordinates the login process with the CLI.
func (s *cliLoginServer) ServeGRPC(addr string) error {
	grpcLis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Info("Starting grpc server")
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(errors.UnaryServerInterceptor))
	login.RegisterLoginServer(grpcServer, s)
	return grpcServer.Serve(grpcLis)
}

func (s *cliLoginServer) Register(mux *http.ServeMux) {
	mux.HandleFunc(cliOAuthCallback, s.cliLoginCallback)
}

// oauthCallback retrieves the oauth token, and associates it with the session
// encoded in the state. The grpc server then sends the token back to the
// appropriate client.
func (s *cliLoginServer) cliLoginCallback(w http.ResponseWriter, r *http.Request) {
	log.Info("Received oauth code")

	sessionID, token, err := func() (string, string, error) {
		sessionID, err := getSession(r)
		if err != nil {
			return "", "", errors.WithContext("get session", err)
		}

		token, err := getTokenForCode(s.oauthConf, r)
		if err != nil {
			return "", "", errors.WithContext("get token", err)
		}

		return sessionID, token, nil
	}()

	s.sessionsLock.Lock()
	ch, ok := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.sessionsLock.Unlock()

	if !ok {
		fmt.Fprintf(w, "Login failed. Unknown session (%s).\n"+
			"Try logging in manually at https://%s%s",
			sessionID, LoginProxyHost, manualLoginURL)
		return
	}

	// Send the result to the CLI.
	ch <- login.LoginResult{
		Token: token,
		Error: errorToString(err),
	}

	// Show a friendly message in the user's browser.
	if err != nil {
		fmt.Fprintf(w, "Login failed: %s\n."+
			"Try logging in manually at https://%s%s",
			err, LoginProxyHost, manualLoginURL)
		return
	}

	redirectURL := "https://blimpup.io/thank-you-login/"
	if user, err := auth.ParseIDToken(token, auth.DefaultVerifier); err == nil {
		redirectURL += fmt.Sprintf("?bns=%s", user.Namespace)
	} else {
		log.WithError(err).Warn("Failed to parse ID token from auth0")
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *cliLoginServer) Login(_ *login.LoginRequest, srv login.Login_LoginServer) error {
	log.Info("Starting login from CLI")

	// Save a session ID in the state parameter so that the server can send the
	// authentication token back to the right client.
	sessionID, err := randomSession()
	if err != nil {
		return errors.WithContext("create session", err)
	}

	resChan := make(chan login.LoginResult, 1)
	s.sessionsLock.Lock()
	s.sessions[sessionID] = resChan
	s.sessionsLock.Unlock()

	state, err := makeState(sessionID)
	if err != nil {
		return errors.WithContext("marshal state", err)
	}

	// Step 1: Send the CLI the URL that the user should log in to. The URL
	// contains a redirect that will send the authorization token back to this
	// process.
	err = srv.Send(&login.LoginResponse{
		Msg: &login.LoginResponse_Instructions{
			Instructions: &login.LoginInstructions{
				URL: s.oauthConf.AuthCodeURL(state),
			},
		},
	})
	if err != nil {
		return errors.WithContext("send instructions", err)
	}

	// Step 2: Wait for the login result to come back, and forward it to the CLI.
	res := <-resChan
	err = srv.Send(&login.LoginResponse{
		Msg: &login.LoginResponse_Result{
			Result: &res,
		},
	})
	if err != nil {
		return errors.WithContext("send result", err)
	}
	return nil
}

var sessionGenerator *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func randomSession() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := sessionGenerator.Read(randomBytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

func makeState(sessionID string) (string, error) {
	stateJSON, err := json.Marshal(oauthState{
		Session: sessionID,
	})
	if err != nil {
		return "", errors.WithContext("marshal state", err)
	}

	return base64.URLEncoding.EncodeToString(stateJSON), nil
}

func errorToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// getSession retrieves the session ID encoded in the OAuth flow.
func getSession(r *http.Request) (string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", errors.WithContext("parse form", err)
	}

	stateBase64 := r.FormValue("state")
	if stateBase64 == "" {
		return "", errors.New("no state")
	}

	stateJSON, err := base64.StdEncoding.DecodeString(stateBase64)
	if err != nil {
		return "", errors.WithContext("base64 decode state", err)
	}

	var state oauthState
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		return "", errors.WithContext("unmarshal state", err)
	}

	if state.Session == "" {
		return "", errors.New("no session ID")
	}
	return state.Session, nil
}
