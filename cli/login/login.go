package login

import (
	"context"
	"crypto/tls"
	"fmt"
	"os/exec"
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/login"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in to Kelda Blimp",
		Long: `Log in to Kelda Blimp.

Kelda Blimp only uses your login to identify you, and doesn't pull any other information.`,
		Run: func(_ *cobra.Command, _ []string) {
			idToken, refreshToken, err := getAuthToken()
			if err != nil {
				log.WithError(err).Fatal("Failed to login")
			}
			fmt.Println("Successfully logged in")

			// TODO: Store in OS's encrypted storage rather than in regular file.
			store, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse existing Kelda Blimp credentials")
			}

			store.AuthToken = idToken
			store.RefreshToken = refreshToken
			if err := store.Save(); err != nil {
				log.WithError(err).Fatal("Failed to update local Kelda Blimp credentials")
			}
		},
	}
}

func getAuthToken() (string, string, error) {
	// Use the system's default certificate pool.
	tlsConfig := &tls.Config{}
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", auth.LoginProxyGRPCHost, auth.LoginProxyGRPCPort),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithUnaryInterceptor(errors.UnaryClientInterceptor),
	)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	// Start the login process.
	client := login.NewLoginClient(conn)
	stream, err := client.Login(context.Background(), &login.LoginRequest{})
	if err != nil {
		return "", "", err
	}

	// Open the login URL as instructed by the login proxy.
	loginURL, err := getLoginURL(stream)
	if err != nil {
		return "", "", errors.WithContext("read instructions", err)
	}

	fmt.Printf("Your browser has been opened to log in.\n"+
		"Please leave this command running while you finish logging in.\n"+
		"If your browser doesn't open, you can also visit this link directly:\n\n%s\n\n",
		loginURL)
	if err := openBrowser(loginURL); err != nil {
		log.WithError(err).Warn("Failed to open browser. Please open the link manually.")
	}

	// Wait for the user to login. The login proxy will receive the token, and
	// forward it to us.
	return getLoginResult(stream)
}

// The first message in the stream should be the login URL.
func getLoginURL(stream login.Login_LoginClient) (string, error) {
	msg, err := stream.Recv()
	if err != nil {
		return "", errors.WithContext("receive", err)
	}

	if msg.Msg == nil {
		return "", errors.New("nil message")
	}

	instr, ok := msg.Msg.(*login.LoginResponse_Instructions)
	if !ok {
		return "", errors.New("unexpected type")
	}

	return instr.Instructions.URL, nil
}

// The second, and final, message in the stream should be the result of the login.
func getLoginResult(stream login.Login_LoginClient) (string, string, error) {
	msg, err := stream.Recv()
	if err != nil {
		return "", "", errors.WithContext("receive", err)
	}

	if msg.Msg == nil {
		return "", "", errors.New("nil message")
	}

	res, ok := msg.Msg.(*login.LoginResponse_Result)
	if !ok {
		return "", "", errors.New("unexpected type")
	}

	var loginErr error
	if res.Result.Error != "" {
		loginErr = errors.New(res.Result.Error)
	}
	return res.Result.IdToken, res.Result.RefreshToken, loginErr
}

func openBrowser(url string) (err error) {
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = errors.New("unsupported platform")
	}
	return err
}
