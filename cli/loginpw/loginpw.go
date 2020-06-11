package loginpw

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/pkg/auth"
)

func New() *cobra.Command {
	var username, password string
	cmd := &cobra.Command{
		Use:    "loginpw",
		Hidden: true,
		Short:  "Used to login during internal testing. NOT meant to be used by external users.",
		Run: func(_ *cobra.Command, _ []string) {
			token, err := auth.PasswordLogin(username, password)
			if err != nil {
				log.WithError(err).Fatal("Failed to login")
			}
			fmt.Println("Successfully logged in")

			store, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse existing Kelda Blimp credentials")
			}

			store.AuthToken = token
			if err := store.Save(); err != nil {
				log.WithError(err).Fatal("Failed to update local Kelda Blimp credentials")
			}
		},
	}
	cmd.Flags().StringVarP(&username, "username", "", "",
		"The username to login with")
	cmd.Flags().StringVarP(&password, "password", "", "",
		"The password to login with")
	return cmd
}
