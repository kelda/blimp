package main

import (
	"fmt"

	"github.com/kelda-inc/auth0/management"
)

func getUsersFromAuth0() ([]*management.User, error) {
	m, err := management.New(
		"blimp-testing.auth0.com",
		Auth0ClientID,
		Auth0ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("create auth0 client: %w", err)
	}

	var users []*management.User
	page := 0
	for {
		usersResp, err := m.User.List(management.Page(page), management.PerPage(100))
		if err != nil {
			return nil, err
		}

		users = append(users, usersResp...)
		if len(usersResp) == 0 || len(usersResp) != 100 {
			return users, nil
		}

		page++
	}
}

func getUserAgent(m *management.Management, userID string) (string, error) {
	logs, err := m.Log.Search(
		management.Parameter(
			"q",
			fmt.Sprintf(`(user_id: %s) AND (type: ("s"))`, userID)),
		management.Parameter(
			"sort",
			"date:1"),
	)

	if err != nil {
		return "", fmt.Errorf("search: %w", err)
	}

	if len(logs) == 0 {
		return "", nil
	}
	return *logs[0].UserAgent, nil
}
