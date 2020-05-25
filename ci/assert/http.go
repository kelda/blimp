package assert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/stretchr/testify/require"
)

type HTTPPostTest struct {
	Name     string
	Endpoint string
	Body     interface{}
}

type HTTPGetTest struct {
	Name     string
	Endpoint string
}

func (test HTTPPostTest) Run(_ context.Context, t *testing.T) {
	jsonBody, err := json.Marshal(test.Body)
	if err != nil {
		require.NoError(t, err, "marshal json")
	}

	resp, err := http.Post(test.Endpoint, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		require.NoError(t, err, "post")
	}

	// Close the body to avoid leaking resources.
	resp.Body.Close()
}

func (test HTTPPostTest) GetName() string {
	return test.Name
}

func (test HTTPGetTest) Run(_ context.Context, t *testing.T) {
	resp, err := http.Get(test.Endpoint)
	if err != nil {
		require.NoError(t, err, "get")
	}

	// Close the body to avoid leaking resources.
	resp.Body.Close()
}

func (test HTTPGetTest) GetName() string {
	return test.Name
}

func httpGet(endpoint string) (string, error) {
	resp, err := http.Get(endpoint)
	if err != nil {
		return "", errors.WithContext("get", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithContext("read", err)
	}

	return string(body), nil
}

func HTTPGetShouldNotContain(endpoint, str string) Assertion {
	return func() error {
		actual, err := httpGet(endpoint)
		if err != nil {
			return errors.WithContext("get", err)
		}

		if strings.Contains(actual, str) {
			return fmt.Errorf("unexpected response: expected %q to not contain %q",
				actual, str)
		}
		return nil
	}
}

func HTTPGetShouldContain(endpoint, exp string) Assertion {
	return func() error {
		actual, err := httpGet(endpoint)
		if err != nil {
			return errors.WithContext("get", err)
		}

		if !strings.Contains(actual, exp) {
			return fmt.Errorf("unexpected response: expected %q to contain %q",
				actual, exp)
		}
		return nil
	}
}

func HTTPGetShouldEqual(endpoint, exp string) Assertion {
	return func() error {
		actual, err := httpGet(endpoint)
		if err != nil {
			return errors.WithContext("get", err)
		}

		if exp != actual {
			return fmt.Errorf("unexpected response: expected %q to equal %q",
				exp, actual)
		}
		return nil
	}
}
