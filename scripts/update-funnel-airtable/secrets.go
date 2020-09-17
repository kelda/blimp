package main

import (
	"encoding/base64"
	"fmt"
	"os"
)

var (
	DataDogAPIKey          = mustGetEnvVar("DATADOG_API_KEY")
	DataDogAppKey          = mustGetEnvVar("DATADOG_APP_KEY")
	DripAPIKey             = mustGetEnvVar("DRIP_API_KEY")
	DripAccountID          = mustGetEnvVar("DRIP_ACCOUNT_ID")
	AirtableBaseID         = mustGetEnvVar("AIRTABLE_BASE_ID")
	AirtableAPIKey         = mustGetEnvVar("AIRTABLE_API_KEY")
	Auth0ClientID          = mustGetEnvVar("AUTH0_CLIENT_ID")
	Auth0ClientSecret      = mustGetEnvVar("AUTH0_CLIENT_SECRET")
	GoogleAnalyticsJSONKey = mustDecodeBase64(mustGetEnvVar("GOOGLE_ANALYTICS_JSON_KEY_BASE64"))
)

func mustGetEnvVar(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic(fmt.Sprintf("%s is required", key))
	}
	return val
}

func mustDecodeBase64(encoded string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return decoded
}
