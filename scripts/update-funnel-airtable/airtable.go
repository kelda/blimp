package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/brianloveswords/airtable"
)

type Stage string

const (
	StageLoggedIn      = "Logged In"
	StageRanExampleApp = "Ran Example App"
	StageRanOwnApp     = "Ran Own App"
	StageOwnAppFailed  = "Own App Failed"
	StageRepeatUser    = "Repeat User"
)

// TODO: Upgrade record limits. 1200 max.
// TODO: There are people in Logged In that definitely ran the example app.
// E.g. Guillaume. Issue is that DataDog is only keeping log events for about a
// month.
type UserRecord struct {
	airtable.Record

	Fields struct {
		Name                string
		Login               string
		Email               string
		AccountCreationDate time.Time           `json:"Account Creation Date"`
		UserAgent           string              `json:"User Agent"`
		ClientID            airtable.RecordLink `json:"GA Client ID"`
		Namespace           string
		LastUsage           time.Time           `json:"Last Usage"`
		RanBlimpUp          bool                `json:"Ran Blimp Up"`
		RanOwnApp           bool                `json:"Ran Own App"`
		DaysUsed            int                 `json:"Days Used"`
		BlimpUps            airtable.RecordLink `json:"Blimp Ups"`
		Stage               Stage
		Source              []string
		SuccessfulLastBoot  bool `json:"Successfully Booted"`
	}
}

type BlimpUpRecord struct {
	airtable.Record

	Fields struct {
		Namespace          string
		Date               time.Time
		Services           string
		SuccessfullyBooted bool `json:"Successfully Booted"`
		Error              string
		ExampleApp         bool   `json:"Example App"`
		DataDogLink        string `json:"Logs"`
	}

	update bool
	create bool
}

type WebsiteUserRecord struct {
	airtable.Record

	Fields struct {
		ClientID       string `json:"Client ID"`
		Source         string
		Campaign       string
		Keyword        string
		FirstVisit     *time.Time `json:"First Visit"`
		FirstLogin     *time.Time `json:"First Login"`
		FirstLoginPath string     `json:"First Login Path"`
		Visits         int        `json:"Visits"`
		DeviceCategory string     `json:"Device Category"`
		BlimpNamespace string     `json:"Blimp Namespace"`
	}
}

var airtableClient = airtable.Client{
	APIKey: AirtableAPIKey,
	BaseID: AirtableBaseID,
}

func getUserRecords() (map[string]UserRecord, error) {
	var users []UserRecord
	table := airtableClient.Table("Blimp Users")
	if err := table.List(&users, &airtable.Options{}); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}

	usersMap := map[string]UserRecord{}
	for _, user := range users {
		usersMap[user.Fields.Login] = user
	}
	return usersMap, nil
}

func getWebsiteUsers() (map[string]WebsiteUserRecord, error) {
	var users []WebsiteUserRecord
	table := airtableClient.Table("Website Users")
	if err := table.List(&users, &airtable.Options{}); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}

	usersMap := map[string]WebsiteUserRecord{}
	for _, user := range users {
		// TODO: There are dups for some reason.
		if existingUser, ok := usersMap[user.Fields.ClientID]; ok && existingUser.Fields.BlimpNamespace != "" {
			continue
		}
		usersMap[user.Fields.ClientID] = user
	}
	return usersMap, nil
}

func createWebsiteUser(record *WebsiteUserRecord) error {
	fmt.Println("Creating website user record")
	table := airtableClient.Table("Website Users")
	return table.Create(record)
}

func getBlimpRunRecordsFromAirtable() (records []BlimpUpRecord, err error) {
	table := airtableClient.Table("Blimp Ups")
	return records, table.List(&records, &airtable.Options{})
}

func upsertBlimpRuns(currRecords []BlimpUpRecord, newRecords []BlimpUpRecord) (map[string][]BlimpUpRecord, error) {
	table := airtableClient.Table("Blimp Ups")
	key := func(record BlimpUpRecord) string {
		return fmt.Sprintf("%s-%d", record.Fields.Namespace, record.Fields.Date.Unix())
	}

	currMap := map[string]BlimpUpRecord{}
	for _, record := range currRecords {
		currMap[key(record)] = record
	}

	namespaceToRecords := map[string][]BlimpUpRecord{}
	duplicateRecords := map[string]struct{}{}
	for _, record := range newRecords {
		var err error
		if curr, ok := currMap[key(record)]; ok {
			duplicateRecords[key(record)] = struct{}{}
			if !reflect.DeepEqual(curr.Fields, record.Fields) {
				fmt.Println("Updating Blimp Run record")
				curr.Fields = record.Fields
				err = table.Update(&curr)
			}
			record = curr
		} else {
			fmt.Println("Creating Blimp Run record")
			err = table.Create(&record)
		}

		if err != nil {
			return nil, fmt.Errorf("write: %s", err)
		}
		namespaceToRecords[record.Fields.Namespace] = append(namespaceToRecords[record.Fields.Namespace], record)
	}

	for _, record := range currRecords {
		_, ok := duplicateRecords[key(record)]
		if !ok {
			namespaceToRecords[record.Fields.Namespace] = append(namespaceToRecords[record.Fields.Namespace], record)
		}
	}

	return namespaceToRecords, nil
}

// TODO: Protect against accidental edits by viewers in browser.
func upsertUsers(currUsers map[string]UserRecord, newUsers []UserRecord) error {
	table := airtableClient.Table("Blimp Users")
	for _, user := range newUsers {
		var err error
		if curr, ok := currUsers[user.Fields.Login]; ok {
			if reflect.DeepEqual(curr.Fields, user.Fields) {
				continue
			}

			fmt.Println("Updating User record")
			curr.Fields = user.Fields
			err = table.Update(&curr)
		} else {
			fmt.Println("Creating User record")
			err = table.Create(&user)
		}

		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
	return nil
}
