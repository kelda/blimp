package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/brianloveswords/airtable"
	"github.com/kelda-inc/auth0/management"
)

// TODO: Measure how long people use Blimp after it boots.
// TODO: Add session IDs so that we can track events from concurrent sessions.
// e.g. killing blimp after running `blimp up` in another terminal
func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	auth0Users, err := getUsersFromAuth0()
	if err != nil {
		return err
	}
	fmt.Printf("Got %d users from auth0\n", len(auth0Users))

	currRunRecords, err := getBlimpRunRecordsFromAirtable()
	if err != nil {
		return err
	}

	var lastKnownRun time.Time
	for _, record := range currRunRecords {
		if record.Fields.Date.After(lastKnownRun) {
			lastKnownRun = record.Fields.Date
		}
	}
	// Avoid race condition where previous read partially read events from that
	// minute.
	// TODO: Maybe we should just always list everything, doesn't seem like
	// we're hitting DataDog's limits.
	listSince := lastKnownRun
	if !lastKnownRun.IsZero() {
		listSince = lastKnownRun.Add(-1 * time.Minute)
	}

	blimpRuns, all, err := getBlimpRunsFromDataDog(listSince)
	if err != nil {
		return fmt.Errorf("get runs from datadog: %w", err)
	}
	fmt.Printf("Found %d new Blimp runs since %s\n", len(blimpRuns), listSince)

	if !all {
		fmt.Println("WARNING: There are more events in DataDog that haven't been processed. " +
			"The Airtable won't be completely up to date after this run.")
	}

	blimpUpRecords, err := upsertBlimpRuns(currRunRecords, blimpRuns)
	if err != nil {
		return fmt.Errorf("update blimp up records: %w", err)
	}

	logins, err := getLoginsFromGoogleAnalytics()
	if err != nil {
		return fmt.Errorf("get logins from Google Analytics: %w", err)
	}

	uniqueLoggedInUsers := map[string]LoginEvent{}
	for _, login := range logins {
		if curr, ok := uniqueLoggedInUsers[login.ClientID]; ok && curr.BlimpNamespace != "" {
			login.BlimpNamespace = curr.BlimpNamespace
		}
		uniqueLoggedInUsers[login.ClientID] = login
	}

	loggedInClientIDs, err := getWebsiteUsers()
	if err != nil {
		return fmt.Errorf("get website users: %w", err)
	}

	for _, login := range uniqueLoggedInUsers {
		// Don't hit the Google API if they're already in Airtable.
		if _, ok := loggedInClientIDs[login.ClientID]; ok {
			continue
		}

		sessions, err := getWebsiteSessions(login.ClientID)
		if err != nil {
			return fmt.Errorf("get sessions: %w", err)
		}

		record := WebsiteUserRecord{}
		record.Fields.ClientID = login.ClientID
		record.Fields.BlimpNamespace = login.BlimpNamespace

		var dates []time.Time
		for _, session := range sessions {
			dates = append(dates, session.Date)
		}
		record.Fields.Visits = countDays(dates)

		record.Fields.FirstVisit = &sessions[0].Date
		if len(sessions[0].Activities) > 0 {
			record.Fields.Source = fmt.Sprintf("%s / %s",
				sessions[0].Activities[0].Medium,
				sessions[0].Activities[0].Source)
			campaign := sessions[0].Activities[0].Campaign
			if campaign != "" && campaign != "(not set)" {
				record.Fields.Campaign = campaign
			}

			keyword := sessions[0].Activities[0].Keyword
			if keyword != "" && keyword != "(not set)" {
				record.Fields.Keyword = keyword
			}
		}

		record.Fields.DeviceCategory = sessions[0].DeviceCategory

	Outer:
		for _, session := range sessions {
			for _, activity := range session.Activities {
				if activity.Pageview == nil {
					continue
				}

				if record.Fields.LandingPage == "" {
					record.Fields.LandingPage = activity.Pageview.PagePath
				}

				if strings.Contains(activity.Pageview.PagePath, "/thank-you-login") ||
					strings.Contains(activity.Pageview.PagePath, "/login-success-sign-up-try-blimp") ||
					strings.Contains(activity.Pageview.PagePath, "/docs/logged-in") {
					// TODO: Would be nice if we didn't have to reparse in every usage of activity.ActivityTime.
					// Parses to UTC even though it shouldn't.
					activityTime, err := time.ParseInLocation(time.RFC3339, activity.ActivityTime, gaTimezone)
					activityTime = time.Date(activityTime.Year(), activityTime.Month(), activityTime.Day(), activityTime.Hour(), activityTime.Minute(), activityTime.Second(), activityTime.Nanosecond(), gaTimezone)
					if err == nil {
						record.Fields.FirstLogin = &activityTime
					} else {
						fmt.Printf("WARN: Failed to parse timestamp %s: %s\n", activity.ActivityTime, err)
					}

					record.Fields.FirstLoginPath = activity.Pageview.PagePath
					break Outer
				}
			}
		}

		if err := upsertWebsiteUser(loggedInClientIDs, &record); err != nil {
			return fmt.Errorf("upsert website user: %w", err)
		}
		loggedInClientIDs[login.ClientID] = record
	}

	currUserRecords, err := getUserRecords()
	if err != nil {
		return err
	}

	var userRecords []UserRecord
	for _, user := range auth0Users {
		if *user.ID == "" {
			fmt.Printf("%+v\n", user)
		}

		userRecord, ok := currUserRecords[*user.ID]
		if ok {
			userRecord = makeUserRecord(blimpUpRecords, loggedInClientIDs, *user, &userRecord)
		} else {
			userRecord = makeUserRecord(blimpUpRecords, loggedInClientIDs, *user, nil)
		}

		userRecords = append(userRecords, userRecord)
	}

	return upsertUsers(currUserRecords, userRecords)
}

func makeUserRecord(blimpRuns map[string][]BlimpUpRecord, websiteUserRecords map[string]WebsiteUserRecord, user management.User, existingRecord *UserRecord) UserRecord {
	var record UserRecord
	if existingRecord != nil {
		record = *existingRecord
	}

	// Auth0 only keeps login logs for a couple days.
	if record.Fields.UserAgent == "" && user.LastLogin != nil && user.LastLogin.After(time.Now().Add(-7*24*time.Hour)) {
		m, err := management.New(
			"blimp-testing.auth0.com",
			"jP8Xv9Qj7LqZcMRVLIhdoNODCgMCQ2eW",
			"FcLjzsh6-YjIlCrJLJ4QvJ-6frDD8zoHpprzKaQ3sWlaa0o_7ITcUyNh_Js8fMiD")
		if err != nil {
			panic(err)
			//return nil, fmt.Errorf("create auth0 client: %w", err)
		}

		userAgent, err := getUserAgent(m, *user.ID)
		if err != nil {
			panic(err)
		}

		record.Fields.UserAgent = userAgent
	}

	record.Fields.Namespace = DNSCompliant(*user.ID)

	// TODO: This correlation is messy, we should have the CLI report it.
	websiteUserRecord, err := findWebsiteUserRecord(websiteUserRecords, record.Fields.Namespace, *user.CreatedAt)
	if err == nil {
		if len(record.Fields.ClientID) != 0 && record.Fields.ClientID[0] != websiteUserRecord.ID {
			fmt.Printf("INFO: Not overwriting GA Client ID for %s from %s to %s\n",
				*user.ID, record.Fields.ClientID, websiteUserRecord.ID)
		} else {
			record.Fields.ClientID = airtable.RecordLink([]string{websiteUserRecord.ID})
		}
		source := append(record.Fields.Source, websiteUserRecord.Fields.Source)
		record.Fields.Source = unique(source)
	} else {
		fmt.Printf("WARN: Failed to find website user record for %s: %s\n", *user.ID, err)
	}
	if len(record.Fields.Source) == 0 {
		record.Fields.Source = []string{"Unknown"}
	}

	if record.Fields.Name == "" {
		record.Fields.Name = *user.Name
	} else if record.Fields.Name != *user.Name {
		fmt.Printf("INFO: Not overwriting name for %s from %s to %s\n",
			*user.ID, record.Fields.Name, *user.Name)
	}

	// TODO: Check emptiness.
	record.Fields.Email = *user.Email
	record.Fields.Login = *user.ID
	record.Fields.AccountCreationDate = *user.CreatedAt
	record.Fields.LastUsage = *user.CreatedAt
	record.Fields.Stage = StageLoggedIn

	blimpUps, ok := blimpRuns[record.Fields.Namespace]
	if !ok || len(blimpUps) == 0 {
		return record
	}
	record.Fields.RanBlimpUp = true

	sort.Slice(blimpUps, func(i, j int) bool {
		return blimpUps[i].Fields.Date.After(blimpUps[j].Fields.Date)
	})

	var blimpUpIDs airtable.RecordLink
	for _, up := range blimpUps {
		blimpUpIDs = append(blimpUpIDs, up.ID)
	}
	record.Fields.BlimpUps = blimpUpIDs

	var datesUsed []time.Time
	for _, blimpUp := range blimpUps {
		if len(blimpUp.Fields.Services) != 0 && !blimpUp.Fields.ExampleApp {
			record.Fields.RanOwnApp = true
		}

		if blimpUp.Fields.Date.After(record.Fields.LastUsage) {
			record.Fields.LastUsage = blimpUp.Fields.Date
		}

		datesUsed = append(datesUsed, blimpUp.Fields.Date)
	}

	// blimpUps are sorted by newest first.
	record.Fields.SuccessfulLastBoot = blimpUps[0].Fields.SuccessfullyBooted

	record.Fields.DaysUsed = countDays(datesUsed)
	if record.Fields.RanOwnApp {
		record.Fields.Stage = StageRanOwnApp

		// This check isn't exactly correct since the user could have tried
		// their own app, and switched to the example app, or had gotten
		// their own app working, and then broke it. But it's probably close enough.
		if !record.Fields.SuccessfulLastBoot {
			record.Fields.Stage = StageOwnAppFailed
		} else if record.Fields.DaysUsed > 1 {
			record.Fields.Stage = StageRepeatUser
		}
	} else {
		record.Fields.Stage = StageRanExampleApp
	}

	return record
}

func findWebsiteUserRecord(users map[string]WebsiteUserRecord, namespace string, loginTime time.Time) (WebsiteUserRecord, error) {
	matches := map[string]WebsiteUserRecord{}
	for _, user := range users {
		if user.Fields.BlimpNamespace == namespace {
			return user, nil
		}

		if user.Fields.FirstLogin != nil && user.Fields.FirstLogin.After(loginTime) && user.Fields.FirstLogin.Sub(loginTime) <= 30*time.Second {
			// TODO: users is already unique over ClientID, don't need to keep
			// track of matches in a map.
			matches[user.Fields.ClientID] = user
		}
	}

	switch len(matches) {
	case 0:
		return WebsiteUserRecord{}, errors.New("no matches found")
	case 1:
		for _, user := range matches {
			return user, nil
		}
	}
	return WebsiteUserRecord{}, errors.New("ambiguous logins")
}

func countDays(dates []time.Time) int {
	uniqueDates := map[string]struct{}{}
	for _, date := range dates {
		uniqueDates[date.Format("2006-01-02")] = struct{}{}
	}
	return len(uniqueDates)
}

func unique(strs []string) (ret []string) {
	strSet := map[string]struct{}{}
	for _, str := range strs {
		if _, ok := strSet[str]; ok {
			continue
		}
		strSet[str] = struct{}{}
		ret = append(ret, str)
	}
	return ret
}
