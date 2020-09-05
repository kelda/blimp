package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	ga "google.golang.org/api/analytics/v3"
	gaActivity "google.golang.org/api/analyticsreporting/v4"
)

var gaTimezone *time.Location

var loggedInPaths = []string{
	"/thank-you-login",
	"/login-success-sign-up-try-blimp",
	"/get-started/#welcome",
	"/docs/logged-in",
}

func init() {
	var err error
	gaTimezone, err = time.LoadLocation("America/Los_Angeles")
	if err != nil {
		panic(fmt.Errorf("failed to load timezone: %s", err))
	}
}

const (
	// From https://analytics.google.com/analytics/web/?authuser=1#/a134292490w194243387p189682833/admin/view/settings
	googleAnalyticsViewID = "ga:189682833"

	clientIDDimension = "ga:dimension2"

	blimpNamespaceDimension = "ga:dimension10"
)

type LoginEvent struct {
	ClientID       string
	BlimpNamespace string
}

func getLoginsFromGoogleAnalytics() (map[string]LoginEvent, error) {
	jwtConf, err := google.JWTConfigFromJSON(
		GoogleAnalyticsJSONKey,
		ga.AnalyticsReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("make jwt: %w", err)
	}

	httpClient := jwtConf.Client(oauth2.NoContext)
	svc, err := ga.New(httpClient)
	if err != nil {
		return nil, fmt.Errorf("make client: %w", err)
	}

	var filters []string
	for _, loggedInPath := range loggedInPaths {
		filters = append(filters, fmt.Sprintf("ga:pagePath=~%s", loggedInPath))
	}
	filterStr := strings.Join(filters, ",")

	// First, add all users that have logged in, regardless of whether we have
	// their Blimp Namespace.
	logins := map[string]LoginEvent{}
	req := svc.Data.Ga.
		Get(googleAnalyticsViewID, "120daysAgo", "today", "ga:pageViews").
		Dimensions(strings.Join([]string{
			clientIDDimension,
		}, ",")).
		Filters(filterStr)
	callback := func(row []string) {
		logins[row[0]] = LoginEvent{ClientID: row[0]}
	}
	if err := getAll(req, callback); err != nil {
		return nil, fmt.Errorf("get", err)
	}

	// Then, add the BlimpNamespace data for the users that have it set.
	req = svc.Data.Ga.
		Get(googleAnalyticsViewID, "120daysAgo", "today", "ga:pageViews").
		Dimensions(strings.Join([]string{
			clientIDDimension,
			blimpNamespaceDimension,
		}, ",")).
		Filters(filterStr)
	callback = func(row []string) {
		logins[row[0]] = LoginEvent{ClientID: row[0], BlimpNamespace: row[1]}
	}
	if err := getAll(req, callback); err != nil {
		return nil, fmt.Errorf("get", err)
	}

	return logins, nil
}

func getAll(req *ga.DataGaGetCall, callback func([]string)) error {
	startIndex := int64(0)
	for {
		if startIndex != 0 {
			req = req.StartIndex(startIndex)
		}

		res, err := req.Do()
		if err != nil {
			return err
		}

		for _, row := range res.Rows {
			callback(row)
		}

		startIndex += int64(len(res.Rows))
		if startIndex == res.TotalResults {
			return nil
		}
	}
}

type WebsiteSession struct {
	Date time.Time
	*gaActivity.UserActivitySession
}

func getWebsiteSessions(userID string) (sessions []WebsiteSession, err error) {
	jwtConf, err := google.JWTConfigFromJSON(
		GoogleAnalyticsJSONKey,
		ga.AnalyticsReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("make jwt: %w", err)
	}

	httpClient := jwtConf.Client(oauth2.NoContext)
	svc, err := gaActivity.New(httpClient)
	if err != nil {
		return nil, fmt.Errorf("make client: %w", err)
	}

	var pageToken string
	for {
		gaDateFormat := "2006-01-02"
		resp, err := svc.UserActivity.Search(&gaActivity.SearchUserActivityRequest{
			User: &gaActivity.User{
				Type:   "CLIENT_ID",
				UserId: userID,
			},
			DateRange: &gaActivity.DateRange{
				StartDate: time.Now().Add(-365 * 24 * time.Hour).Format(gaDateFormat),
				EndDate:   time.Now().Format(gaDateFormat),
			},
			ViewId:    googleAnalyticsViewID,
			PageToken: pageToken,
		}).Do()
		if err != nil {
			return nil, fmt.Errorf("get activity: %w", err)
		}

		for _, session := range resp.Sessions {
			date, err := time.ParseInLocation(gaDateFormat, session.SessionDate, gaTimezone)
			if err != nil {
				return nil, fmt.Errorf("parse date: %w", err)
			}

			sessions = append(sessions, WebsiteSession{
				Date:                date,
				UserActivitySession: session,
			})
		}

		if resp.NextPageToken == "" {
			sortSessions(sessions)
			return sessions, nil
		}
		pageToken = resp.NextPageToken
	}
}

func sortSessions(sessions []WebsiteSession) {
	for i, session := range sessions {
		sort.Slice(session.Activities, func(i, j int) bool {
			left := session.Activities[i]
			right := session.Activities[j]
			leftTimestamp, err := time.ParseInLocation(time.RFC3339, left.ActivityTime, gaTimezone)
			if err != nil {
				fmt.Printf("WARN: Failed to parse timestamp %s: %s\n", left.ActivityTime, err)
				return false
			}
			leftTimestamp = time.Date(leftTimestamp.Year(), leftTimestamp.Month(), leftTimestamp.Day(), leftTimestamp.Hour(), leftTimestamp.Minute(), leftTimestamp.Second(), leftTimestamp.Nanosecond(), gaTimezone)

			rightTimestamp, err := time.ParseInLocation(time.RFC3339, right.ActivityTime, gaTimezone)
			if err != nil {
				fmt.Printf("WARN: Failed to parse timestamp %s: %s\n", right.ActivityTime, err)
				return false
			}
			rightTimestamp = time.Date(rightTimestamp.Year(), rightTimestamp.Month(), rightTimestamp.Day(), rightTimestamp.Hour(), rightTimestamp.Minute(), rightTimestamp.Second(), rightTimestamp.Nanosecond(), gaTimezone)

			return leftTimestamp.Before(rightTimestamp)
		})

		// The session object only tracks the date, but not the time. We use
		// the first activity time in the session so that we can sort sessions
		// on the same day.
		if len(session.Activities) != 0 {
			activityTime, err := time.Parse(time.RFC3339, session.Activities[0].ActivityTime)
			activityTime = time.Date(activityTime.Year(), activityTime.Month(), activityTime.Day(), activityTime.Hour(), activityTime.Minute(), activityTime.Second(), activityTime.Nanosecond(), gaTimezone)
			if err == nil {
				sessions[i].Date = activityTime
			}
		}
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Date.Before(sessions[j].Date)
	})
}
