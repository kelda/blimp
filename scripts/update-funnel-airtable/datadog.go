package main

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	datadog "github.com/DataDog/datadog-api-client-go/api/v1/datadog"
)

var (
	// Must be in alphabetical order.
	exampleApps = [][]string{
		{"mongo", "web"},
		{"kafka", "zookeeper"},
	}

	ignoredNamespaces = []string{
		"a98c0197112b7a4a96b72ea21ac0802b", // Kevin.
		"6dd662101c6f4897a0f62fe5181c8a5d", // Christopher.
		"364041fa88aec5c4fbc551684fd62702", // Integration reporter.
	}
)

// The max number of pages to request from DataDog. This is necessary to avoid
// getting rate limited. DataDog allows 300 requests per hour to the logs API.
const maxDataDogRequests = 10

type eventUpStarted struct {
	time time.Time
}

type eventUpCrashed struct {
	time time.Time
	err  string
}

type eventParsedCreateSandbox struct {
	time     time.Time
	services []string
}

type eventContainersBooted struct {
	time time.Time
}

func getBlimpRunsFromDataDog(since time.Time) ([]BlimpUpRecord, bool, error) {
	logs, all, err := searchDatadog(since, []string{
		`(source:up "Ran command")`,
		`(source:up "Fatal error")`,
		`(source:up "Containers booted")`,
		`("Parsed CreateSandbox request")`,
	})
	if err != nil {
		return nil, false, err
	}

	eventsByNamespace := map[string][]interface{}{}
	for _, log := range logs {
		switch *log.Content.Message {
		case "Ran command":
			namespace := getNamespaceFromTags(*log.Content.Tags)
			eventsByNamespace[namespace] = append(eventsByNamespace[namespace], eventUpStarted{
				time: *log.Content.Timestamp,
			})
		case "Fatal error":
			attrs := *log.Content.Attributes
			namespace := getNamespaceFromTags(*log.Content.Tags)
			eventsByNamespace[namespace] = append(eventsByNamespace[namespace], eventUpCrashed{
				time: *log.Content.Timestamp,
				// TODO: Make sure these fields exist.
				err: attrs["msg"].(string),
			})
		case "Containers booted":
			namespace := getNamespaceFromTags(*log.Content.Tags)
			eventsByNamespace[namespace] = append(eventsByNamespace[namespace], eventContainersBooted{
				time: *log.Content.Timestamp,
			})
		case "Parsed CreateSandbox request":
			attrs := *log.Content.Attributes
			namespace := attrs["namespace"].(string)
			servicesIntf := attrs["serviceNames"]

			var services []string
			if servicesIntf != nil {
				for _, intf := range servicesIntf.([]interface{}) {
					services = append(services, intf.(string))
				}
			}

			eventsByNamespace[namespace] = append(eventsByNamespace[namespace], eventParsedCreateSandbox{
				time:     *log.Content.Timestamp,
				services: services,
			})
		}
	}

	var blimpUps []BlimpUpRecord
	for namespace, events := range eventsByNamespace {
		var blimpUp *BlimpUpRecord
		for _, event := range events {
			switch event := event.(type) {
			case eventUpStarted:
				if blimpUp != nil {
					blimpUps = append(blimpUps, *blimpUp)
				}
				blimpUp = &BlimpUpRecord{}
				blimpUp.Fields.Date = event.time
				blimpUp.Fields.DataDogLink = makeDataDogLink(namespace, event.time.Add(-1*time.Minute))
				blimpUp.Fields.Namespace = namespace

			case eventUpCrashed:
				if blimpUp != nil {
					blimpUp.Fields.Error = event.err
				}

			case eventParsedCreateSandbox:
				if blimpUp != nil {
					sort.Strings(event.services)
					blimpUp.Fields.Services = strings.Join(event.services, "\n")

					isExampleApp := false
					for _, exampleApp := range exampleApps {
						if slcEqualIgnoreOrder(event.services, exampleApp) {
							isExampleApp = true
							break
						}
					}

					blimpUp.Fields.ExampleApp = isExampleApp
				}

			case eventContainersBooted:
				if blimpUp != nil {
					blimpUp.Fields.SuccessfullyBooted = true
				}
			}
		}

		if blimpUp != nil {
			blimpUps = append(blimpUps, *blimpUp)
		}
	}
	return blimpUps, all, nil
}

func getNamespaceFromTags(tags []interface{}) string {
	for _, tag := range tags {
		tagStr, ok := tag.(string)
		if !ok {
			continue
		}

		parts := strings.Split(tagStr, ":")
		if len(parts) != 2 || parts[0] != "namespace" {
			continue
		}
		return parts[1]
	}
	panic("expected a namespace tag")
}

func searchDatadog(since time.Time, queries []string) ([]datadog.Log, bool, error) {
	ctx := context.WithValue(
		context.Background(),
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"apiKeyAuth": {
				Key: DataDogAPIKey,
			},
			"appKeyAuth": {
				Key: DataDogAppKey,
			},
		},
	)
	configuration := datadog.NewConfiguration()
	client := datadog.NewAPIClient(configuration)

	var exclusions []string
	for _, namespace := range ignoredNamespaces {
		// TODO: Test
		exclusions = append(exclusions,
			fmt.Sprintf("-namespace:%s", namespace),
			fmt.Sprintf("-@namespace:%s", namespace),
		)
	}

	limit := int32(1000)
	sort := datadog.LOGSSORT_TIME_ASCENDING
	body := datadog.LogsListRequest{
		Query: fmt.Sprintf("(%s) AND (%s)",
			strings.Join(queries, " OR "),
			strings.Join(exclusions, " ")),
		Limit: &limit,
		Time:  datadog.LogsListRequestTime{From: since, To: time.Now()},
		Sort:  &sort,
	}

	numRequests := 0
	var logs []datadog.Log
	for {
		resp, _, err := client.LogsApi.ListLogs(ctx).Body(body).Execute()
		if err != nil {
			return nil, false, fmt.Errorf("list: %w", err)
		}

		numRequests++
		logs = append(logs, *resp.Logs...)

		if resp.NextLogId == nil {
			return logs, true, nil
		} else if numRequests == maxDataDogRequests {
			return logs, false, nil
		}
		body.StartAt = resp.NextLogId
	}
}

func slcEqualIgnoreOrder(a, b []string) bool {
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}

func makeDataDogLink(namespace string, start time.Time) string {
	reqValues := url.Values{}
	reqValues.Add("from_ts", strconv.Itoa(int(start.UnixNano()/1000000)))
	reqValues.Add("to_ts", strconv.Itoa(int(start.Add(1*time.Hour).UnixNano()/1000000)))
	reqValues.Add("query", fmt.Sprintf("service:blimp AND (namespace:%s OR @namespace:%s)", namespace, namespace))
	reqValues.Add("cols", "status,source")
	reqValues.Add("live", "false")
	reqValues.Add("messageDisplay", "inline")
	reqValues.Add("stream-sort", "asc")

	base, err := url.Parse("https://app.datadoghq.com/logs")
	if err != nil {
		panic(err)
	}

	base.RawQuery = reqValues.Encode()
	return base.String()
}
