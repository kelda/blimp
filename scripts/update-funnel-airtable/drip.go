package main

import (
	"fmt"
	"strings"

	drip "github.com/kklin/drip-go"
)

func syncToDrip(users []UserRecord) error {
	c, err := drip.New(DripAPIKey, DripAccountID)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	// Get subscribers.
	subscribers := map[string][]drip.Subscriber{}
	page := 1
	for {
		perPage := 1000
		resp, err := c.ListSubscribers(&drip.ListSubscribersReq{
			Status:  "all",
			Page:    &page,
			PerPage: &perPage,
		})
		if err != nil {
			return fmt.Errorf("list subscribers: %w", err)
		}

		for _, subscriber := range resp.Subscribers {
			subscribers[strings.ToLower(subscriber.Email)] = append(subscribers[subscriber.Email], *subscriber)
		}

		if resp.Meta.TotalPages == page {
			break
		}
		page++
	}

	// For each user, get the tag for their stage, and queue up any updates if
	// necessary.
	var updateReqs []drip.UpdateSubscriber
	for _, user := range users {
		var tag string
		switch user.Fields.Stage {
		case StageLoggedIn:
			tag = "[Blimp Usage] Logged In"
		case StageRanExampleApp:
			tag = "[Blimp Usage] Ran Example App"
		case StageRanOwnApp, StageOwnAppFailed:
			tag = "[Blimp Usage] Ran Own App"
		case StageRepeatUser:
			tag = "[Blimp Usage] Repeat User"
		default:
			fmt.Printf("Unknown stage for %s: %s\n", user.Fields.Email, user.Fields.Stage)
			continue
		}

		subscribers, ok := subscribers[strings.ToLower(user.Fields.Email)]
		if !ok {
			fmt.Printf("Creating new subscriber for %s\n", user.Fields.Email)
			updateReqs = append(updateReqs, drip.UpdateSubscriber{
				Email: user.Fields.Email,
				Tags:  []string{tag},
				CustomFields: map[string]string{
					"full_name": user.Fields.Name,
				},
			})
			continue
		}

	Outer:
		for _, subscriber := range subscribers {
			// Don't add the tag if the user already has it.
			for _, currTag := range subscriber.Tags {
				if currTag == tag {
					continue Outer
				}
			}

			fmt.Printf("Updating subscriber for %s\n", user.Fields.Email)
			updateReqs = append(updateReqs, drip.UpdateSubscriber{
				// Note that even though we don't explicitly set other fields,
				// like Name, the Drip API won't unset those fields.
				ID:   subscriber.ID,
				Tags: append(subscriber.Tags, tag),
			})
		}
	}

	// Execute the required updates.
	if len(updateReqs) == 0 {
		return nil
	}

	updateReq := &drip.UpdateBatchSubscribersReq{
		Batches: []drip.SubscribersBatch{
			{
				Subscribers: updateReqs,
			},
		},
	}
	resp, err := c.UpdateBatchSubscribers(updateReq)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	if len(resp.Errors) != 0 {
		return fmt.Errorf("update: %+v", resp.Errors)
	}
	return nil
}
