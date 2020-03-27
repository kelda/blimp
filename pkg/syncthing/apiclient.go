package syncthing

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type APIClient struct {
	ServerAddress string
	APIKey        string
}

type Completion struct {
	Completion int `json:"completion"`
}

func (c APIClient) GetCompletion(device, folder string) (Completion, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/rest/db/completion", c.ServerAddress), nil)
	if err != nil {
		return Completion{}, fmt.Errorf("create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("device", device)
	q.Add("folder", folder)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("X-API-Key", c.APIKey)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Completion{}, fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()

	var completion Completion
	if err := json.NewDecoder(resp.Body).Decode(&completion); err != nil {
		return Completion{}, fmt.Errorf("decode: %w", err)
	}

	return completion, nil
}
