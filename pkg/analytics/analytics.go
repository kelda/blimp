package analytics

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/version"
)

var (
	// Log is the global analytics logger. Log events created via this object are
	// automatically pushed into our analytics system.
	Log = newAnalyticsLogger()

	// Mocked out for unit testing.
	httpPost = http.Post
)

func newAnalyticsLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(ioutil.Discard)

	// Don't publish analytics during development.
	if version.Version != "latest" {
		logger.AddHook(&hook{
			endpoint:   "https://http-intake.logs.datadoghq.com/v1/input/9ac6e71a87aa0c160c84017823ce2348",
			levels:     logrus.AllLevels,
			streamType: "blimp-analytics",
		})
	}

	return logger
}

const (
	ddContentType = "application/json"
)

// ddFormatter formats log entries according to DD's preferred format
var ddFormatter = &logrus.JSONFormatter{
	FieldMap: logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyLevel: "status",
		logrus.FieldKeyMsg:   "message",
	},
}

type hook struct {
	// Documentation: https://docs.datadoghq.com/api/?lang=python#send-logs-over-http
	// https://docs.datadoghq.com/logs/log_collection/?tab=ussite#datadog-logs-endpoints
	endpoint   string
	levels     []logrus.Level
	streamType string
}

func (h *hook) Levels() []logrus.Level {
	return h.levels
}

func (h *hook) Fire(entry *logrus.Entry) error {
	tags := []string{
		fmt.Sprintf("stream:%s", h.streamType),
	}
	dataCopy := map[string]interface{}{
		"ddtags":   strings.Join(tags, ","),
		"ddsource": "blimp",
	}
	for k, v := range entry.Data {
		dataCopy[k] = v
	}

	// Copy the entry so that when we don't change it when we add
	// DataDog-specific values to Data.
	entryCopy := *entry
	entryCopy.Data = dataCopy

	// DataDog doesn't have a concept of "panic" level, so we treat panics as
	// fatal errors.
	if entry.Level == logrus.PanicLevel {
		entryCopy.Level = logrus.FatalLevel
	}

	jsonBytes, err := ddFormatter.Format(&entryCopy)
	if err != nil {
		logrus.WithError(err).Debug("Failed to marshal log entry for analytics")
		return nil
	}

	resp, err := httpPost(h.endpoint, ddContentType, bytes.NewReader(jsonBytes))
	if err != nil {
		logrus.WithError(err).Debug("Failed to update analytics")
	} else {
		// Close the body to avoid leaking resources.
		resp.Body.Close()
	}

	// Never return an error because doing so causes the error to be printed
	// directly to `stderr`, which pollutes the logs:
	return nil
}
