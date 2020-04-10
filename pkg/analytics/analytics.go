package analytics

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/version"
)

// Log is the global analytics logger. Log events created via this object are
// automatically pushed into our analytics system.
var Log = noopLogger()

// DatadogPoster posts the given payload to the Datadog log API.
type DatadogPoster interface {
	Post(body string) error
}

// DirectPoster posts logs directly to Datadog.
type DirectPoster struct{}

func (c DirectPoster) Post(body string) error {
	resp, err := http.Post(
		"https://http-intake.logs.datadoghq.com/v1/input/9ac6e71a87aa0c160c84017823ce2348",
		"application/json",
		bytes.NewBufferString(body))
	if err != nil {
		return err
	}

	// Close the body to avoid leaking resources.
	resp.Body.Close()
	return nil
}

// ProxyPoster posts logs to the manager, which in turn posts to Datadog.
type ProxyPoster struct {
	Client cluster.ManagerClient
}

func (c ProxyPoster) Post(body string) error {
	_, err := c.Client.ProxyAnalytics(context.TODO(), &cluster.ProxyAnalyticsRequest{
		Body: body,
	})
	return err
}

type StreamID struct {
	Source    string
	Namespace string
}

func Init(p DatadogPoster, id StreamID) {
	// Don't publish analytics during development.
	if version.Version == "latest" {
		return
	}

	Log.AddHook(&hook{
		levels: logrus.AllLevels,
		poster: p,
		stream: "analytics",
		id:     id,
	})

	// Forward error and warning logs for the global logger.
	logrus.AddHook(&hook{
		levels: []logrus.Level{logrus.WarnLevel, logrus.ErrorLevel},
		poster: p,
		stream: "logs",
		id:     id,
	})
}

// ddFormatter formats log entries according to DD's preferred format
var ddFormatter = &logrus.JSONFormatter{
	FieldMap: logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyLevel: "status",
		logrus.FieldKeyMsg:   "message",
	},
}

type hook struct {
	poster DatadogPoster
	levels []logrus.Level
	stream string
	id     StreamID
}

func (h *hook) Levels() []logrus.Level {
	return h.levels
}

func (h *hook) Fire(entry *logrus.Entry) error {
	tags := []string{
		fmt.Sprintf("stream:%s", h.stream),
		fmt.Sprintf("version:%s", version.Version),
		fmt.Sprintf("namespace:%s", h.id.Namespace),
	}
	dataCopy := map[string]interface{}{
		"ddtags":   strings.Join(tags, ","),
		"ddsource": h.id.Source,
		"service":  "blimp",
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
		// Don't log anything when analytics errors to avoid scaring users.
		return nil
	}

	if err = h.poster.Post(string(jsonBytes)); err != nil {
		// Don't log anything when analytics errors to avoid scaring users.
		return nil
	}

	return nil
}

func noopLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(ioutil.Discard)
	return logger
}
