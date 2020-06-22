package analytics

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/version"
)

// Log is the global analytics logger. Log events created via this object are
// automatically pushed into our analytics system.
var Log = noopLogger()

type StreamID struct {
	Source    string
	Namespace string
}

func Init(c cluster.ManagerClient, id StreamID) {
	// Don't publish analytics during development.
	if version.Version == "latest" {
		return
	}

	Log.AddHook(&hook{
		levels: logrus.AllLevels,
		stream: "analytics",
		client: c,
		id:     id,
	})

	// Forward error and warning logs for the global logger.
	logrus.AddHook(&hook{
		levels: []logrus.Level{logrus.WarnLevel, logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel},
		client: c,
		stream: "logs",
		id:     id,
	})
}

// ddFormatter formats log entries according to DD's preferred format.
var ddFormatter = &logrus.JSONFormatter{
	FieldMap: logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyLevel: "status",
		logrus.FieldKeyMsg:   "message",
	},
}

type hook struct {
	client cluster.ManagerClient
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
		return nil
	}

	//nolint:errcheck // We want to return nil whether or not this errors.
	h.client.ProxyAnalytics(context.TODO(), &cluster.ProxyAnalyticsRequest{
		Body: string(jsonBytes),
	})
	return nil
}

func noopLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(ioutil.Discard)
	return logger
}
