package analytics

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda/blimp/pkg/errors"
)

// Log is the global analytics logger. Log events created via this object are
// automatically pushed into our analytics system.
var Log = noopLogger()

type StreamID struct {
	Source    string
	Namespace string
}

func Init(id StreamID) {
	// Don't publish analytics during development.
	if version.Version == "latest" {
		return
	}

	Log.AddHook(&hook{
		levels: logrus.AllLevels,
		stream: "analytics",
		id:     id,
	})

	// Forward error and warning logs for the global logger.
	logrus.AddHook(&hook{
		levels: []logrus.Level{logrus.WarnLevel, logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel},
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
		return errors.WithContext("format log", err)
	}

	if err := Post(jsonBytes); err != nil {
		return errors.WithContext("post log", err)
	}

	return nil
}

func noopLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(ioutil.Discard)
	return logger
}

func Post(body []byte) error {
	resp, err := http.Post(
		"https://http-intake.logs.datadoghq.com/v1/input/9ac6e71a87aa0c160c84017823ce2348",
		"application/json",
		bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	// Close the body to avoid leaking resources.
	resp.Body.Close()
	return nil
}
