package dockercompose

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
)

// TODO: Could generate from the schema definitions in the Docker Compose
// project (https://github.com/docker/compose/tree/master/compose/config).

type Config struct {
	Services map[string]Service `json:"services"`
}

type Service struct {
	Image        string        `json:"image"`
	Command      []string      `json:"command"`
	PortMappings []PortMapping `json:"ports"`
	Build        *Build        `json:"build"`
}

type PortMapping struct {
	// The port accessed by the user via localhost.
	HostPort uint32

	// The port inside the container.
	ContainerPort uint32
}

func (mapping *PortMapping) UnmarshalJSON(b []byte) error {
	var mappingStr string
	if err := yaml.Unmarshal(b, &mappingStr); err != nil {
		return fmt.Errorf("parse string: %w", err)
	}

	var mappingParts []uint32
	// TODO: Port ranges.
	for _, portStr := range strings.Split(mappingStr, ":") {
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			return fmt.Errorf("parse mapping port: %w", err)
		}
		mappingParts = append(mappingParts, uint32(port))
	}

	switch len(mappingParts) {
	case 0:
		return errors.New("malformed port")
	case 1:
		mapping.HostPort = mappingParts[0]
		mapping.ContainerPort = mappingParts[0]
	case 2:
		mapping.HostPort = mappingParts[0]
		mapping.ContainerPort = mappingParts[1]
	default:
		return errors.New("malformed port")
	}
	return nil
}

type Build struct {
	Dockerfile string
	Context    string
}

func (build *Build) UnmarshalJSON(b []byte) error {
	var intf interface{}
	if err := yaml.Unmarshal(b, &intf); err != nil {
		return err
	}

	switch v := intf.(type) {
	case string:
		build.Context = v
	case map[string]interface{}:
		var ok bool
		build.Dockerfile, ok = v["dockerfile"].(string)
		if !ok {
			return fmt.Errorf("unexpected type for dockerfile")
		}

		build.Context, ok = v["context"].(string)
		if !ok {
			return fmt.Errorf("unexpected type for context")
		}
	default:
		return errors.New("unexpected type for build")
	}

	return nil
}

func Parse(cfg []byte) (parsed Config, err error) {
	if err := yaml.Unmarshal(cfg, &parsed); err != nil {
		return Config{}, fmt.Errorf("parse: %w", err)
	}
	return parsed, nil
}
