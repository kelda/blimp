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
	Volumes  map[string]Volume  `json:"volumes"`
}

type Service struct {
	Image string `json:"image"`
	// TODO: Command and Entrypoint can be specified by a single raw string as well.
	Command      []string             `json:"command"`
	Entrypoint   []string             `json:"entrypoint"`
	PortMappings []PortMapping        `json:"ports"`
	Build        *Build               `json:"build"`
	Volumes      []VolumeMount        `json:"volumes"`
	Environment  EnvironmentVariables `json:"environment"`
	// TODO: Validate that DependsOn only references declared services.
	DependsOn []string `json:"depends_on"`
}

type EnvironmentVariables map[string]string

func (vars *EnvironmentVariables) UnmarshalJSON(b []byte) error {
	*vars = map[string]string{}

	var intf interface{}
	if err := yaml.Unmarshal(b, &intf); err != nil {
		return err
	}

	// Environment variables may be expressed as either an array or dictionary.
	switch varsIntf := intf.(type) {
	case []interface{}:
		for _, keyValIntf := range varsIntf {
			keyValStr, ok := keyValIntf.(string)
			if !ok {
				return errors.New("expected a list of strings")
			}

			keyValParts := strings.SplitN(keyValStr, "=", 2)
			if len(keyValParts) != 2 {
				return fmt.Errorf("missing environment variable value: %s", keyValStr)
			}

			(*vars)[keyValParts[0]] = keyValParts[1]
		}
	case map[string]interface{}:
		for key, valIntf := range varsIntf {
			valStr, ok := valIntf.(string)
			if !ok {
				return fmt.Errorf("environment variable value must be a string: %v", valIntf)
			}

			(*vars)[key] = valStr
		}
	default:
		return errors.New("unexpected type for environment")
	}

	return nil
}

type Volume struct{}

type VolumeMount struct {
	Type   string
	Source string
	Target string

	// If the volume mount was defined using the string syntax, the volume's
	// type can't be inferred until the mount is compared with the volumes
	// explicitly declared by the Docker Compose file.
	guessType bool
}

func (mount *VolumeMount) UnmarshalJSON(b []byte) error {
	var intf interface{}
	if err := yaml.Unmarshal(b, &intf); err != nil {
		return err
	}

	// Volumes may be expressed as a string as passed to `docker run`, or in
	// full YAML syntax.
	switch v := intf.(type) {
	case string:
		mountParts := strings.Split(v, ":")
		if len(mountParts) == 1 {
			mount.Target = mountParts[0]
		} else {
			mount.guessType = true
			mount.Source = mountParts[0]
			mount.Target = mountParts[1]
			// TODO: 3rd part is Mode.
		}
	case map[string]interface{}:
		var ok bool
		mount.Type, ok = v["type"].(string)
		if !ok {
			return errors.New("unexpected type for type")
		}

		mount.Source, ok = v["source"].(string)
		if !ok {
			return errors.New("unexpected type for source")
		}

		mount.Target, ok = v["target"].(string)
		if !ok {
			return errors.New("unexpected type for target")
		}
	default:
		return errors.New("unexpected type for mount")
	}

	return nil
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

	for _, svc := range parsed.Services {
		for i, volume := range svc.Volumes {
			if !volume.guessType {
				continue
			}

			if _, ok := parsed.Volumes[volume.Source]; ok {
				svc.Volumes[i].Type = "volume"
			} else {
				svc.Volumes[i].Type = "bind"
			}
		}
	}
	return parsed, nil
}
