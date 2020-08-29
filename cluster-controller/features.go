package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/kelda/compose-go/types"

	"github.com/kelda/blimp/pkg/strs"
)

// GetUnsupportedFeatures checks for any references to unsupported features.
func GetUnsupportedFeatures(cfg types.Project) []string {
	var messages []string
	if len(cfg.Secrets) != 0 {
		messages = append(messages, "secrets")
	}
	if len(cfg.Configs) != 0 {
		messages = append(messages, "configs")
	}

	messages = append(messages, validateVolumes(cfg.Volumes)...)
	messages = append(messages, validateServices(cfg.Services)...)
	messages = append(messages, validateNetworks(cfg.Networks)...)
	return strs.Unique(messages)
}

func validateNetworks(networks map[string]types.NetworkConfig) []string {
	return addPrefix("Network", validator{[]field{
		// Bridge is the default network, and just signals that the containers
		// can talk to each other.
		{ID: ".Driver", AllowedValues: []interface{}{"bridge"}},
		{ID: ".Extras"},
		{ID: ".Name"},
		{ID: ".Labels"},
	}}.GetUnsupportedFields(networks))
}

func validateServices(services types.Services) []string {
	return addPrefix("Service", validator{[]field{
		{ID: ".Name"},
		{ID: ".Build.Dockerfile"},
		{ID: ".Build.Context"},
		{ID: ".Build.Args"},
		{ID: ".Build.Target"},
		{ID: ".Build.Labels"},
		{ID: ".Build.CacheFrom"},
		{ID: ".Command"},
		{ID: ".ContainerName"},
		{ID: ".Entrypoint"},
		{ID: ".Extends"},
		{ID: ".DependsOn"},
		{ID: ".Environment"},
		{ID: ".EnvFile"},
		{ID: ".ExtraHosts"},
		{ID: ".Hostname"},
		{ID: ".HealthCheck"},
		{ID: ".Image"},
		{ID: ".Links"},
		{ID: ".Networks.Aliases"},
		{ID: ".Ports.HostIP"},
		{ID: ".Ports.Target"},
		{ID: ".Ports.Published"},
		{ID: ".Ports.Protocol", AllowedValues: []interface{}{"tcp"}},
		{ID: ".Ports.Mode", AllowedValues: []interface{}{"ingress"}},
		{ID: ".Restart", AllowedValues: []interface{}{"no", "always", "unless-stopped", "on-failure"}},
		{ID: ".StdinOpen"},
		{ID: ".Tty"},
		{ID: ".Volumes.Type", AllowedValues: []interface{}{types.VolumeTypeBind, types.VolumeTypeVolume}},
		{ID: ".Volumes.Source"},
		{ID: ".Volumes.Target"},
		{ID: ".WorkingDir"},
		{ID: ".User"},

		// Meaningless.
		{ID: ".Labels"},
		// Containers can access all ports on other services by default.
		{ID: ".Expose"},
		{ID: ".Extras"},
	}}.GetUnsupportedFields(services))
}

func validateVolumes(volumes map[string]types.VolumeConfig) []string {
	messages := addPrefix("Volume", validator{[]field{
		{ID: ".Name"},
		{ID: ".Labels"},
		{ID: ".Extras"},
		{ID: ".Driver", AllowedValues: []interface{}{"local"}},
		{ID: ".DriverOpts"},
	}}.GetUnsupportedFields(volumes))

	for _, volume := range volumes {
		if volume.Driver == "" || volume.Driver == "local" {
			messages = append(addPrefix("Volume.DriverOpts",
				validateLocalVolumeOpts(volume.DriverOpts)))
		}
	}

	return messages
}

func validateLocalVolumeOpts(driverOpts map[string]string) []string {
	if len(driverOpts) == 0 {
		return nil
	}

	// The only kind of "local" volume options we support are specifying a bind
	// mount, which we will treat like a normal bind volume.
	// See https://github.com/docker/compose/issues/2957 for why people do this.
	isBind := func() bool {
		// Look for -o bind.
		mountOpts, ok := driverOpts["o"]
		if !ok {
			mountOpts, ok = driverOpts["options"]
			if !ok {
				return false
			}
		}
		for _, option := range strings.Split(mountOpts, ",") {
			if option == "bind" {
				return true
			}
		}

		// No -o bind found.
		return false
	}

	if !isBind() {
		// Everything is unsupported.
		return []string{""}
	}

	// See manpage mount(8) for details on which options are available for
	// "local" driver (although for some reason this doesn't match up
	// perfectly). Most options are unsupported.
	var messages []string
	for opt, value := range driverOpts {
		switch {
		case opt == "t" || opt == "type":
			// For bind mounts, type is ignored.
		case opt == "o" || opt == "options":
			for _, option := range strings.Split(value, ",") {
				if option != "bind" {
					messages = append(messages, "."+opt+"."+option)
				}
			}
		case opt == "device":
			// For bind mounts, device is the bind mount dir on the host. We
			// should have this.
		default:
			// We don't support anything else.
			messages = append(messages, "."+opt)
		}
	}
	return messages
}

// field is a reference to a field within a struct.
type field struct {
	// A reference to a field within a struct.
	// Must start with ".".
	// Fields within slices and maps are treated as if they were direct
	// references. For example, use ".Names.Name" to refer to the Name field in:
	// type User struct {
	//     Names []struct{
	//         Name string
	//     }
	// }
	ID string

	// ALl values are allowed if empty.
	AllowedValues []interface{}
}

// Supports returns whether the given value for the field is supported by Blimp.
func (f field) Supports(intf interface{}) bool {
	if len(f.AllowedValues) == 0 {
		return true
	}

	for _, okVal := range f.AllowedValues {
		if reflect.DeepEqual(intf, okVal) {
			return true
		}
	}
	return false
}

type validator struct {
	supportedFields []field
}

// GetUnsupportedFields walks all the non-zero fields of the given object, and ensures
// that they're set to a value supported by Blimp.
func (v validator) GetUnsupportedFields(obj interface{}) []string {
	return v.getUnsupportedFields("", reflect.ValueOf(obj))
}

func (v validator) supports(fieldID string, intf interface{}) bool {
	for _, field := range v.supportedFields {
		if field.ID == fieldID {
			return field.Supports(intf)
		}
	}
	return false
}

func (v validator) getUnsupportedFields(fieldID string, val reflect.Value) (unsupported []string) {
	if val.IsValid() && (val.IsZero() || v.supports(fieldID, val.Interface())) {
		return nil
	}

	switch val.Kind() {
	case reflect.Interface, reflect.Ptr:
		unsupported = v.getUnsupportedFields(fieldID, val.Elem())
	case reflect.Struct:
		for i := 0; i < val.NumField(); i++ {
			child := val.Field(i)
			childName := val.Type().Field(i).Name
			childID := fmt.Sprintf("%s.%s", fieldID, childName)
			unsupported = append(unsupported, v.getUnsupportedFields(childID, child)...)
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < val.Len(); i++ {
			unsupported = append(unsupported, v.getUnsupportedFields(fieldID, val.Index(i))...)
		}
	case reflect.Map:
		for _, key := range val.MapKeys() {
			unsupported = append(unsupported, v.getUnsupportedFields(fieldID, val.MapIndex(key))...)
		}
	default:
		unsupported = []string{fieldID}
	}

	return unsupported
}

func addPrefix(prefix string, items []string) (res []string) {
	for _, item := range items {
		res = append(res, prefix+item)
	}
	return res
}
