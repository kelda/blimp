package dockercompose

import (
	"fmt"
	"reflect"

	"github.com/kelda/compose-go/types"
)

// GetUnsupportedFeatures checks for any references to unsupported features.
func GetUnsupportedFeatures(cfg types.Config) []string {
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
	return uniqueStrings(messages)
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
		{ID: ".Entrypoint"},
		{ID: ".DependsOn"},
		{ID: ".Environment"},
		{ID: ".EnvFile"},
		{ID: ".ExtraHosts"},
		{ID: ".Hostname"},
		{ID: ".HealthCheck"},
		{ID: ".Image"},
		{ID: ".Networks.Aliases"},
		{ID: ".Ports.Target"},
		{ID: ".Ports.Published"},
		{ID: ".Ports.Protocol", AllowedValues: []interface{}{"tcp"}},
		{ID: ".Ports.Mode", AllowedValues: []interface{}{"ingress"}},
		{ID: ".Restart"},
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
	return addPrefix("Volume", validator{[]field{
		{ID: ".Name"},
		{ID: ".Labels"},
		{ID: ".Extras"},
		{ID: ".Driver", AllowedValues: []interface{}{"local"}},
	}}.GetUnsupportedFields(volumes))
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

func uniqueStrings(strs []string) (unique []string) {
	strSet := map[string]struct{}{}
	for _, str := range strs {
		if _, ok := strSet[str]; ok {
			continue
		}
		strSet[str] = struct{}{}
		unique = append(unique, str)
	}
	return unique
}
