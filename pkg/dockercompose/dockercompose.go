package dockercompose

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/buger/goterm"
	"github.com/ghodss/yaml"
	"github.com/kelda/compose-go/envfile"
	"github.com/kelda/compose-go/loader"
	"github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/hash"
)

var fs = afero.NewOsFs()

// Load loads and merges the given compose files. If `services` is non-empty,
// the return config only includes the services specified in `services`.
func Load(composePath string, overridePaths, services []string) (types.Project, error) {
	var configFiles []types.ConfigFile
	for _, path := range append([]string{composePath}, overridePaths...) {
		b, err := afero.ReadFile(fs, path)
		if err != nil {
			return types.Project{}, errors.WithContext("read compose file", err)
		}

		configIntf, err := loader.ParseYAML(b)
		if err != nil {
			msg := fmt.Sprintf("Failed to parse Compose file (%s)\n"+
				"Error: %s", path, err)
			if context, ok := getErrorContext(b, err.Error()); ok {
				msg += "\n\n" + context
			}
			return types.Project{}, errors.NewFriendlyError(msg)
		}

		configFiles = append(configFiles, types.ConfigFile{
			Filename: filepath.Base(path),
			Config:   configIntf,
		})
	}

	env := map[string]string{}
	dotenvPath := filepath.Join(filepath.Dir(composePath), ".env")
	if _, err := os.Stat(dotenvPath); err == nil {
		dotenv, err := parseEnvFile(dotenvPath)
		if err != nil {
			return types.Project{}, errors.NewFriendlyError(
				"Failed to parse .env file at %s.\n\n"+
					"The full error was:\n%s",
				dotenvPath, err)
		}

		env = dotenv
	}

	// Environment variables in the shell take precedence over the .env file:
	// https://docs.docker.com/compose/environment-variables/#the-env-file
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		var val string
		if len(pair) == 2 {
			val = pair[1]
		}
		env[pair[0]] = val
	}

	opts := []func(*loader.Options){
		// Discard env_files references after evaluating them so that the
		// cluster manager doesn't error when it tries to load the
		// configuration file.
		loader.WithDiscardEnvFiles,

		// Skip validation so that the loader doesn't error on non-v3 files.
		withSkipValidation,

		// Skip consistency check since it's broken for volumes that are just a path.
		withSkipConsistency,
	}

	cfgPtr, err := load(types.ConfigDetails{
		WorkingDir:  filepath.Dir(composePath),
		ConfigFiles: configFiles,
		Environment: env,
	}, opts...)
	if err != nil {
		if forbiddenPropertiesErr, ok := err.(*loader.ForbiddenPropertiesError); ok {
			var tips []string
			for property, tip := range forbiddenPropertiesErr.Properties {
				tips = append(tips, fmt.Sprintf("%s: %s", property, tip))
			}
			return types.Project{}, errors.NewFriendlyError("Compose File uses forbidden properties. "+
				"Please upgrade to Compose Spec version 3 (http://link.kelda.io/upgrade-compose).\n\n%s",
				strings.Join(tips, "\n"))
		}

		debugCmd := []string{"docker-compose"}
		for _, path := range append([]string{composePath}, overridePaths...) {
			debugCmd = append(debugCmd, "-f", path)
		}
		debugCmd = append(debugCmd, "config")
		return types.Project{}, errors.NewFriendlyError("Malformed Docker Compose file. "+
			"To get a more informative error message, run `%s`.\n\n"+
			"The full error was:\n%s", strings.Join(debugCmd, " "), err)
	}

	for svcIdx, svc := range cfgPtr.Services {
		if svc.ContainerName != "" {
			continue
		}

		cfgPtr.Services[svcIdx].ContainerName = fmt.Sprintf("%s_%s_1",
			filepath.Base(filepath.Dir(composePath)), svc.Name)
	}

	// Convert build contexts to absolute paths, set the default value for the
	// dockerfile field, and validate that the dockerfile exists.
	for svcIdx, svc := range cfgPtr.Services {
		if svc.Build == nil {
			continue
		}

		if !filepath.IsAbs(svc.Build.Context) {
			cfgPtr.Services[svcIdx].Build.Context = filepath.Join(filepath.Dir(composePath), svc.Build.Context)
		}
		if svc.Build.Dockerfile == "" {
			cfgPtr.Services[svcIdx].Build.Dockerfile = "Dockerfile"
		}

		dockerfilePath := filepath.Join(cfgPtr.Services[svcIdx].Build.Context, cfgPtr.Services[svcIdx].Build.Dockerfile)
		stat, err := os.Stat(dockerfilePath)
		if err != nil {
			return types.Project{}, errors.NewFriendlyError(
				"Can't open Dockerfile for %s, please make sure it exists and can be accessed.\n"+
					"The Dockerfile should be at the path %s.\nThe underlying error was: %v",
				svc.Name, dockerfilePath, err)
		}
		if !stat.Mode().IsRegular() {
			return types.Project{}, errors.NewFriendlyError(
				"The Dockerfile for %s (%s) is not a regular file.",
				svc.Name, dockerfilePath)
		}
	}

	for svcIdx, svc := range cfgPtr.Services {
		for volumeIdx, volume := range svc.Volumes {
			// Assign names to any volumes that are specified as just paths. E.g.:
			// services:
			//   web:
			//     image: 'ubuntu'
			//     volumes:
			//       - '/node_modules'
			if volume.Type == types.VolumeTypeVolume && volume.Source == "" {
				name := hash.DNSCompliant(fmt.Sprintf("%s-%s", svc.Name, volume.Target))
				cfgPtr.Services[svcIdx].Volumes[volumeIdx].Source = name
			}

			if volume.Type != types.VolumeTypeBind {
				continue
			}

			// Resolve any bind volumes that reference symlinks. Docker mounts
			// the contents of the symlink, rather than the symlink itself.
			fi, err := os.Lstat(volume.Source)
			if err != nil {
				if !os.IsNotExist(err) {
					log.WithError(err).WithField("path", volume.Source).Warn("Failed to stat volume")
				}
				continue
			}

			if fi.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(volume.Source)
				if err != nil {
					log.WithError(err).WithField("path", volume.Source).Warn(
						"Failed to get symlink target for volume")
					continue
				}

				newPath := link
				if !filepath.IsAbs(link) {
					newPath = filepath.Join(filepath.Dir(volume.Source), link)
				}
				cfgPtr.Services[svcIdx].Volumes[volumeIdx].Source = newPath

			}
		}
	}

	// If the user specified specific services to boot, modify the config file
	// to only contain those services, and their dependencies.
	if len(services) != 0 {
		// cfg.WithServices also walks all dependencies of the services.
		var filtered []types.ServiceConfig
		err := cfgPtr.WithServices(services, func(service types.ServiceConfig) error {
			filtered = append(filtered, service)
			return nil
		})
		if err != nil {
			return types.Project{}, errors.WithContext("lookup services", err)
		}

		cfgPtr.Services = filtered
	}

	cfgPtr.Name = getProjectName(composePath)
	return *cfgPtr, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	parsed, err := envfile.Parse(path)
	if err != nil {
		return nil, err
	}

	ret := map[string]string{}
	for k, vPtr := range parsed {
		v := ""
		if vPtr != nil {
			v = *vPtr
		}
		ret[k] = v
	}
	return ret, nil
}

// Unmarshal loads the parsed compose spec that was serialized by the Marshal function.
func Unmarshal(b []byte) (parsed types.Project, err error) {
	configIntf, err := loader.ParseYAML(b)
	if err != nil {
		return types.Project{}, errors.WithContext("parse", err)
	}

	cfgPtr, err := load(types.ConfigDetails{
		ConfigFiles: []types.ConfigFile{
			{
				Config: configIntf,
			},
		},
	}, withSkipValidation, withSkipConsistency, withSkipInterpolation, withSkipExtends)
	if err != nil {
		return types.Project{}, errors.WithContext("load", err)
	}

	return *cfgPtr, nil
}

// Marshal serializes a parsed compose spec so that it can be loaded by the
// Unmarshal function.
// Note that `Marshal` and `Unmarshal` used to use `types.Config` types, but
// switching to `types.Project` is fully backwards compatible, since
// `types.Project` and `types.Config` both have the same field names and types
// for `Services`, `Networks`, and `Volumes`.
func Marshal(cfg types.Project) ([]byte, error) {
	return yaml.Marshal(cfg)
}

func withSkipValidation(opts *loader.Options) {
	opts.SkipValidation = true
}

func withSkipConsistency(opts *loader.Options) {
	opts.SkipConsistencyCheck = true
}

func withSkipInterpolation(opts *loader.Options) {
	opts.SkipInterpolation = true
}

func withSkipExtends(opts *loader.Options) {
	opts.SkipExtends = true
}

func getErrorContext(file []byte, errMsg string) (string, bool) {
	matches := regexp.MustCompile(`yaml: line ?(\d+):`).FindSubmatch([]byte(errMsg))
	if len(matches) != 2 {
		return "", false
	}

	errorLine, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		return "", false
	}

	lines := strings.Split(string(file), "\n")
	inRange := func(line int) bool {
		return line <= len(lines)
	}

	startLine := errorLine - 1
	if !inRange(startLine) {
		return "", false
	}

	endLine := errorLine + 1
	if !inRange(endLine) {
		endLine = errorLine
		if !inRange(endLine) {
			return "", false
		}
	}

	var printLines []string
	for i := startLine; i <= endLine; i++ {
		// The line numbers are one-indexed, while `lines` is zero-indexed.
		line := fmt.Sprintf("%d | %s", i, lines[i-1])
		if i == errorLine {
			line = goterm.Color(line, goterm.YELLOW)
		}
		printLines = append(printLines, line)
	}
	return strings.Join(printLines, "\n"), true
}

// The compose-go library panics when the provided YAML file contains
// unexpected types. For example, the following Compose file causes a panic:
// ```
// version: '3'
// services:
//   bad: parsing
// ```
// load wraps the call to loader.Load and catches any panics.
func load(det types.ConfigDetails, opts ...func(opts *loader.Options)) (cfg *types.Project, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("%s", r)
		}
	}()

	cfg, err = loader.Load(det, opts...)
	return
}

func getProjectName(absComposePath string) string {
	// See https://github.com/docker/compose/blob/854c14a5bcf566792ee8a972325c37590521656b/compose/cli/command.py#L176.
	project := filepath.Base(filepath.Dir(absComposePath))
	badChar := regexp.MustCompile(`[^-_a-z0-9]`)
	return badChar.ReplaceAllString(strings.ToLower(project), "")
}

func ParseNamedBindVolume(vol types.VolumeConfig) (source string, ok bool) {
	if vol.Driver != "" && vol.Driver != "local" {
		return "", false
	}

	// Look for -o bind.
	mountOpts, ok := vol.DriverOpts["o"]
	if !ok {
		mountOpts = vol.DriverOpts["options"]
	}
	for _, opt := range strings.Split(mountOpts, ",") {
		if opt == "bind" {
			return vol.DriverOpts["device"], true
		}
	}

	return "", false
}
