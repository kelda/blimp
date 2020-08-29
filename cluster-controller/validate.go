package main

import (
	"fmt"

	"github.com/kelda/compose-go/types"
)

// ValidateComposeFile attempts to find common cases of broken Compose files so
// we can abort early and provide a helpful error.
// This is needlessly abstract for now, but I imagine more will be added.
func ValidateComposeFile(cfg types.Project) []string {
	problems := []string{}

	problems = append(problems, checkNonexistentDepends(cfg.Services)...)

	return problems
}

// checkNonexistentDepends checks that every DependsOn matches an actual service
// defined in the list of services.
func checkNonexistentDepends(services types.Services) []string {
	problems := []string{}

	serviceExists := func(service string) bool {
		for _, matchingService := range services {
			if service == matchingService.Name {
				// We found a match!
				return true
			}
		}
		// No match found.
		return false
	}

	for _, service := range services {
		for dependency := range service.DependsOn {
			if !serviceExists(dependency) {
				problems = append(problems, fmt.Sprintf(
					"The %s service depends on %q, which does not exist",
					service.Name, dependency))
			}
		}
	}

	return problems
}
