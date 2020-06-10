package metadata

import (
	"strings"
)

const AliasesKey = "io.kelda.blimp/aliases"

// CustomPodAnnotations contains all annotations that Blimp could apply to pods
// that should persist across restarts, except blimp.appliedObject.
var CustomPodAnnotations = []string{
	AliasesKey,
}

func ParseAliases(aliases string) []string {
	return strings.Split(aliases, ",")
}

func Aliases(aliases []string) string {
	return strings.Join(aliases, ",")
}
