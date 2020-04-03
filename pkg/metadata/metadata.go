package metadata

import (
	"strings"
)

const AliasesKey = "io.kelda.blimp/aliases"

func ParseAliases(aliases string) []string {
	return strings.Split(aliases, ",")
}

func Aliases(aliases []string) string {
	return strings.Join(aliases, ",")
}
