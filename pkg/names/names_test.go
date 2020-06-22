package names_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kelda/blimp/pkg/names"
)

func TestPodName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expOutput string
	}{
		{
			name:      "already valid 1",
			input:     "qwerty",
			expOutput: "qwerty-65e84be335",
		},
		{
			name:      "already valid 2",
			input:     "123qwerty789",
			expOutput: "123qwerty789-56396e2147",
		},
		{
			name:      "already valid 3",
			input:     "123-qwerty-789",
			expOutput: "123-qwerty-789-d39330775a",
		},
		{
			name:      "convert to lowercase",
			input:     "123-QwerTY-789",
			expOutput: "123-qwerty-789-e337d0b104",
		},
		{
			name:      "remove garbage characters after lowercase conversion",
			input:     "!@#qW-er&*()ty",
			expOutput: "qw-erty-6e90f594cb",
		},
		{
			name:      "remove leading hyphen",
			input:     "-qwer-ty",
			expOutput: "qwer-ty-778130d355",
		},
		{
			name:      "remove trailing hyphen",
			input:     "qwer-ty-",
			expOutput: "qwer-ty-61653c842a",
		},
		{
			name:      "remove leading and trailing hyphen",
			input:     "-qwer-ty-",
			expOutput: "qwer-ty-e91e49ff66",
		},
		{
			name:      "leading hyphen after invalid characters",
			input:     "!@#-qwerty",
			expOutput: "qwerty-20ab96a526",
		},
		{
			name:      "truncate after removal",
			input:     "--abcdefghijklm^^^^^nopqrstuvwxyzabcdefghijklmnopqrstuvwxyz-Abcdefghijkl--",
			expOutput: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx-b7a9e9960b",
		},
		{
			name:      "single character",
			input:     "q",
			expOutput: "q-8e35c2cd3b",
		},
	}

	for _, test := range tests {
		podName := names.PodName(test.input)
		assert.Equal(t, test.expOutput, podName, test.name)
	}
}
