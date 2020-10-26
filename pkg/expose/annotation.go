package expose

import (
	"encoding/json"

	"github.com/kelda/blimp/pkg/errors"
)

type ExposeInfo struct {
	Service string
	Port    int
}

// ExposeAnnotation maps secret tokens to their underlying ExposeInfos.
type ExposeAnnotation map[string]ExposeInfo

func (annotation ExposeAnnotation) ToJson() (string, error) {
	bytes, err := json.Marshal(annotation)
	if err != nil {
		return "", errors.WithContext("marshal expose annotation", err)
	}
	return string(bytes), nil
}

func ParseJsonAnnotation(annotation string) (ExposeAnnotation, error) {
	var parsedAnnotation ExposeAnnotation
	err := json.Unmarshal([]byte(annotation), &parsedAnnotation)
	if err != nil {
		return ExposeAnnotation{}, errors.WithContext("unmarshal expose annotation", err)
	}
	return parsedAnnotation, nil
}
