package filters

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

//nolint:unused
type PathExclude struct {
	excludePaths sets.String
	prefixes     []string
}

func (a PathExclude) hasPrefix(pth string) bool {
	for _, prefix := range a.prefixes {
		if strings.HasPrefix(pth, prefix) {
			return true
		}
	}
	return false
}
