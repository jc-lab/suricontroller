// Package nodeid validates node identifiers. Node ids are used as path
// components (e.g. nodes/{node-id}/ in the config repository), so the
// accepted alphabet is deliberately small.
package nodeid

import (
	"fmt"
	"regexp"
	"strings"
)

var pattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

var reserved = map[string]bool{"common": true}

// Validate reports whether id is an acceptable node id.
func Validate(id string) error {
	if !pattern.MatchString(id) {
		return fmt.Errorf("invalid node id %q: must match %s", id, pattern)
	}
	if reserved[id] || strings.HasPrefix(id, "_") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid node id %q: reserved", id)
	}
	return nil
}
