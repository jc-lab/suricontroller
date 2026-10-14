// Package yamlmerge merges Suricata YAML configuration layers.
//
// Mappings are merged recursively; scalars and sequences in a later layer
// replace earlier values. Documents keep their key order and comments, and
// are written back with the "%YAML 1.1" header Suricata requires.
package yamlmerge

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Header is prepended to every encoded document.
const Header = "%YAML 1.1\n---\n"

// Parse parses a YAML document and returns its root mapping. An empty
// document yields an empty mapping.
func Parse(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return NewMap(), nil
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return NewMap(), nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("yamlmerge: document root must be a mapping")
	}
	return root, nil
}

// Encode writes root as a Suricata YAML document.
func Encode(root *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(Header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NewMap returns an empty mapping node.
func NewMap() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }

// Scalar returns a plain string scalar node.
func Scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

// FromValue converts a Go value into a node.
func FromValue(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

// Clone deep-copies a node.
func Clone(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	if n.Content != nil {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, ch := range n.Content {
			c.Content[i] = Clone(ch)
		}
	}
	return &c
}

// Merge merges src into dst. Both must be mapping nodes.
func Merge(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		k, v := src.Content[i], src.Content[i+1]
		idx := index(dst, k.Value)
		if idx < 0 {
			dst.Content = append(dst.Content, Clone(k), Clone(v))
			continue
		}
		cur := dst.Content[idx+1]
		if cur.Kind == yaml.MappingNode && v.Kind == yaml.MappingNode {
			Merge(cur, v)
			continue
		}
		dst.Content[idx+1] = Clone(v)
	}
}

func index(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// Get returns the node at path, or nil.
func Get(root *yaml.Node, path ...string) *yaml.Node {
	n := root
	for _, p := range path {
		i := index(n, p)
		if i < 0 {
			return nil
		}
		n = n.Content[i+1]
	}
	return n
}

// GetString returns the scalar value at path, or "".
func GetString(root *yaml.Node, path ...string) string {
	n := Get(root, path...)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// Set stores value at path, creating intermediate mappings and replacing
// non-mapping intermediates.
func Set(root *yaml.Node, value *yaml.Node, path ...string) {
	n := root
	for i, p := range path {
		idx := index(n, p)
		if i == len(path)-1 {
			if idx < 0 {
				n.Content = append(n.Content, Scalar(p), value)
			} else {
				n.Content[idx+1] = value
			}
			return
		}
		if idx < 0 {
			child := NewMap()
			n.Content = append(n.Content, Scalar(p), child)
			n = child
			continue
		}
		if n.Content[idx+1].Kind != yaml.MappingNode {
			n.Content[idx+1] = NewMap()
		}
		n = n.Content[idx+1]
	}
}

// Delete removes the key at path. It reports whether the key existed.
func Delete(root *yaml.Node, path ...string) bool {
	if len(path) == 0 {
		return false
	}
	parent := Get(root, path[:len(path)-1]...)
	i := index(parent, path[len(path)-1])
	if i < 0 {
		return false
	}
	parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
	return true
}

// LeafPaths returns the dotted paths of all non-mapping values below root,
// sorted.
func LeafPaths(root *yaml.Node) []string {
	var out []string
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if prefix != "" {
				p = prefix + "." + p
			}
			if v := n.Content[i+1]; v.Kind == yaml.MappingNode && len(v.Content) > 0 {
				walk(v, p)
			} else {
				out = append(out, p)
			}
		}
	}
	if root != nil && root.Kind == yaml.MappingNode {
		walk(root, "")
	}
	sort.Strings(out)
	return out
}

// Shadowed returns the leaf paths of base that are overridden by any of the
// overlay layers: either the same path, or an ancestor/descendant path whose
// value replaces it.
func Shadowed(base *yaml.Node, overlays ...*yaml.Node) []string {
	var over []string
	for _, o := range overlays {
		over = append(over, LeafPaths(o)...)
	}
	var out []string
	for _, b := range LeafPaths(base) {
		for _, o := range over {
			if b == o || strings.HasPrefix(b, o+".") || strings.HasPrefix(o, b+".") {
				out = append(out, b)
				break
			}
		}
	}
	return out
}

// MoveToEnd moves the given top-level keys (if present) to the end of the
// mapping. Suricata applies settings in document order, so keys at the end
// win over equivalent dotted or underscore spellings earlier in the file.
func MoveToEnd(root *yaml.Node, keys ...string) {
	for _, k := range keys {
		i := index(root, k)
		if i < 0 {
			continue
		}
		kn, vn := root.Content[i], root.Content[i+1]
		root.Content = append(root.Content[:i], root.Content[i+2:]...)
		root.Content = append(root.Content, kn, vn)
	}
}

// TopKeys returns the top-level keys of a mapping.
func TopKeys(root *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		out = append(out, root.Content[i].Value)
	}
	return out
}
