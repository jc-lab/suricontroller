package ruleset

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// compileFnmatch compiles a shell pattern with the semantics of Python's
// fnmatch.fnmatch on POSIX (case-sensitive, full match, "*" and "?" match
// any character including "/", "[...]" sets with "!" negation, no escaping).
// The translation follows fnmatch.translate from Python 3.12.
func compileFnmatch(pat string) (*regexp.Regexp, error) {
	p := []rune(pat)
	n := len(p)
	var res strings.Builder
	res.WriteString(`\A(?s:`)
	lastStar := false
	i := 0
	for i < n {
		c := p[i]
		i++
		switch c {
		case '*':
			if !lastStar {
				res.WriteString(".*")
			}
			lastStar = true
			continue
		case '?':
			res.WriteString(".")
		case '[':
			j := i
			if j < n && p[j] == '!' {
				j++
			}
			if j < n && p[j] == ']' {
				j++
			}
			for j < n && p[j] != ']' {
				j++
			}
			if j >= n {
				res.WriteString(`\[`)
				break
			}
			stuff := fnmatchSetStuff(p, i, j)
			i = j + 1
			switch {
			case stuff == "":
				res.WriteString(`[^\x00-\x{10FFFF}]`) // empty range: never match
			case stuff == "!":
				res.WriteString(".")
			default:
				if stuff[0] == '!' {
					stuff = "^" + stuff[1:]
				} else if stuff[0] == '^' || stuff[0] == '[' {
					stuff = `\` + stuff
				}
				res.WriteString(pySetToGo(stuff))
			}
		default:
			res.WriteString(regexp.QuoteMeta(string(c)))
		}
		lastStar = false
	}
	res.WriteString(`)\z`)
	re, err := regexp.Compile(res.String())
	if err != nil {
		return nil, fmt.Errorf("%w: fnmatch pattern %q: %v", ErrUnsupported, pat, err)
	}
	return re, nil
}

// fnmatchSetStuff returns the Python regex set body fnmatch.translate builds
// for the set p[i:j] (the text between "[" and "]").
func fnmatchSetStuff(p []rune, i, j int) string {
	if !slices.Contains(p[i:j], '-') {
		return escapeSetOps(strings.ReplaceAll(string(p[i:j]), `\`, `\\`))
	}
	var chunks [][]rune
	k := i + 1
	if p[i] == '!' {
		k = i + 2
	}
	for {
		k = runeFind(p, '-', k, j)
		if k < 0 {
			break
		}
		chunks = append(chunks, slices.Clone(p[i:k]))
		i = k + 1
		k += 3
	}
	if chunk := p[i:j]; len(chunk) > 0 {
		chunks = append(chunks, slices.Clone(chunk))
	} else {
		chunks[len(chunks)-1] = append(chunks[len(chunks)-1], '-')
	}
	// Remove empty ranges -- invalid in RE.
	for k := len(chunks) - 1; k > 0; k-- {
		a, b := chunks[k-1], chunks[k]
		if len(a) == 0 || len(b) == 0 {
			continue
		}
		if a[len(a)-1] > b[0] {
			chunks[k-1] = append(slices.Clone(a[:len(a)-1]), b[1:]...)
			chunks = slices.Delete(chunks, k, k+1)
		}
	}
	parts := make([]string, len(chunks))
	for x, ch := range chunks {
		s := strings.ReplaceAll(string(ch), `\`, `\\`)
		parts[x] = strings.ReplaceAll(s, "-", `\-`)
	}
	return escapeSetOps(strings.Join(parts, "-"))
}

// escapeSetOps emulates re.sub(r'([&~|])', r'\\\1', stuff).
func escapeSetOps(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '&' || r == '~' || r == '|' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// runeFind emulates str.find(sub, start, end) for a single rune.
func runeFind(p []rune, c rune, start, end int) int {
	if end > len(p) {
		end = len(p)
	}
	for k := start; k < end; k++ {
		if p[k] == c {
			return k
		}
	}
	return -1
}

// pySetToGo converts the body of a Python regex character set as produced
// by fnmatch.translate (only literals, backslash escapes of literals, "-"
// ranges and a leading "^") into a Go character class.
func pySetToGo(stuff string) string {
	var b strings.Builder
	b.WriteByte('[')
	r := []rune(stuff)
	if len(r) > 0 && r[0] == '^' {
		b.WriteByte('^')
		r = r[1:]
	}
	for k := 0; k < len(r); k++ {
		switch {
		case r[k] == '\\' && k+1 < len(r):
			k++
			writeClassRune(&b, r[k])
		case r[k] == '-':
			b.WriteByte('-')
		default:
			writeClassRune(&b, r[k])
		}
	}
	b.WriteByte(']')
	return b.String()
}

func writeClassRune(b *strings.Builder, r rune) {
	fmt.Fprintf(b, `\x{%x}`, r)
}

// fnmatch is a convenience wrapper used by tests and ignore handling.
func fnmatch(name, pat string) (bool, error) {
	re, err := compileFnmatch(pat)
	if err != nil {
		return false, err
	}
	return re.MatchString(name), nil
}
