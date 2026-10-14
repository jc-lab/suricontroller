package ruleset

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file holds small re-implementations of Python str/os.path behaviour
// that suricata-update relies on and whose Go counterparts differ subtly.

// isPySpace reports whether r is whitespace for Python's str.isspace, which
// is what str.strip(), str.split() and the re module's \s use.
func isPySpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f, ' ',
		0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// isPyWord reports whether r matches Python's Unicode \w.
func isPyWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

func pyStrip(s string) string  { return strings.TrimFunc(s, isPySpace) }
func pyRStrip(s string) string { return strings.TrimRightFunc(s, isPySpace) }
func pyLStrip(s string) string { return strings.TrimLeftFunc(s, isPySpace) }

func pyStripRunes(r []rune) []rune {
	for len(r) > 0 && isPySpace(r[0]) {
		r = r[1:]
	}
	for len(r) > 0 && isPySpace(r[len(r)-1]) {
		r = r[:len(r)-1]
	}
	return r
}

// pySplitMax1 emulates s.split(maxsplit=1): it returns the first
// whitespace-delimited word and the (left-stripped) remainder.
func pySplitMax1(s string) (first, rest string, ok bool) {
	s = pyLStrip(s)
	i := strings.IndexFunc(s, isPySpace)
	if i < 0 {
		return s, "", false
	}
	rest = pyLStrip(s[i:])
	if rest == "" {
		return s[:i], "", false
	}
	return s[:i], rest, true
}

// pyLower emulates str.lower() (full Unicode lower-casing). Only U+0130 has
// an unconditional multi-rune lower-case mapping; final-sigma context rules
// are not applied.
func pyLower(s string) string {
	if !strings.ContainsRune(s, 0x130) {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r == 0x130 {
			b.WriteString("i̇")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// pyDecimalValue returns the value of a Unicode decimal digit (category Nd).
// Unicode guarantees decimal digits come in contiguous runs of ten, 0..9.
func pyDecimalValue(r rune) int {
	start := r
	for start > 0 && unicode.Is(unicode.Nd, start-1) {
		start--
	}
	return int(r-start) % 10
}

// pyInt emulates Python's int(s) for base 10: surrounding whitespace, an
// optional sign, Unicode decimal digits and single underscores between
// digits are accepted. overflow is set when the value does not fit in int64
// (Python would still accept it).
func pyInt(s string) (v int64, ok, overflow bool) {
	s = pyStrip(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return 0, false, false
	}
	prevDigit := false
	var acc uint64
	for i, r := range s {
		if r == '_' {
			if !prevDigit || i+1 >= len(s) {
				return 0, false, false
			}
			prevDigit = false
			continue
		}
		if !unicode.Is(unicode.Nd, r) {
			return 0, false, false
		}
		prevDigit = true
		if !overflow {
			d := uint64(pyDecimalValue(r))
			if acc > (1<<63)/10 || acc*10+d > 1<<63 {
				overflow = true
			} else {
				acc = acc*10 + d
			}
		}
	}
	if !prevDigit {
		return 0, false, false
	}
	if overflow || (!neg && acc > 1<<63-1) {
		return 0, true, true
	}
	if neg {
		return -int64(acc), true, false
	}
	return int64(acc), true, false
}

// pyBasename emulates os.path.basename (posixpath).
func pyBasename(p string) string {
	return p[strings.LastIndexByte(p, '/')+1:]
}

// pyDirname emulates os.path.dirname (posixpath).
func pyDirname(p string) string {
	head := p[:strings.LastIndexByte(p, '/')+1]
	if head != "" && strings.Trim(head, "/") != "" {
		head = strings.TrimRight(head, "/")
	}
	return head
}

// pySplitextRoot returns the root part of os.path.splitext (posixpath).
func pySplitextRoot(p string) string {
	sep := strings.LastIndexByte(p, '/')
	dot := strings.LastIndexByte(p, '.')
	if dot > sep {
		for i := sep + 1; i < dot; i++ {
			if p[i] != '.' {
				return p[:dot]
			}
		}
	}
	return p
}

// hasNonASCIIWord reports whether s contains a non-ASCII rune that Python
// considers a word character.
func hasNonASCIIWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			for _, r := range s[i:] {
				if r >= utf8.RuneSelf && isPyWord(r) {
					return true
				}
			}
			return false
		}
	}
	return false
}
