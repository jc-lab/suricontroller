package ruleset

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// ErrUnsupported is wrapped by errors for input that suricata-update
// accepts but that this package cannot reproduce faithfully (for example
// Python regular expression features that Go's regexp lacks). Such input is
// rejected instead of being processed with different results.
var ErrUnsupported = errors.New("ruleset: not supported by the Go port of suricata-update")

// errPyInvalid is wrapped by errors for regular expressions that Python's re
// module itself rejects.
var errPyInvalid = errors.New("invalid Python regular expression")

// Python re flags, as understood by compilePyRegex.
const (
	pyFlagI = 1 << iota // IGNORECASE
	pyFlagL             // LOCALE
	pyFlagM             // MULTILINE
	pyFlagS             // DOTALL
	pyFlagX             // VERBOSE
	pyFlagA             // ASCII
	pyFlagT             // TEMPLATE
	pyFlagU             // UNICODE

	pyTypeFlags   = pyFlagA | pyFlagL | pyFlagU
	pyGlobalFlags = pyFlagT
	pyMaxRepeat   = 4294967295
	pyMaxGroups   = 1073741823
	goMaxRepeat   = 1000
)

var pyInlineFlags = map[string]int{
	"i": pyFlagI, "L": pyFlagL, "m": pyFlagM, "s": pyFlagS,
	"x": pyFlagX, "a": pyFlagA, "t": pyFlagT, "u": pyFlagU,
}

// pyRegex is a Python regular expression translated to Go.
type pyRegex struct {
	src    string
	re     *regexp.Regexp
	groups int            // number of capturing groups (pattern.groups)
	names  map[string]int // pattern.groupindex
	// wordBoundary is set when the pattern uses \b or \B with Unicode
	// semantics, which Go only implements for ASCII.
	wordBoundary bool
	// nullable is set when the pattern may match the empty string.
	nullable bool
}

// compilePyRegex translates pattern, a Python 3.12 re pattern compiled with
// the given flags, into an equivalent Go regexp. Errors wrap errPyInvalid
// when Python would reject the pattern and ErrUnsupported when Python
// accepts it but it cannot be expressed in Go.
func compilePyRegex(pattern string, flags int) (rx *pyRegex, err error) {
	p := &pyParser{src: []rune(pattern), flags: flags, groups: 1, closed: []bool{true}, names: map[string]int{}}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(pyReError)
			if !ok {
				panic(r)
			}
			if pe.unsupported {
				err = fmt.Errorf("%w: regular expression %q: %s", ErrUnsupported, pattern, pe.msg)
			} else {
				err = fmt.Errorf("%w %q: %s", errPyInvalid, pattern, pe.msg)
			}
			rx = nil
		}
	}()
	p.advance()
	p.ascii = flags&pyFlagA != 0
	body := p.parseSub(flags&pyFlagX != 0, 0)
	if p.next != "" {
		p.fail("unbalanced parenthesis")
	}
	if p.flags&pyFlagA != 0 && p.flags&pyFlagU != 0 {
		p.fail("ASCII and UNICODE flags are incompatible")
	}
	if p.flags&pyFlagT != 0 {
		p.unsupported("TEMPLATE flag")
	}
	var goFlags string
	for _, f := range []struct {
		bit int
		c   string
	}{{pyFlagI, "i"}, {pyFlagM, "m"}, {pyFlagS, "s"}} {
		if p.flags&f.bit != 0 {
			goFlags += f.c
		}
	}
	goSrc := body
	if goFlags != "" {
		goSrc = "(?" + goFlags + ")" + body
	}
	re, cerr := regexp.Compile(goSrc)
	if cerr != nil {
		return nil, fmt.Errorf("%w: regular expression %q: %v", ErrUnsupported, pattern, cerr)
	}
	tree, cerr := syntax.Parse(goSrc, syntax.Perl)
	if cerr != nil {
		return nil, fmt.Errorf("%w: regular expression %q: %v", ErrUnsupported, pattern, cerr)
	}
	return &pyRegex{
		src:          pattern,
		re:           re,
		groups:       p.groups - 1,
		names:        p.names,
		wordBoundary: p.wordBoundary,
		nullable:     canMatchEmpty(tree),
	}, nil
}

func (rx *pyRegex) checkSubject(s string) error {
	if rx.wordBoundary && hasNonASCIIWord(s) {
		return fmt.Errorf("%w: regular expression %q uses \\b or \\B on text with non-ASCII word characters", ErrUnsupported, rx.src)
	}
	return nil
}

// search emulates bool(pattern.search(s)).
func (rx *pyRegex) search(s string) (bool, error) {
	if err := rx.checkSubject(s); err != nil {
		return false, err
	}
	return rx.re.MatchString(s), nil
}

// sub emulates pattern.sub(repl, s) for a parsed template. Patterns that can
// match the empty string are rejected at construction time by callers,
// because Go and Python differ in how they handle adjacent empty matches.
func (rx *pyRegex) sub(t *pyTemplate, s string) (string, error) {
	if rx.nullable {
		return "", fmt.Errorf("%w: substitution with regular expression %q that can match the empty string", ErrUnsupported, rx.src)
	}
	if err := rx.checkSubject(s); err != nil {
		return "", err
	}
	matches := rx.re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s, nil
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(s[last:m[0]])
		for _, part := range t.parts {
			if part.group < 0 {
				b.WriteString(part.lit)
			} else if lo, hi := m[2*part.group], m[2*part.group+1]; lo >= 0 {
				b.WriteString(s[lo:hi])
			}
		}
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

func canMatchEmpty(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return false
	case syntax.OpLiteral:
		return len(re.Rune) == 0
	case syntax.OpCapture, syntax.OpPlus:
		return canMatchEmpty(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min == 0 || canMatchEmpty(re.Sub[0])
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if !canMatchEmpty(s) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if canMatchEmpty(s) {
				return true
			}
		}
		return false
	}
	// Empty-width assertions, empty match, star and quest.
	return true
}

type pyReError struct {
	unsupported bool
	msg         string
}

// pyParser mirrors re._parser from Python 3.12 closely enough to accept and
// reject the same patterns, emitting Go syntax as it goes.
type pyParser struct {
	src   []rune
	index int
	next  string // lookahead token: one character or a backslash escape; "" at end

	flags        int // global flags (state.flags)
	ascii        bool
	groups       int    // state.groups (group 0 included)
	closed       []bool // closed[g] reports whether group g has been closed
	names        map[string]int
	wordBoundary bool
}

func (p *pyParser) fail(msg string)        { panic(pyReError{false, msg}) }
func (p *pyParser) unsupported(msg string) { panic(pyReError{true, msg}) }

func (p *pyParser) advance() {
	if p.index >= len(p.src) {
		p.next = ""
		return
	}
	if p.src[p.index] == '\\' {
		if p.index+1 >= len(p.src) {
			p.fail("bad escape (end of pattern)")
		}
		p.next = string(p.src[p.index : p.index+2])
		p.index += 2
		return
	}
	p.next = string(p.src[p.index])
	p.index++
}

func (p *pyParser) get() string {
	t := p.next
	p.advance()
	return t
}

func (p *pyParser) match(s string) bool {
	if p.next != "" && p.next == s {
		p.advance()
		return true
	}
	return false
}

func (p *pyParser) tell() int { return p.index - utf8.RuneCountInString(p.next) }

func (p *pyParser) seek(i int) {
	p.index = i
	p.advance()
}

func (p *pyParser) getwhile(n int, set string) string {
	var res string
	for range n {
		if len(p.next) != 1 || !strings.Contains(set, p.next) {
			break
		}
		res += p.get()
	}
	return res
}

func (p *pyParser) getuntil(term, name string) string {
	var res string
	for {
		c := p.get()
		if c == "" {
			if res == "" {
				p.fail("missing " + name)
			}
			p.fail("missing " + term + ", unterminated name")
		}
		if c == term {
			if res == "" {
				p.fail("missing " + name)
			}
			return res
		}
		res += c
	}
}

const (
	pyDigits    = "0123456789"
	pyOctDigits = "01234567"
	pyHexDigits = "0123456789abcdefABCDEF"
)

func isOneOf(tok, set string) bool { return len(tok) == 1 && strings.Contains(set, tok) }

func isASCIILetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

func isPyIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || isPyWord(r)) || (i == 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func isGoGroupName(s string) bool {
	for _, r := range s {
		if !(r == '_' || r >= '0' && r <= '9' || isASCIILetter(r)) {
			return false
		}
	}
	return s != ""
}

const (
	itemOther = iota
	itemAt
	itemRepeat
)

type reItem struct {
	s    string
	kind int
}

func goLiteral(r rune) string {
	if r < utf8.RuneSelf && (isASCIILetter(r) || r >= '0' && r <= '9') {
		return string(r)
	}
	return fmt.Sprintf(`\x{%x}`, r)
}

// parseSub ports _parse_sub: an alternation.
func (p *pyParser) parseSub(verbose bool, nested int) string {
	var branches []string
	for {
		branches = append(branches, p.parse(verbose, nested+1, nested == 0 && len(branches) == 0))
		if !p.match("|") {
			break
		}
		if nested == 0 {
			verbose = p.flags&pyFlagX != 0
		}
	}
	return strings.Join(branches, "|")
}

// parse ports _parse: a sequence of items.
func (p *pyParser) parse(verbose bool, nested int, first bool) string {
	var items []reItem
	for {
		this := p.next
		if this == "" || this == "|" || this == ")" {
			break
		}
		p.get()
		if verbose {
			if isOneOf(this, " \t\n\r\v\f") {
				continue
			}
			if this == "#" {
				for {
					t := p.get()
					if t == "" || t == "\n" {
						break
					}
				}
				continue
			}
		}
		if this[0] == '\\' {
			items = append(items, p.escape(this))
			continue
		}
		if !isOneOf(this, `.\[{()*+?^$|`) {
			items = append(items, reItem{goLiteral([]rune(this)[0]), itemOther})
			continue
		}
		switch this {
		case "[":
			items = append(items, reItem{p.parseClass(), itemOther})
		case "*", "+", "?", "{":
			var lo, hi int
			inf := false
			switch this {
			case "?":
				lo, hi = 0, 1
			case "*":
				inf = true
			case "+":
				lo, inf = 1, true
			case "{":
				if p.next == "}" {
					items = append(items, reItem{goLiteral('{'), itemOther})
					continue
				}
				here := p.tell()
				var los, his string
				for isOneOf(p.next, pyDigits) {
					los += p.get()
				}
				if p.match(",") {
					for isOneOf(p.next, pyDigits) {
						his += p.get()
					}
				} else {
					his = los
				}
				if !p.match("}") {
					items = append(items, reItem{goLiteral('{'), itemOther})
					p.seek(here)
					continue
				}
				inf = true
				if los != "" {
					lo = p.repeatCount(los)
				}
				if his != "" {
					hi = p.repeatCount(his)
					inf = false
					if hi < lo {
						p.fail("min repeat greater than max repeat")
					}
				}
			}
			if len(items) == 0 || items[len(items)-1].kind == itemAt {
				p.fail("nothing to repeat")
			}
			if items[len(items)-1].kind == itemRepeat {
				p.fail("multiple repeat")
			}
			var q string
			switch {
			case inf && lo == 0:
				q = "*"
			case inf && lo == 1:
				q = "+"
			case inf:
				q = fmt.Sprintf("{%d,}", lo)
			case lo == 0 && hi == 1:
				q = "?"
			case lo == hi:
				q = fmt.Sprintf("{%d}", lo)
			default:
				q = fmt.Sprintf("{%d,%d}", lo, hi)
			}
			if p.match("?") {
				q += "?"
			} else if p.match("+") {
				p.unsupported("possessive quantifier")
			}
			if lo > goMaxRepeat || (!inf && hi > goMaxRepeat) {
				p.unsupported("repeat count above 1000")
			}
			last := &items[len(items)-1]
			*last = reItem{"(?:" + last.s + ")" + q, itemRepeat}
		case ".":
			items = append(items, reItem{".", itemOther})
		case "(":
			it, ok := p.parseGroup(&verbose, nested, first && len(items) == 0)
			if ok {
				items = append(items, it)
			}
		case "^":
			items = append(items, reItem{"^", itemAt})
		case "$":
			// Python's non-multiline $ also matches before a trailing
			// newline; rule texts never end with one, so Go's $ is
			// equivalent here.
			items = append(items, reItem{"$", itemAt})
		}
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.s)
	}
	return b.String()
}

func (p *pyParser) repeatCount(s string) int {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v >= pyMaxRepeat {
		p.fail("the repetition number is too large")
	}
	return int(v)
}

// parseGroup handles everything after "(". ok is false when the construct
// produced no item (comments and global flags).
func (p *pyParser) parseGroup(verbose *bool, nested int, atStart bool) (reItem, bool) {
	capture := true
	name := ""
	addFlags, delFlags := 0, 0
	if p.match("?") {
		char := p.get()
		if char == "" {
			p.fail("unexpected end of pattern")
		}
		switch {
		case char == "P":
			if p.match("<") {
				name = p.getuntil(">", "group name")
				if !isPyIdentifier(name) {
					p.fail("bad character in group name")
				}
				if !isGoGroupName(name) {
					p.unsupported("non-ASCII group name")
				}
			} else if p.match("=") {
				name = p.getuntil(")", "group name")
				if !isPyIdentifier(name) {
					p.fail("bad character in group name")
				}
				gid, ok := p.names[name]
				if !ok {
					p.fail("unknown group name")
				}
				if !p.closed[gid] {
					p.fail("cannot refer to an open group")
				}
				p.unsupported("backreference")
			} else {
				c := p.get()
				if c == "" {
					p.fail("unexpected end of pattern")
				}
				p.fail("unknown extension ?P" + c)
			}
		case char == ":":
			capture = false
		case char == "#":
			for {
				if p.next == "" {
					p.fail("missing ), unterminated comment")
				}
				if p.get() == ")" {
					return reItem{}, false
				}
			}
		case isOneOf(char, "=!<"):
			if char == "<" {
				c := p.get()
				if c == "" {
					p.fail("unexpected end of pattern")
				}
				if !isOneOf(c, "=!") {
					p.fail("unknown extension ?<" + c)
				}
			}
			p.unsupported("lookahead/lookbehind assertion")
		case char == "(":
			p.unsupported("conditional group")
		case char == ">":
			p.unsupported("atomic group")
		case char == "-" || pyInlineFlags[char] != 0:
			var global bool
			addFlags, delFlags, global = p.parseFlags(char)
			if global {
				if !atStart {
					p.fail("global flags not at the start of the expression")
				}
				if addFlags&pyFlagA != 0 {
					p.ascii = true
				}
				*verbose = p.flags&pyFlagX != 0
				return reItem{}, false
			}
			capture = false
		default:
			p.fail("unknown extension ?" + char)
		}
	}
	gid := -1
	if capture {
		gid = p.groups
		p.groups++
		p.closed = append(p.closed, false)
		if p.groups > pyMaxGroups {
			p.fail("too many groups")
		}
		if name != "" {
			if _, dup := p.names[name]; dup {
				p.fail("redefinition of group name")
			}
			p.names[name] = gid
		}
	}
	subVerbose := (*verbose || addFlags&pyFlagX != 0) && delFlags&pyFlagX == 0
	savedASCII := p.ascii
	if addFlags&pyFlagU != 0 && p.ascii {
		p.unsupported("(?u:...) inside an ASCII pattern")
	}
	if addFlags&pyFlagA != 0 {
		p.ascii = true
	}
	body := p.parseSub(subVerbose, nested+1)
	p.ascii = savedASCII
	if !p.match(")") {
		p.fail("missing ), unterminated subpattern")
	}
	switch {
	case gid >= 0:
		p.closed[gid] = true
		if name != "" {
			return reItem{"(?P<" + name + ">" + body + ")", itemOther}, true
		}
		return reItem{"(" + body + ")", itemOther}, true
	default:
		var on, off string
		for _, f := range []struct {
			bit int
			c   string
		}{{pyFlagI, "i"}, {pyFlagM, "m"}, {pyFlagS, "s"}} {
			if addFlags&f.bit != 0 {
				on += f.c
			}
			if delFlags&f.bit != 0 {
				off += f.c
			}
		}
		if off != "" {
			on += "-" + off
		}
		return reItem{"(?" + on + ":" + body + ")", itemOther}, true
	}
}

// parseFlags ports _parse_flags. global reports a "(?flags)" group.
func (p *pyParser) parseFlags(char string) (add, del int, global bool) {
	if char != "-" {
		for {
			flag := pyInlineFlags[char]
			if char == "L" {
				p.fail("bad inline flags: cannot use 'L' flag with a str pattern")
			}
			add |= flag
			if flag&pyTypeFlags != 0 && add&pyTypeFlags != flag {
				p.fail("bad inline flags: flags 'a', 'u' and 'L' are incompatible")
			}
			char = p.get()
			if char == "" {
				p.fail("missing -, : or )")
			}
			if isOneOf(char, ")-:") {
				break
			}
			if pyInlineFlags[char] == 0 {
				p.fail("unknown flag")
			}
		}
	}
	if char == ")" {
		p.flags |= add
		return add, 0, true
	}
	if add&pyGlobalFlags != 0 {
		p.fail("bad inline flags: cannot turn on global flag")
	}
	if char == "-" {
		char = p.get()
		if char == "" {
			p.fail("missing flag")
		}
		if pyInlineFlags[char] == 0 {
			p.fail("unknown flag")
		}
		for {
			flag := pyInlineFlags[char]
			if flag&pyTypeFlags != 0 {
				p.fail("bad inline flags: cannot turn off flags 'a', 'u' and 'L'")
			}
			del |= flag
			char = p.get()
			if char == "" {
				p.fail("missing :")
			}
			if char == ":" {
				break
			}
			if pyInlineFlags[char] == 0 {
				p.fail("unknown flag")
			}
		}
	}
	if del&pyGlobalFlags != 0 {
		p.fail("bad inline flags: cannot turn off global flag")
	}
	if add&del != 0 {
		p.fail("bad inline flags: flag turned on and off")
	}
	return add, del, false
}

// escape ports _escape (escapes outside character classes).
func (p *pyParser) escape(tok string) reItem {
	c := []rune(tok)[1]
	switch c {
	case 'A':
		return reItem{`\A`, itemAt}
	case 'Z':
		return reItem{`\z`, itemAt}
	case 'b', 'B':
		if !p.ascii {
			p.wordBoundary = true
		}
		return reItem{`\` + string(c), itemAt}
	case 'd', 'D', 's', 'S', 'w', 'W':
		return reItem{"[" + categoryClass(c, p.ascii) + "]", itemOther}
	}
	if r, ok := p.commonEscape(c); ok {
		return reItem{goLiteral(r), itemOther}
	}
	switch {
	case c == '0':
		v, _ := strconv.ParseUint("0"+p.getwhile(2, pyOctDigits), 8, 32)
		return reItem{goLiteral(rune(v)), itemOther}
	case c >= '1' && c <= '9':
		esc := string(c)
		if isOneOf(p.next, pyDigits) {
			esc += p.get()
			if isOneOf(esc[:1], pyOctDigits) && isOneOf(esc[1:], pyOctDigits) && isOneOf(p.next, pyOctDigits) {
				esc += p.get()
				v, _ := strconv.ParseUint(esc, 8, 32)
				if v > 0o377 {
					p.fail("octal escape value outside of range 0-0o377")
				}
				return reItem{goLiteral(rune(v)), itemOther}
			}
		}
		g, _ := strconv.Atoi(esc)
		if g < p.groups {
			if !p.closed[g] {
				p.fail("cannot refer to an open group")
			}
			p.unsupported("backreference")
		}
		p.fail("invalid group reference")
	}
	if isASCIILetter(c) {
		p.fail("bad escape " + tok)
	}
	return reItem{goLiteral(c), itemOther}
}

// commonEscape handles the escapes shared by _escape and _class_escape
// that denote a single character (except \b and octal escapes, which
// differ between the two contexts).
func (p *pyParser) commonEscape(c rune) (rune, bool) {
	switch c {
	case 'a':
		return 7, true
	case 'f':
		return '\f', true
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'v':
		return '\v', true
	case '\\':
		return '\\', true
	case 'x', 'u', 'U':
		n := map[rune]int{'x': 2, 'u': 4, 'U': 8}[c]
		hex := p.getwhile(n, pyHexDigits)
		if len(hex) != n {
			p.fail("incomplete escape \\" + string(c) + hex)
		}
		v, _ := strconv.ParseUint(hex, 16, 32)
		if v > utf8.MaxRune {
			p.fail("bad escape \\" + string(c) + hex)
		}
		if v >= 0xd800 && v <= 0xdfff {
			p.unsupported("surrogate code point")
		}
		return rune(v), true
	case 'N':
		p.unsupported(`\N{...} named character escape`)
	}
	return 0, false
}

type classItem struct {
	kind   int // 0 literal, 1 range, 2 category
	lo, hi rune
	cat    rune
	ascii  bool
}

// parseClass ports the "[" branch of _parse and returns a Go class.
func (p *pyParser) parseClass() string {
	var set []classItem
	negate := p.match("^")
	for {
		this := p.get()
		if this == "" {
			p.fail("unterminated character set")
		}
		if this == "]" && len(set) > 0 {
			break
		}
		var code1 classItem
		if this[0] == '\\' {
			code1 = p.classEscape(this)
		} else {
			code1 = classItem{kind: 0, lo: []rune(this)[0]}
		}
		if p.match("-") {
			that := p.get()
			if that == "" {
				p.fail("unterminated character set")
			}
			if that == "]" {
				set = append(set, code1, classItem{kind: 0, lo: '-'})
				break
			}
			var code2 classItem
			if that[0] == '\\' {
				code2 = p.classEscape(that)
			} else {
				code2 = classItem{kind: 0, lo: []rune(that)[0]}
			}
			if code1.kind != 0 || code2.kind != 0 {
				p.fail("bad character range " + this + "-" + that)
			}
			if code2.lo < code1.lo {
				p.fail("bad character range " + this + "-" + that)
			}
			set = append(set, classItem{kind: 1, lo: code1.lo, hi: code2.lo})
		} else {
			set = append(set, code1)
		}
	}
	var b strings.Builder
	b.WriteByte('[')
	if negate {
		b.WriteByte('^')
	}
	for _, it := range set {
		switch it.kind {
		case 0:
			fmt.Fprintf(&b, `\x{%x}`, it.lo)
		case 1:
			fmt.Fprintf(&b, `\x{%x}-\x{%x}`, it.lo, it.hi)
		case 2:
			b.WriteString(categoryClass(it.cat, it.ascii))
		}
	}
	b.WriteByte(']')
	return b.String()
}

// classEscape ports _class_escape.
func (p *pyParser) classEscape(tok string) classItem {
	c := []rune(tok)[1]
	switch c {
	case 'b':
		return classItem{kind: 0, lo: '\b'}
	case 'd', 'D', 's', 'S', 'w', 'W':
		return classItem{kind: 2, cat: c, ascii: p.ascii}
	}
	if r, ok := p.commonEscape(c); ok {
		return classItem{kind: 0, lo: r}
	}
	switch {
	case c >= '0' && c <= '7':
		esc := string(c) + p.getwhile(2, pyOctDigits)
		v, _ := strconv.ParseUint(esc, 8, 32)
		if v > 0o377 {
			p.fail("octal escape value outside of range 0-0o377")
		}
		return classItem{kind: 0, lo: rune(v)}
	case c == '8' || c == '9' || isASCIILetter(c):
		p.fail("bad escape " + tok)
	}
	return classItem{kind: 0, lo: c}
}

type runeRange struct{ lo, hi rune }

var (
	categoryOnce   sync.Once
	categoryRanges map[string]string
)

// categoryClass returns the body of a Go character class equivalent to the
// Python category escape c (one of dDsSwW) in Unicode or ASCII mode.
func categoryClass(c rune, ascii bool) string {
	categoryOnce.Do(initCategories)
	key := string(c)
	if ascii {
		key = "a" + key
	}
	return categoryRanges[key]
}

func initCategories() {
	render := func(rs []runeRange) string {
		var b strings.Builder
		for _, r := range rs {
			if r.lo == r.hi {
				fmt.Fprintf(&b, `\x{%x}`, r.lo)
			} else {
				fmt.Fprintf(&b, `\x{%x}-\x{%x}`, r.lo, r.hi)
			}
		}
		return b.String()
	}
	ranges := func(pred func(rune) bool) (in, out []runeRange) {
		start, startOut := rune(-1), rune(-1)
		for r := rune(0); r <= utf8.MaxRune+1; r++ {
			ok := r <= utf8.MaxRune && pred(r)
			end := r > utf8.MaxRune
			if ok && start < 0 {
				start = r
			}
			if (!ok || end) && start >= 0 {
				in = append(in, runeRange{start, r - 1})
				start = -1
			}
			if !ok && !end && startOut < 0 {
				startOut = r
			}
			if (ok || end) && startOut >= 0 {
				out = append(out, runeRange{startOut, r - 1})
				startOut = -1
			}
		}
		return in, out
	}
	isASCIIDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	isASCIIWord := func(r rune) bool { return r == '_' || isASCIIDigit(r) || isASCIILetter(r) }
	isASCIISpace := func(r rune) bool { return r == ' ' || r >= '\t' && r <= '\r' }

	categoryRanges = map[string]string{
		"d": `\p{Nd}`,
		"D": `\P{Nd}`,
		"w": `\p{L}\p{N}_`,
	}
	_, nonWord := ranges(isPyWord)
	categoryRanges["W"] = render(nonWord)
	sp, nonSp := ranges(isPySpace)
	categoryRanges["s"], categoryRanges["S"] = render(sp), render(nonSp)
	for k, pred := range map[string]func(rune) bool{"d": isASCIIDigit, "w": isASCIIWord, "s": isASCIISpace} {
		in, out := ranges(pred)
		categoryRanges["a"+k] = render(in)
		categoryRanges["a"+strings.ToUpper(k)] = render(out)
	}
}

// pyTemplate is a parsed Python re replacement template.
type pyTemplate struct {
	parts []tmplPart
}

type tmplPart struct {
	lit   string
	group int // -1 for literal parts
}

// parsePyTemplate ports re._parser.parse_template for a str template.
func parsePyTemplate(repl string, rx *pyRegex) (t *pyTemplate, err error) {
	p := &pyParser{src: []rune(repl)}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(pyReError)
			if !ok {
				panic(r)
			}
			if pe.unsupported {
				err = fmt.Errorf("%w: replacement %q: %s", ErrUnsupported, repl, pe.msg)
			} else {
				err = fmt.Errorf("%w: invalid replacement %q: %s", errPyInvalid, repl, pe.msg)
			}
			t = nil
		}
	}()
	t = &pyTemplate{}
	var lit strings.Builder
	addGroup := func(g int) {
		if g > rx.groups {
			p.fail(fmt.Sprintf("invalid group reference %d", g))
		}
		if lit.Len() > 0 {
			t.parts = append(t.parts, tmplPart{lit: lit.String(), group: -1})
			lit.Reset()
		}
		t.parts = append(t.parts, tmplPart{group: g})
	}
	p.advance()
	for {
		this := p.get()
		if this == "" {
			break
		}
		if this[0] != '\\' {
			lit.WriteString(this)
			continue
		}
		c := []rune(this)[1]
		switch {
		case c == 'g':
			if !p.match("<") {
				p.fail("missing <")
			}
			name := p.getuntil(">", "group name")
			if strings.Trim(name, pyDigits) == "" {
				g, err := strconv.Atoi(name)
				if err != nil || g >= pyMaxGroups {
					p.fail("invalid group reference " + name)
				}
				addGroup(g)
			} else {
				if !isPyIdentifier(name) {
					p.fail("bad character in group name " + name)
				}
				g, ok := rx.names[name]
				if !ok {
					p.fail("unknown group name " + name)
				}
				addGroup(g)
			}
		case c == '0':
			esc := "0"
			if isOneOf(p.next, pyOctDigits) {
				esc += p.get()
				if isOneOf(p.next, pyOctDigits) {
					esc += p.get()
				}
			}
			v, _ := strconv.ParseUint(esc, 8, 32)
			lit.WriteRune(rune(v & 0xff))
		case c >= '1' && c <= '9':
			esc := string(c)
			isOctal := false
			if isOneOf(p.next, pyDigits) {
				esc += p.get()
				if isOneOf(esc[:1], pyOctDigits) && isOneOf(esc[1:], pyOctDigits) && isOneOf(p.next, pyOctDigits) {
					esc += p.get()
					isOctal = true
					v, _ := strconv.ParseUint(esc, 8, 32)
					if v > 0o377 {
						p.fail("octal escape value outside of range 0-0o377")
					}
					lit.WriteRune(rune(v))
				}
			}
			if !isOctal {
				g, _ := strconv.Atoi(esc)
				addGroup(g)
			}
		default:
			switch c {
			case 'a':
				lit.WriteByte(7)
			case 'b':
				lit.WriteByte('\b')
			case 'f':
				lit.WriteByte('\f')
			case 'n':
				lit.WriteByte('\n')
			case 'r':
				lit.WriteByte('\r')
			case 't':
				lit.WriteByte('\t')
			case 'v':
				lit.WriteByte('\v')
			case '\\':
				lit.WriteByte('\\')
			default:
				if isASCIILetter(c) {
					p.fail("bad escape " + this)
				}
				// Unknown escapes of non-letters are kept verbatim,
				// backslash included.
				lit.WriteString(this)
			}
		}
	}
	if lit.Len() > 0 {
		t.parts = append(t.parts, tmplPart{lit: lit.String(), group: -1})
	}
	return t, nil
}
