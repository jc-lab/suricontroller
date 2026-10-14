package ruleset

import "errors"

// shlexSplit emulates Python's shlex.split(s) (POSIX mode, no comments),
// which suricata-update uses to tokenize modify.conf lines:
//   - whitespace (space, tab, CR, LF) separates tokens;
//   - inside '...' nothing is special;
//   - inside "..." a backslash only escapes '"' and '\' (otherwise it is kept);
//   - outside quotes a backslash escapes any character;
//   - adjacent quoted and unquoted parts form one token, and "" yields an
//     empty token.
func shlexSplit(s string) ([]string, error) {
	l := shlexer{in: []rune(s), state: ' '}
	var tokens []string
	for {
		tok, ok, err := l.readToken()
		if err != nil {
			return nil, err
		}
		if !ok {
			return tokens, nil
		}
		tokens = append(tokens, tok)
	}
}

const shlexEOF = -1

type shlexer struct {
	in    []rune
	pos   int
	state rune // ' ', 'a', '\'', '"', '\\' or shlexEOF
}

func shlexSpace(c rune) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// readToken ports shlex.read_token for the configuration used by split.
func (l *shlexer) readToken() (string, bool, error) {
	quoted := false
	escapedState := ' '
	var token []rune
	for {
		var c rune
		have := l.pos < len(l.in)
		if have {
			c = l.in[l.pos]
			l.pos++
		}
		switch l.state {
		case shlexEOF:
			token = nil
			goto done
		case ' ':
			switch {
			case !have:
				l.state = shlexEOF
				goto done
			case shlexSpace(c):
				if len(token) > 0 || quoted {
					goto done
				}
			case c == '\\':
				escapedState = 'a'
				l.state = '\\'
			case c == '\'' || c == '"':
				l.state = c
			default:
				token = []rune{c}
				l.state = 'a'
			}
		case '\'', '"':
			quoted = true
			switch {
			case !have:
				return "", false, errors.New("no closing quotation")
			case c == l.state:
				l.state = 'a'
			case c == '\\' && l.state == '"':
				escapedState = l.state
				l.state = '\\'
			default:
				token = append(token, c)
			}
		case '\\':
			if !have {
				return "", false, errors.New("no escaped character")
			}
			// In POSIX shells only the quote itself or the escape character
			// may be escaped within quotes.
			if (escapedState == '\'' || escapedState == '"') && c != '\\' && c != escapedState {
				token = append(token, '\\')
			}
			token = append(token, c)
			l.state = escapedState
		case 'a':
			switch {
			case !have:
				l.state = shlexEOF
				goto done
			case shlexSpace(c):
				l.state = ' '
				if len(token) > 0 || quoted {
					goto done
				}
			case c == '\'' || c == '"':
				l.state = c
			case c == '\\':
				escapedState = 'a'
				l.state = '\\'
			default:
				token = append(token, c)
			}
		}
	}
done:
	if !quoted && len(token) == 0 {
		return "", false, nil
	}
	return string(token), true, nil
}
