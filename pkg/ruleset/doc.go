// Package ruleset is a Go port of the rule processing of suricata-update
// (OISF, version 1.3.0), used to render a final suricata.rules from raw
// provider rule files and disable.conf, enable.conf, drop.conf and
// modify.conf, identically to suricata-update.
//
// Typical use:
//
//	rules, deps, err := ruleset.ParseFiles(files, ruleset.LoadOptions{Ignore: ruleset.DefaultIgnore})
//	out, stats, err := ruleset.Process(rules, ruleset.Config{
//		Disable: disable, Enable: enable, Drop: drop, Modify: modify,
//		ResolveFlowbits: true, DepFiles: deps,
//	})
//	err = ruleset.Write(w, out)               // suricata.rules
//	datasets := ruleset.DatasetFiles(out)     // "datasets/<md5>" files to ship alongside
//
// The port follows suricata-update's quirks on purpose: rule parsing
// (accepted actions, find_opt_end, multi-line rules), duplicate gid:sid
// handling, the matcher syntax and precedence, Python fnmatch, shlex and re
// semantics (patterns are translated to Go regexp syntax), the loss of the
// group when a drop filter re-parses a rule, noalert insertion, flowbits
// resolution and dataset "load" rewriting. Golden tests compare the output
// byte for byte with suricata-update (see testdata/gen-golden.sh).
//
// Deliberate differences:
//   - By default Process rejects conf lines that suricata-update would only
//     warn about; set Config.IgnoreInvalid for suricata-update's behaviour.
//     ValidateConfig performs the same strict checks without rules.
//   - Input suricata-update accepts but this package cannot reproduce is
//     rejected with an error wrapping ErrUnsupported: Python regex features
//     missing from Go (look-around, backreferences, conditionals, atomic
//     groups, possessive quantifiers, \N{...}, repeats above 1000, non-ASCII
//     group names), modify patterns that can match the empty string, and
//     \b or \B applied to text containing non-ASCII word characters.
//   - Conditions that crash suricata-update (for example a valueless
//     flowbits option, or a dropped rule with a dataset load) are errors.
//   - gid, sid and rev must fit in uint32; such rules are rejected by Parse
//     while suricata-update would keep them.
//   - Features that need a Suricata binary or suricata.yaml (disabling rules
//     of disabled app-layer protocols or unknown variables, ja3 handling,
//     classification.config merging, rule tests) are not implemented.
package ruleset
