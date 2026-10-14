// Initial content of files created in the UI. They must pass the
// controller's validation (checked by the smoke test).

/** Templates for new files in common/ and nodes/<id>/ of the config repository. */
export const CONFIG_TEMPLATES: Record<string, string> = {
  "suricata.yaml": `%YAML 1.1
---
# Controller-managed overlay, deep-merged into the node's suricata.yaml
# (maps are merged recursively, lists are replaced; node files win over common).
`,
  "sources.yaml": `# Rule sources used for the bundle. Empty providers = all enabled providers.
providers: []
# exclude:
#   - et-open/emerging-games.rules
`,
  "disable.conf": `# Rules to disable, one matcher per line:
#   1:2019401 | 2019401 | re:<regex> | group:<file glob> | metadata: <key> <value>
`,
  "enable.conf": `# Rules to enable, one matcher per line (same syntax as disable.conf).
`,
  "drop.conf": `# Rules to convert to "drop", one matcher per line (same syntax as disable.conf).
`,
  "modify.conf": `# Rule modifications: <matcher> "<from regex>" "<to>"
# Example: 2019401 "alert" "drop"
`,
  "threshold.config": `# threshold.config entries, for example:
# suppress gen_id 1, sig_id 2010935, track by_src, ip 10.0.0.1
`,
};

/** Template for a new local .rules file. */
export const NEW_RULES_TEMPLATE = `# Local Suricata rules: one rule per line, each with a unique sid
# (for example in the 1000000-1999999 range).
# Lines starting with "#" are comments; a commented-out rule counts as a disabled rule.
`;
