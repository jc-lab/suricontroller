package overlay

import (
	"strings"
	"testing"

	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

func TestCheck(t *testing.T) {
	ok, _ := yamlmerge.Parse([]byte("vars:\n  address-groups:\n    HOME_NET: '[10.0.0.0/8]'\ndetect:\n  profile: high\n"))
	if err := Check(ok); err != nil {
		t.Fatalf("valid overlay rejected: %v", err)
	}
	bad, _ := yamlmerge.Parse([]byte("outputs: []\nplugins: [/tmp/x.so]\nvars: {}\n"))
	err := Check(bad)
	if err == nil || !strings.Contains(err.Error(), "outputs") || !strings.Contains(err.Error(), "plugins") {
		t.Fatalf("err = %v", err)
	}
	inc, _ := yamlmerge.Parse([]byte("vars: !include /etc/passwd\n"))
	if err := Check(inc); err == nil {
		t.Fatal("!include accepted")
	}
	// Suricata expands dotted keys and maps "_" to "-": all of these would
	// set forbidden settings.
	for _, doc := range []string{
		"plugins.0: /tmp/x.so\n",
		"security.lua.allow-rules: yes\n",
		"security:\n  lua.allow-rules: yes\n",
		"detect:\n  profile: high\nunix-command.filename: /tmp/s\n",
		"default_log_dir: /tmp\n",
		"run_as:\n  user: root\n",
		"vars: &a\n  x: 1\ndetect: *a\n",
	} {
		n, err := yamlmerge.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if err := Check(n); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}
