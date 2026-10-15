package rules

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/store"
	"github.com/jc-lab/suricontroller/controller/store/sqlite"
)

const testOinkcode = "0123456789abcdef0123456789abcdef01234567"

// fakeSnortOrg serves snort.org's download endpoints: an oinkcode is
// required for /rules/ and errors are JSON string arrays with status 422.
type fakeSnortOrg struct {
	archives  map[string][]byte // path -> archive
	downloads atomic.Int32
}

func (f *fakeSnortOrg) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/rules/") {
		switch oc := r.URL.Query().Get("oinkcode"); {
		case oc == "":
			w.WriteHeader(422)
			w.Write([]byte(`["oinkcode required"]`))
			return
		case oc != testOinkcode:
			w.WriteHeader(422)
			w.Write([]byte(`["Invalid oinkcode"]`))
			return
		}
	}
	data, ok := f.archives[strings.TrimSuffix(p, ".md5")]
	if !ok {
		w.WriteHeader(422)
		w.Write([]byte(`["File not found by name"]`))
		return
	}
	if strings.HasSuffix(p, ".md5") {
		sum := md5.Sum(data)
		w.Write([]byte(hex.EncodeToString(sum[:])))
		return
	}
	f.downloads.Add(1)
	w.Write(data)
}

const (
	webappRule  = `alert http $EXTERNAL_NET any -> $HOME_NET any ( msg:"SERVER-WEBAPP NGINX rewrite module remote code execution attempt"; flow:to_server,established; http_client_body; content:"|70 AD 80 F7 FF 7F 00 00|",depth 8,fast_pattern; metadata:policy balanced-ips drop,policy max-detect-ips drop; reference:cve,2026-42945; classtype:attempted-user; gid:1; sid:66501; rev:1; )`
	maxRule     = `alert tcp $EXTERNAL_NET any -> $SIP_SERVERS $SIP_PORTS ( msg:"OS-OTHER only in max-detect"; flow:to_server,established; content:"() {"; metadata:policy max-detect-ips drop; classtype:attempted-admin; sid:32042; rev:4; )`
	berRule     = `alert ssl ( msg:"SERVER-OTHER ber"; flow:established; content:"|06 03|"; ber_data:0x04; metadata:policy balanced-ips drop; classtype:attempted-use; sid:300306; rev:1; )`
	setterRule  = `alert tcp $EXTERNAL_NET any -> $HOME_NET any ( msg:"FILE-IDENTIFY setter"; flow:to_client,established; file_data; content:"|CE FA ED FE|",depth 4; flowbits:set,file.machole; flowbits:noalert; metadata:policy max-detect-ips alert; classtype:misc-activity; sid:15001; rev:1; )`
	checkerRule = `alert tcp $EXTERNAL_NET any -> $HOME_NET any ( msg:"FILE-EXECUTABLE checker"; flow:to_client,established; flowbits:isset,file.elf|file.machole; file_data; content:"x"; metadata:policy balanced-ips drop; classtype:attempted-user; sid:15002; rev:1; )`
	modbusRule  = `alert tcp $EXTERNAL_NET any -> $HOME_NET 502 ( msg:"PROTOCOL-SCADA modbus"; flow:to_server,established; modbus_func:write_file_record; metadata:policy balanced-ips drop; classtype:attempted-admin; sid:50000; rev:1; )`
)

func snortService(t *testing.T, base string) (*Service, *gitrepo.Repo, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	repo, err := gitrepo.Open(filepath.Join(dir, "rules.git"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Store: st, Repo: repo})
	s.types[TypeSnort].Fetcher.(*Snort).BaseURL = base
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, repo, st
}

func TestSnortRegisteredSync(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSnortOrg{archives: map[string][]byte{
		"/rules/snortrules-snapshot-3900.tar.gz": tarGz(t, map[string]string{
			"rules/snort3-server-webapp.rules":  "# header comment\n" + webappRule + "\n" + maxRule + "\n" + berRule + "\n",
			"rules/snort3-protocol-scada.rules": modbusRule + "\n",
			"rules/snort3-file-identify.rules":  setterRule + "\n" + checkerRule + "\n",
			"rules/includes.rules":              "include $RULE_PATH/snort3-server-webapp.rules\n",
			"so_rules/os-windows.rules":         `alert tcp any any -> any any ( msg:"so stub"; soid:1; gid:3; sid:1; rev:1; )` + "\n",
			"builtins/builtins.rules":           `alert ( gid:116; sid:1; rev:1; msg:"decoder"; )` + "\n",
		}),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s, repo, st := snortService(t, srv.URL)

	p, err := st.GetProvider(ctx, "snort")
	if err != nil || p.Enabled || p.Type != TypeSnort {
		t.Fatalf("default snort provider = %+v, %v", p, err)
	}

	// A wrong oinkcode is reported without leaking the code.
	bad := strings.Repeat("f", 40)
	if _, err := s.Update(ctx, "snort", nil, nil, map[string]string{"oinkcode": bad}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Sync(ctx, "snort")
	if err == nil || !strings.Contains(err.Error(), "Invalid oinkcode") || strings.Contains(err.Error(), bad) {
		t.Fatalf("sync with a bad oinkcode: %v", err)
	}
	if p, _ := st.GetProvider(ctx, "snort"); strings.Contains(p.LastError, bad) {
		t.Fatalf("LastError leaks the oinkcode: %q", p.LastError)
	}

	// The masked value sent back by a client keeps the stored secret.
	if _, err := s.Update(ctx, "snort", nil, nil, map[string]string{"oinkcode": testOinkcode}); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.Update(ctx, "snort", nil, nil, map[string]string{"oinkcode": MaskedSecret}); p.Options["oinkcode"] != testOinkcode {
		t.Fatalf("masked update replaced the oinkcode: %q", p.Options["oinkcode"])
	}
	if got := RedactOptions(p.Options)["oinkcode"]; got != MaskedSecret {
		t.Fatalf("redacted oinkcode = %q", got)
	}

	c1, err := s.Sync(ctx, "snort")
	if err != nil || c1 == "" {
		t.Fatalf("sync: %q %v", c1, err)
	}
	files, err := repo.ReadDir(c1, "snort")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 || files["snort3-server-webapp.rules"] == nil || files["snort3-protocol-scada.rules"] == nil || files[snortReportFile] == nil {
		t.Fatalf("files = %v", keys(files))
	}
	web := string(files["snort3-server-webapp.rules"])
	// Balanced policy: 66501 enabled, the max-detect rule commented out
	// (with $SIP_SERVERS replaced), the ber_data rule left out.
	if !strings.Contains(web, "\nalert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"SERVER-WEBAPP NGINX") ||
		!strings.Contains(web, `http.request_body; content:"|70 AD 80 F7 FF 7F 00 00|"; depth:8; fast_pattern;`) {
		t.Fatalf("66501 not converted/enabled:\n%s", web)
	}
	if !strings.Contains(web, "\n# alert tcp $EXTERNAL_NET any -> $HOME_NET $SIP_PORTS (msg:\"OS-OTHER only in max-detect\"") {
		t.Fatalf("max-detect rule not disabled or $SIP_SERVERS kept:\n%s", web)
	}
	if strings.Contains(web, "sid:300306") || strings.Contains(string(files["snort3-protocol-scada.rules"]), "sid:50000") {
		t.Fatal("unconvertible or config-dependent rule written")
	}
	// The max-detect setter of a flowbit checked in an OR list by a
	// balanced rule is enabled without alerts.
	if fi := string(files["snort3-file-identify.rules"]); !strings.Contains(fi, "\nalert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:\"FILE-IDENTIFY setter\"") || !strings.Contains(fi, "noalert") {
		t.Fatalf("flowbit setter not enabled:\n%s", fi)
	}
	report := string(files[snortReportFile])
	for _, want := range []string{"rules: 6, written enabled: 3, written disabled: 1", "enabled with noalert for flowbits: 1", "1 failed, 1 need suricata.yaml changes", "ber_data", "modbus:function 21"} {
		if !strings.Contains(report, want) {
			t.Errorf("report misses %q:\n%s", want, report)
		}
	}

	// Unchanged upstream: md5 matches, no second download.
	if c2, err := s.Sync(ctx, "snort"); err != nil || c2 != "" || fake.downloads.Load() != 1 {
		t.Fatalf("second sync: %q %v downloads=%d", c2, err, fake.downloads.Load())
	}

	// Changing the policy converts again.
	if _, err := s.Update(ctx, "snort", nil, nil, map[string]string{"policy": "max-detect"}); err != nil {
		t.Fatal(err)
	}
	c3, err := s.Sync(ctx, "snort")
	if err != nil || c3 == "" {
		t.Fatalf("policy sync: %q %v", c3, err)
	}
	files, _ = repo.ReadDir(c3, "snort")
	if !strings.Contains(string(files["snort3-server-webapp.rules"]), "\nalert tcp $EXTERNAL_NET any -> $HOME_NET $SIP_PORTS") {
		t.Fatalf("max-detect rule not enabled:\n%s", files["snort3-server-webapp.rules"])
	}
}

func TestSnortCommunityWithoutOinkcode(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSnortOrg{archives: map[string][]byte{
		"/downloads/community/snort3-community-rules.tar.gz": tarGz(t, map[string]string{
			"snort3-community-rules/snort3-community.rules": webappRule + "\n",
		}),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s, repo, _ := snortService(t, srv.URL)
	c, err := s.Sync(ctx, "snort")
	if err != nil || c == "" {
		t.Fatalf("sync: %q %v", c, err)
	}
	files, _ := repo.ReadDir(c, "snort")
	if !strings.Contains(string(files["snort3-community.rules"]), "\nalert http ") {
		t.Fatalf("community rule not enabled: %v", keys(files))
	}
}

func TestValidateSnortOptions(t *testing.T) {
	for _, o := range []map[string]string{
		{"ruleset": "registered"},
		{"ruleset": "lightspd"},
		{"oinkcode": "short"},
		{"ruleset": "pro"},
		{"policy": "paranoid"},
		{"approx": "maybe"},
		{"snort_version": "9.9"},
	} {
		if ValidateSnortOptions(o) == nil {
			t.Errorf("%v accepted", o)
		}
	}
	if err := ValidateSnortOptions(map[string]string{"ruleset": "registered", "oinkcode": testOinkcode, "policy": "security", "snort_version": "2.9.20"}); err != nil {
		t.Error(err)
	}
}
