package snortconv

import (
	"errors"
	"strings"
	"testing"
)

func TestConvert(t *testing.T) {
	tests := []struct {
		name    string
		dialect Dialect
		in      string
		want    string // expected Suricata rule; empty when the rule fails
		status  Status
	}{
		{
			name:    "snort2 content modifiers become sticky buffers",
			dialect: Snort2,
			in:      `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"x"; flow:to_server,established; content:"/a.cgi"; fast_pattern:only; http_uri; content:"X-Test|3A|"; nocase; http_header; sid:1; rev:2;)`,
			want:    `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"x"; flow:to_server,established; http.uri; content:"/a.cgi"; nocase; fast_pattern; http.header; content:"X-Test|3A|"; nocase; sid:1; rev:2;)`,
		},
		{
			name:    "snort2 urilen checks the raw URI and its range is inclusive",
			dialect: Snort2,
			in:      `alert tcp any any -> any 80 (msg:"x"; flow:to_server,established; urilen:17<>27; content:"/x"; http_uri; sid:2;)`,
			want:    `alert tcp any any -> any 80 (msg:"x"; flow:to_server,established; urilen:16<>28,raw; http.uri; content:"/x"; sid:2;)`,
		},
		{
			name:    "snort2 urilen norm",
			dialect: Snort2,
			in:      `alert tcp any any -> any 80 (msg:"x"; urilen:>500,norm; sid:3;)`,
			want:    `alert tcp any any -> any 80 (msg:"x"; urilen:>500; sid:3;)`,
		},
		{
			name:    "snort2 buffers are grouped and no empty buffer is left",
			dialect: Snort2,
			in:      `alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"x"; flow:to_client,established; file_data; content:".doc.exe"; fast_pattern:only; content:"Content-Length:"; http_header; content:"PK"; sid:4;)`,
			want:    `alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"x"; flow:to_client,established; file.data; content:".doc.exe"; nocase; fast_pattern; content:"PK"; http.header; content:"Content-Length:"; sid:4;)`,
		},
		{
			name:    "snort2 relative content after a match in another buffer starts the buffer",
			dialect: Snort2,
			in:      `alert tcp any any -> any 80 (msg:"x"; content:"A"; http_uri; content:"BB"; distance:2; within:5; sid:5;)`,
			want:    `alert tcp any any -> any 80 (msg:"x"; http.uri; content:"A"; pkt_data; content:"BB"; offset:2; depth:5; sid:5;)`,
		},
		{
			name:    "snort2 relative isdataat follows the previous match into its buffer",
			dialect: Snort2,
			in:      `alert tcp any any -> any 80 (msg:"x"; flow:to_server,established; content:"X-Forwarded-For"; nocase; http_raw_header; isdataat:90,relative; pcre:"/X-Forwarded-For:[^\n\r]{90}/Hsmi"; sid:6;)`,
			want:    `alert tcp any any -> any 80 (msg:"x"; flow:to_server,established; http.header.raw; content:"X-Forwarded-For"; nocase; isdataat:90,relative; http.header; pcre:"/X-Forwarded-For:[^\n\r]{90}/smi"; sid:6;)`,
		},
		{
			name:    "snort2 pcre R at the start of a buffer",
			dialect: Snort2,
			in:      `alert tcp any any -> any 80 (msg:"x"; content:"a"; http_uri; pcre:"/^b/R"; sid:7;)`,
			want:    `alert tcp any any -> any 80 (msg:"x"; http.uri; content:"a"; pkt_data; pcre:"/^b/"; sid:7;)`,
		},
		{
			name:    "flowbits with & are split",
			dialect: Snort2,
			in:      `alert tcp any any -> any any (msg:"x"; content:"a"; flowbits:set,f.a&f.b; flowbits:isset,f.c|f.d; sid:8;)`,
			want:    `alert tcp any any -> any any (msg:"x"; content:"a"; flowbits:set,f.a; flowbits:set,f.b; flowbits:isset,f.c|f.d; sid:8;)`,
		},
		{
			name:    "commented out rules stay commented out",
			dialect: Snort2,
			in:      `# alert tcp any any -> any 21 (msg:"x"; content:"USER"; nocase; sid:9;)`,
			want:    `# alert tcp any any -> any 21 (msg:"x"; content:"USER"; nocase; sid:9;)`,
		},
		{
			name:    "sip keywords",
			dialect: Snort2,
			in:      `alert udp any 5060 -> any any (msg:"x"; sip_stat_code:4; sid:10;)`,
			want:    `alert udp any 5060 -> any any (msg:"x"; sip.stat_code; content:"4"; startswith; bsize:3; sid:10;)`,
		},
		{
			name:    "sip methods list",
			dialect: Snort3,
			in:      `alert udp any any -> any 5060 ( msg:"x"; flow:to_server; sip_method:invite,cancel; sid:11; )`,
			want:    `alert udp any any -> any 5060 (msg:"x"; flow:to_server; sip.method; pcre:"/^(?:INVITE|CANCEL)$/i"; sid:11;)`,
		},
		{
			name:    "sip method",
			dialect: Snort2,
			in:      `alert udp any any -> any 5060 (msg:"x"; content:"INVITE"; fast_pattern:only; sip_method:invite; sid:27;)`,
			want:    `alert udp any any -> any 5060 (msg:"x"; content:"INVITE"; nocase; fast_pattern; sip.method; content:"INVITE"; nocase; startswith; endswith; sid:27;)`,
		},
		{
			name:    "request and response buffers cannot be mixed",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; flow:to_client,established; http_uri; content:"/a"; http_stat_code; content:"200"; sid:28; )`,
			status:  Failed,
		},
		{
			name:    "snort3 content options and dce",
			dialect: Snort3,
			in:      `alert tcp $EXTERNAL_NET any -> $HOME_NET [135,445] ( msg:"x"; flow:to_server,established; dce_iface:uuid 4b324fc8-1670-01d3-1278-5a47bf6ee188; dce_opnum:"15"; dce_stub_data; pcre:"/^.{4}/s"; byte_jump:4,-4,relative,dce,align; content:"|00 00|",within 4,distance 8; service:netbios-ssn; sid:12; )`,
			want:    `alert tcp $EXTERNAL_NET any -> $HOME_NET [135,445] (msg:"x"; flow:to_server,established; dce_iface:4b324fc8-1670-01d3-1278-5a47bf6ee188; dce_opnum:15; dce_stub_data; pcre:"/^.{4}/s"; byte_jump:4,-4,relative,dce,align; content:"|00 00|"; distance:8; within:4; sid:12;)`,
		},
		{
			name:    "snort3 relative content right after a sticky buffer",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; http_uri; content:".php?id=",offset 6,fast_pattern; http_header; content:" HTTP/1.",within 11,distance 1; content:"UA",distance 0; sid:13; )`,
			want:    `alert tcp any any -> any 80 (msg:"x"; http.uri; content:".php?id="; offset:6; fast_pattern; http.header; content:" HTTP/1."; offset:1; depth:11; content:"UA"; distance:0; sid:13;)`,
		},
		{
			name:    "snort3 selecting a buffer again resets the cursor",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; http_uri; content:"a"; pkt_data; content:"b"; http_uri; content:"c",distance 0; sid:14; )`,
			want:    `alert tcp any any -> any 80 (msg:"x"; http.uri; content:"a"; content:"c"; pkt_data; content:"b"; sid:14;)`,
		},
		{
			name:    "snort3 bufferlen",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; http_uri; content:"/w3who.dll?",fast_pattern,nocase; bufferlen:>=519,relative; http_raw_uri; bufferlen:50<=>150; http_method; bufferlen:<=4; sid:15; )`,
			want:    `alert tcp any any -> any 80 (msg:"x"; http.uri; content:"/w3who.dll?"; nocase; fast_pattern; isdataat:518,relative; http.uri.raw; bsize:49<>151; http.method; bsize:<5; sid:15;)`,
		},
		{
			name:    "snort3 service header, tag and stream_size",
			dialect: Snort3,
			in:      `alert http ( msg:"x"; flow:to_server,established; http_header:field user-agent; content:"Evil",nocase; tag:session,packets 5; sid:16; )`,
			want:    `alert http any any -> any any (msg:"x"; flow:to_server,established; http.user_agent; content:"Evil"; nocase; tag:session,5,packets; sid:16;)`,
		},
		{
			name:    "snort3 stream_size",
			dialect: Snort3,
			in:      `alert tcp any any -> any 513 ( msg:"x"; flow:to_server,established; content:"root|00|",depth 5; stream_size:1,to_client; sid:17; )`,
			want:    `alert tcp any any -> any 513 (msg:"x"; flow:to_server,established; content:"root|00|"; depth:5; stream_size:server,=,1; sid:17;)`,
		},
		{
			name:    "snort3 raw_data is the Suricata payload",
			dialect: Snort3,
			in:      `alert tcp any any -> any 23 ( msg:"x"; flow:to_server,established; raw_data; content:"|FF F3|",fast_pattern,nocase; service:telnet; sid:18; )`,
			want:    `alert tcp any any -> any 23 (msg:"x"; flow:to_server,established; content:"|FF F3|"; nocase; fast_pattern; sid:18;)`,
		},
		{
			name:    "one fast_pattern per rule, none on negated relative content",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; content:"a"; content:!"b",distance 0,fast_pattern; content:"c",fast_pattern; content:"d",fast_pattern; sid:19; )`,
			want:    `alert tcp any any -> any 80 (msg:"x"; content:"a"; content:!"b"; distance:0; content:"c"; fast_pattern; content:"d"; sid:19;)`,
		},
		{
			name:    "sdrop is a drop without alert",
			dialect: Snort2,
			in:      `sdrop tcp any any -> any any (msg:"x"; content:"a"; sid:20;)`,
			want:    `drop tcp any any -> any any (msg:"x"; content:"a"; sid:20; noalert;)`,
		},
		{
			name:    "sip_header is approximated by the payload",
			dialect: Snort3,
			in:      `alert udp any any -> any 5060 ( msg:"x"; flow:stateless; sip_header; content:"() {"; sid:21; )`,
			want:    `alert udp any any -> any 5060 (msg:"x"; flow:stateless; content:"() {"; sid:21;)`,
			status:  Approx,
		},
		{
			name:    "ber_data has no equivalent",
			dialect: Snort3,
			in:      `alert ssl ( msg:"x"; content:"|06 03|"; ber_data:0x04; sid:22; )`,
			status:  Failed,
		},
		{
			name:    "http_param has no equivalent",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; http_param:"id",nocase; sid:23; )`,
			status:  Failed,
		},
		{
			name:    "packet options cannot be combined with app-layer buffers",
			dialect: Snort2,
			in:      `alert tcp any any -> any 80 (msg:"x"; flags:FA; content:"307"; http_stat_code; sid:24;)`,
			status:  Failed,
		},
		{
			name:    "content that cannot fit never matches",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; content:"a"; content:"bcd",within 2; sid:25; )`,
			status:  Failed,
		},
		{
			name:    "byte_extract variables stay defined before use",
			dialect: Snort3,
			in:      `alert tcp any any -> any 80 ( msg:"x"; http_header; content:"L:"; byte_extract:2,0,len,relative,string,dec; pkt_data; content:"P"; http_header; content:"Q",distance len; sid:26; )`,
			want:    `alert tcp any any -> any 80 (msg:"x"; http.header; content:"L:"; byte_extract:2,0,len,relative,string,dec; pkt_data; content:"P"; http.header; content:"Q"; offset:len; sid:26;)`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Convert(tc.in, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != tc.status {
				t.Fatalf("status = %v, want %v (issues %+v)", res.Status, tc.status, res.Issues)
			}
			if res.Output != tc.want {
				t.Errorf("output mismatch\n got: %s\nwant: %s", res.Output, tc.want)
			}
		})
	}
}

func TestConvertNotRule(t *testing.T) {
	for _, l := range []string{"", "# a comment", "#-----", "# alert is a word in this comment"} {
		if _, err := Convert(l, Auto); !errors.Is(err, ErrNotRule) {
			t.Errorf("Convert(%q) err = %v, want ErrNotRule", l, err)
		}
	}
}

func TestDetectDialect(t *testing.T) {
	s2 := []string{
		`alert tcp any any -> any 80 (msg:"x"; content:"a"; http_uri; sid:1;)`,
		`alert tcp any any -> any 80 (msg:"x"; content:"a"; depth:4; sid:2;)`,
	}
	s3 := []string{
		`alert tcp any any -> any 80 ( msg:"x"; http_uri; content:"a",nocase; sid:1; )`,
		`alert tcp any any -> any 80 ( msg:"x"; content:"a"; service:http; sid:2; )`,
	}
	if d := DetectDialect(s2); d != Snort2 {
		t.Errorf("snort2 detected as %v", d)
	}
	if d := DetectDialect(s3); d != Snort3 {
		t.Errorf("snort3 detected as %v", d)
	}
	res, err := Convert(s3[0], Auto)
	if err != nil || res.Dialect != Snort3 || !strings.Contains(res.Output, "http.uri; content:\"a\"; nocase;") {
		t.Errorf("auto conversion: %+v, %v", res, err)
	}
}

func TestNormRange(t *testing.T) {
	tests := []struct {
		in     string
		snort2 bool
		want   string
	}{
		{"5", false, "5"},
		{"=5", false, "5"},
		{"<5", false, "<5"},
		{">=5", false, ">4"},
		{"<=5", false, "<6"},
		{"5<>10", false, "5<>10"},
		{"5<=>10", false, "4<>11"},
		{"5<>10", true, "4<>11"},
		{"0<>10", true, "<11"},
		{"!=3", false, "!3"},
	}
	for _, tc := range tests {
		if got, ok := normRange(tc.in, tc.snort2); !ok || got != tc.want {
			t.Errorf("normRange(%q, %v) = %q, %v; want %q", tc.in, tc.snort2, got, ok, tc.want)
		}
	}
}
