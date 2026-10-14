package suritap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Protocol constants; see docs/suritap.md.
const (
	magic   = 0x50415453 // "STAP"
	version = 1

	kOpen      = 1
	kData      = 2
	kGap       = 3
	kEOF       = 4
	kClose     = 5
	kPing      = 6
	kVerdict   = 0x81
	kBypass    = 0x82
	kPong      = 0x83
	kFlowError = 0x84

	fWantVerdict = 1

	openFixed        = 56
	dataFixed        = 16
	smallBody        = 16
	verdictFixed     = 24
	alertSize        = 16
	maxAlerts        = 8
	maxVerdictRecord = 8 + verdictFixed + alertSize*maxAlerts
	maxMeta          = 2048

	helloSize   = 64
	welcomeSize = 64
	stOK        = 0
)

// Dir is the direction of payload relative to the proxied connection.
type Dir uint8

const (
	// ToServer is client (downstream) to server (upstream) traffic.
	ToServer Dir = 0
	// ToClient is server (upstream) to client (downstream) traffic.
	ToClient Dir = 1
)

func (d Dir) String() string {
	if d == ToClient {
		return "to_client"
	}
	return "to_server"
}

// Action is the outcome of a verdict.
type Action uint8

const (
	Pass Action = 0
	Drop Action = 1
	// Error means no verdict could be computed; apply the fail policy.
	Error Action = 2
)

func (a Action) String() string {
	switch a {
	case Pass:
		return "pass"
	case Drop:
		return "drop"
	default:
		return "error"
	}
}

// Reason explains a verdict that is not a plain pass.
type Reason uint8

const (
	ReasonNone        Reason = 0
	ReasonRule        Reason = 1 // a drop/reject rule matched
	ReasonPolicy      Reason = 2 // exception policy, memcap, stream/decoder error
	ReasonFlow        Reason = 3 // the flow was dropped by an earlier verdict
	ReasonUnknownFlow Reason = 4 // connection id unknown (never opened or rejected)
	ReasonProtocol    Reason = 5 // invalid record
	ReasonEngine      Reason = 6 // the engine could not process the packet
)

func (r Reason) String() string {
	switch r {
	case ReasonNone:
		return "none"
	case ReasonRule:
		return "rule"
	case ReasonPolicy:
		return "policy"
	case ReasonFlow:
		return "flow"
	case ReasonUnknownFlow:
		return "unknown-flow"
	case ReasonProtocol:
		return "protocol"
	case ReasonEngine:
		return "engine"
	}
	return fmt.Sprintf("reason(%d)", uint8(r))
}

// MetaTag identifies connection metadata attached to OPEN and logged in
// EVE under "suritap".
type MetaTag uint8

const (
	MetaSNI       MetaTag = 1
	MetaALPN      MetaTag = 2
	MetaJA4       MetaTag = 3
	MetaRoute     MetaTag = 4
	MetaRequestID MetaTag = 5
	MetaEndpoint  MetaTag = 6
	MetaService   MetaTag = 7
	MetaUser      MetaTag = 8
	MetaProto     MetaTag = 9
	MetaProxy     MetaTag = 10
)

// Meta is one metadata item.
type Meta struct {
	Tag   MetaTag
	Value string
}

// Alert is a rule match reported with a verdict.
type Alert struct {
	SID, GID, Rev uint32
	// Action holds Suricata action bits (alert=1, drop=2, reject=4/8/16, pass=32).
	Action uint8
}

// Verdict answers an Inspect call.
type Verdict struct {
	CID    uint64
	Token  uint32
	Dir    Dir
	Action Action
	Reason Reason
	// DropReason is Suricata's raw PKT_DROP_REASON_* value.
	DropReason uint8
	// AlertTotal may exceed len(Alerts) (at most 8 are carried).
	AlertTotal uint16
	Alerts     []Alert
}

// Dropped reports whether the traffic must be blocked.
func (v Verdict) Dropped() bool { return v.Action == Drop }

func decodeVerdict(b []byte) (Verdict, bool) {
	if len(b) < verdictFixed {
		return Verdict{}, false
	}
	n := min(int(b[15]), maxAlerts)
	if len(b) < verdictFixed+n*alertSize {
		return Verdict{}, false
	}
	v := Verdict{
		CID:        binary.LittleEndian.Uint64(b),
		Token:      binary.LittleEndian.Uint32(b[8:]),
		Dir:        Dir(b[12] & 1),
		Action:     Action(min(b[13], 2)),
		Reason:     Reason(b[14]),
		DropReason: b[16],
		AlertTotal: binary.LittleEndian.Uint16(b[20:]),
	}
	if n > 0 {
		v.Alerts = make([]Alert, n)
		for i := range v.Alerts {
			o := verdictFixed + i*alertSize
			v.Alerts[i] = Alert{
				SID:    binary.LittleEndian.Uint32(b[o:]),
				GID:    binary.LittleEndian.Uint32(b[o+4:]),
				Rev:    binary.LittleEndian.Uint32(b[o+8:]),
				Action: b[o+12],
			}
		}
	}
	return v, true
}

// OpenParams describes a new proxied connection.
type OpenParams struct {
	// Src is the real client address (after PROXY protocol / trusted
	// forwarding headers).
	Src netip.AddrPort
	// Dst is the proxy listener address.
	Dst netip.AddrPort
	// Hint is an informational protocol hint.
	Hint uint8
	// Tenant selects a detection tenant (0 = default).
	Tenant uint32
	Meta   []Meta
}

var errFamily = errors.New("suritap: source and destination address families differ")

func encodeOpen(cid uint64, p *OpenParams) ([]byte, error) {
	src, dst := p.Src.Addr().Unmap(), p.Dst.Addr().Unmap()
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() {
		return nil, errFamily
	}
	size := openFixed
	for _, m := range p.Meta {
		if len(m.Value) > 0xffff {
			return nil, errors.New("suritap: metadata value too long")
		}
		size += 4 + len(m.Value)
	}
	if size-openFixed > maxMeta {
		return nil, errors.New("suritap: metadata too long")
	}
	b := make([]byte, openFixed, size)
	binary.LittleEndian.PutUint64(b, cid)
	if src.Is4() {
		b[8] = 4
		s, d := src.As4(), dst.As4()
		copy(b[24:], s[:])
		copy(b[40:], d[:])
	} else {
		b[8] = 6
		s, d := src.As16(), dst.As16()
		copy(b[24:], s[:])
		copy(b[40:], d[:])
	}
	b[9] = p.Hint
	binary.LittleEndian.PutUint32(b[12:], p.Tenant)
	binary.LittleEndian.PutUint16(b[16:], p.Src.Port())
	binary.LittleEndian.PutUint16(b[18:], p.Dst.Port())
	for _, m := range p.Meta {
		b = append(b, byte(m.Tag), 0, byte(len(m.Value)), byte(len(m.Value)>>8))
		b = append(b, m.Value...)
	}
	return b, nil
}

func dataHeader(b *[dataFixed]byte, cid uint64, dir Dir, token uint32) {
	*b = [dataFixed]byte{}
	binary.LittleEndian.PutUint64(b[:], cid)
	b[8] = byte(dir)
	binary.LittleEndian.PutUint32(b[12:], token)
}

func small(cid uint64, x uint8, word uint32) []byte {
	b := make([]byte, smallBody)
	binary.LittleEndian.PutUint64(b, cid)
	b[8] = x
	binary.LittleEndian.PutUint32(b[12:], word)
	return b
}

func encodeHello(name string) []byte {
	b := make([]byte, helloSize)
	binary.LittleEndian.PutUint32(b, magic)
	binary.LittleEndian.PutUint16(b[4:], version)
	binary.LittleEndian.PutUint16(b[6:], helloSize)
	binary.LittleEndian.PutUint32(b[8:], uint32(pid))
	copy(b[16:48], name)
	return b
}

type welcome struct {
	status, workerIndex, workerCount uint16
	maxPayload, maxFlows, sessionID  uint32
	message                          string
}

func decodeWelcome(b []byte) (welcome, bool) {
	if len(b) != welcomeSize || binary.LittleEndian.Uint32(b) != magic || binary.LittleEndian.Uint16(b[4:]) != version {
		return welcome{}, false
	}
	msg := b[24:64]
	for i, c := range msg {
		if c == 0 {
			msg = msg[:i]
			break
		}
	}
	return welcome{
		status:      binary.LittleEndian.Uint16(b[6:]),
		workerIndex: binary.LittleEndian.Uint16(b[8:]),
		workerCount: binary.LittleEndian.Uint16(b[10:]),
		maxPayload:  binary.LittleEndian.Uint32(b[12:]),
		maxFlows:    binary.LittleEndian.Uint32(b[16:]),
		sessionID:   binary.LittleEndian.Uint32(b[20:]),
		message:     string(msg),
	}, true
}
