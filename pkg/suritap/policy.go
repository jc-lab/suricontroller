package suritap

import "encoding/binary"

// EndpointMode is the inspection mode the operator set for a proxy
// endpoint (the suritap plugin pushes the endpoint policy to clients).
type EndpointMode uint8

const (
	// ModeOff: the endpoint is not inspected; send nothing.
	ModeOff EndpointMode = 1
	// ModeDetect: inspect without waiting for verdicts; never block.
	ModeDetect EndpointMode = 2
	// ModePrevent: wait for verdicts and block on drops.
	ModePrevent EndpointMode = 3
)

func (m EndpointMode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeDetect:
		return "detect"
	case ModePrevent:
		return "prevent"
	}
	return "unknown"
}

// Policy is the endpoint policy received from the plugin.
type Policy struct {
	Version uint32
	Modes   map[string]EndpointMode
}

const policyFixed = 8

// decodePolicy parses a POLICY record body: version:u32 count:u16 rsv:u16,
// then per endpoint mode:u8 len:u8 name[len].
func decodePolicy(b []byte) (*Policy, bool) {
	if len(b) < policyFixed {
		return nil, false
	}
	p := &Policy{Version: binary.LittleEndian.Uint32(b), Modes: map[string]EndpointMode{}}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	off := policyFixed
	for range n {
		if off+2 > len(b) {
			return nil, false
		}
		mode, l := EndpointMode(b[off]), int(b[off+1])
		off += 2
		if off+l > len(b) || mode < ModeOff || mode > ModePrevent {
			return nil, false
		}
		p.Modes[string(b[off:off+l])] = mode
		off += l
	}
	return p, true
}

// EndpointMode returns the operator's mode for endpoint, and false when the
// plugin's policy does not list it (or no policy was received yet): the
// caller then uses its own setting. The last policy received is kept across
// reconnects.
func (c *Client) EndpointMode(endpoint string) (EndpointMode, bool) {
	p := c.policy.Load()
	if p == nil {
		return 0, false
	}
	m, ok := p.Modes[endpoint]
	return m, ok
}

// Policy returns the last endpoint policy received (nil: none).
func (c *Client) Policy() *Policy { return c.policy.Load() }
