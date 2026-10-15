//go:build linux

package suritap

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func testRing(size int) ring {
	mem := make([]byte, ctlSize+size+64)
	// 64-byte alignment is not needed for correctness in tests.
	return ring{ctl: mem[:ctlSize], data: mem[ctlSize : ctlSize+size], size: uint64(size)}
}

func TestRingWrapAndOrder(t *testing.T) {
	r := testRing(256)
	p, c := newProducer(r), newConsumer(r)
	sent, seen := 0, 0
	for round := range 200 {
		body := make([]byte, round%40)
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], uint32(round))
		for !p.push(7, uint16(round), id[:], body) {
			p.publish()
			rec, ok, err := c.peek()
			if err != nil || !ok {
				t.Fatalf("peek: %v %v", ok, err)
			}
			if got := binary.LittleEndian.Uint32(rec.body); got != uint32(seen) || len(rec.body) != 4+seen%40 {
				t.Fatalf("record %d: got id %d len %d", seen, got, len(rec.body))
			}
			c.advance(rec)
			c.release()
			seen++
		}
		sent++
	}
	p.publish()
	for {
		rec, ok, err := c.peek()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if rec.flags != uint16(seen) {
			t.Fatalf("flags %d want %d", rec.flags, seen)
		}
		c.advance(rec)
		seen++
	}
	if seen != sent {
		t.Fatalf("seen %d sent %d", seen, sent)
	}
}

func TestRingLimitsAndWakeups(t *testing.T) {
	r := testRing(256)
	p, c := newProducer(r), newConsumer(r)
	if p.push(1, 0, make([]byte, 57)) {
		t.Fatal("oversized record accepted")
	}
	n := 0
	for p.push(1, 0, make([]byte, 56)) {
		n++
	}
	if n != 4 {
		t.Fatalf("pushed %d records, want 4", n)
	}
	p.publish()
	if c.prepareSleep() {
		t.Fatal("records are pending but consumer would sleep")
	}
	c2 := newConsumer(testRing(256))
	p2 := newProducer(c2.r)
	if !c2.prepareSleep() {
		t.Fatal("empty ring must allow sleeping")
	}
	p2.push(1, 0)
	if !p2.publish() || p2.publish() {
		t.Fatal("exactly one wakeup expected")
	}
}

func TestRingCorruption(t *testing.T) {
	r := testRing(256)
	c := newConsumer(r)
	binary.LittleEndian.PutUint64(r.ctl[ctlHead:], 1000)
	if _, _, err := c.peek(); err == nil {
		t.Fatal("head beyond ring accepted")
	}
	binary.LittleEndian.PutUint64(r.ctl[ctlHead:], 8)
	binary.LittleEndian.PutUint32(r.data, 200)
	binary.LittleEndian.PutUint16(r.data[4:], 1)
	c = newConsumer(r)
	if _, _, err := c.peek(); err == nil {
		t.Fatal("record longer than available data accepted")
	}
}

func TestEncodeOpenAndVerdict(t *testing.T) {
	p := OpenParams{
		Src:  netip.MustParseAddrPort("[::ffff:198.51.100.1]:1234"),
		Dst:  netip.MustParseAddrPort("10.0.0.1:443"),
		Meta: []Meta{{MetaSNI, "a.example"}},
	}
	b, err := encodeOpen(9, &p)
	if err != nil {
		t.Fatal(err)
	}
	if b[8] != 4 || b[24] != 198 || binary.LittleEndian.Uint16(b[16:]) != 1234 || len(b) != openFixed+4+9 {
		t.Fatalf("bad OPEN encoding %v", b[:20])
	}
	p.Dst = netip.MustParseAddrPort("[2001:db8::1]:443")
	if _, err := encodeOpen(9, &p); err == nil {
		t.Fatal("mixed families accepted")
	}

	v := make([]byte, verdictFixed+alertSize)
	binary.LittleEndian.PutUint64(v, 5)
	binary.LittleEndian.PutUint32(v[8:], 3)
	v[12], v[13], v[14], v[15], v[16] = 1, 1, 1, 1, 8
	binary.LittleEndian.PutUint16(v[20:], 2)
	binary.LittleEndian.PutUint32(v[verdictFixed:], 2000001)
	v[verdictFixed+12] = 3
	got, ok := decodeVerdict(v)
	if !ok || got.CID != 5 || got.Token != 3 || got.Dir != ToClient || !got.Dropped() || got.Reason != ReasonRule ||
		got.AlertTotal != 2 || len(got.Alerts) != 1 || got.Alerts[0].SID != 2000001 {
		t.Fatalf("decoded %+v", got)
	}
	if _, ok := decodeVerdict(v[:verdictFixed+3]); ok {
		t.Fatal("truncated alert accepted")
	}
}
