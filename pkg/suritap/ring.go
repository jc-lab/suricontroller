//go:build linux

package suritap

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"unsafe"
)

// Ring layout and wakeup protocol: see tap/suritap/src/ring.rs. Records
// are 8-byte aligned "len:u32 kind:u16 flags:u16 body"; head/tail are
// free-running byte counters; Go's sync/atomic operations are sequentially
// consistent, which the waiting-flag handshake relies on.

const (
	recHeader          = 8
	kindPad            = 0
	ctlSize            = 256
	ctlHead            = 0
	ctlTail            = 64
	ctlConsumerWaiting = 128
	ctlProducerWaiting = 192
)

var errCorrupt = errors.New("suritap: corrupt ring")

func align8(n int) int { return (n + 7) &^ 7 }

type ring struct {
	ctl  []byte
	data []byte
	size uint64
}

func (r *ring) word64(off int) *uint64 { return (*uint64)(unsafe.Pointer(&r.ctl[off])) }
func (r *ring) word32(off int) *uint32 { return (*uint32)(unsafe.Pointer(&r.ctl[off])) }

type producer struct {
	r          ring
	head, tail uint64
}

func newProducer(r ring) *producer {
	return &producer{r: r, head: atomic.LoadUint64(r.word64(ctlHead)), tail: atomic.LoadUint64(r.word64(ctlTail))}
}

func (p *producer) maxRecord() int { return int(p.r.size / 4) }

func (p *producer) free() uint64 {
	used := p.head - p.tail
	if used > p.r.size {
		return 0
	}
	return p.r.size - used
}

func (p *producer) refresh() {
	tail := atomic.LoadUint64(p.r.word64(ctlTail))
	if p.head-tail <= p.r.size {
		p.tail = tail
	}
}

// need returns the bytes (padding included) a record with body bytes needs.
func (p *producer) need(body int) int {
	total := align8(recHeader + body)
	toEnd := int(p.r.size - p.head&(p.r.size-1))
	if total > toEnd {
		return toEnd + total
	}
	return total
}

// push appends a record; false when it does not fit right now.
func (p *producer) push(kind, flags uint16, parts ...[]byte) bool {
	body := 0
	for _, b := range parts {
		body += len(b)
	}
	n := recHeader + body
	if n > p.maxRecord() {
		return false
	}
	need := uint64(p.need(body))
	if p.free() < need {
		p.refresh()
		if p.free() < need {
			return false
		}
	}
	mask := p.r.size - 1
	total := uint64(align8(n))
	pos := p.head & mask
	if toEnd := p.r.size - pos; total > toEnd {
		p.header(pos, uint32(toEnd), kindPad, 0)
		p.head += toEnd
		pos = 0
	}
	p.header(pos, uint32(n), kind, flags)
	off := pos + recHeader
	for _, b := range parts {
		off += uint64(copy(p.r.data[off:], b))
	}
	p.head += total
	return true
}

func (p *producer) header(pos uint64, n uint32, kind, flags uint16) {
	h := p.r.data[pos : pos+8]
	binary.LittleEndian.PutUint32(h, n)
	binary.LittleEndian.PutUint16(h[4:], kind)
	binary.LittleEndian.PutUint16(h[6:], flags)
}

// publish makes pushed records visible; true when the consumer sleeps and
// must be signalled.
func (p *producer) publish() bool {
	atomic.StoreUint64(p.r.word64(ctlHead), p.head)
	w := p.r.word32(ctlConsumerWaiting)
	return atomic.LoadUint32(w) != 0 && atomic.SwapUint32(w, 0) != 0
}

// prepareWait announces that the producer will sleep until need bytes are
// free; false (withdrawn) when the space appeared meanwhile.
func (p *producer) prepareWait(need int) bool {
	atomic.StoreUint32(p.r.word32(ctlProducerWaiting), 1)
	p.refresh()
	if p.free() >= uint64(need) {
		atomic.StoreUint32(p.r.word32(ctlProducerWaiting), 0)
		return false
	}
	return true
}

type record struct {
	kind, flags uint16
	body        []byte // aliases shared memory until the consumer advances
	size        uint64
}

type consumer struct {
	r          ring
	tail, head uint64
}

func newConsumer(r ring) *consumer {
	t := atomic.LoadUint64(r.word64(ctlTail))
	return &consumer{r: r, tail: t, head: t}
}

func (c *consumer) peek() (record, bool, error) {
	for {
		if c.tail == c.head {
			c.head = atomic.LoadUint64(c.r.word64(ctlHead))
			if c.tail == c.head {
				return record{}, false, nil
			}
		}
		avail := c.head - c.tail
		if avail > c.r.size || avail%8 != 0 {
			return record{}, false, errCorrupt
		}
		pos := c.tail & (c.r.size - 1)
		toEnd := c.r.size - pos
		h := c.r.data[pos : pos+8]
		n := uint64(binary.LittleEndian.Uint32(h))
		kind := binary.LittleEndian.Uint16(h[4:])
		flags := binary.LittleEndian.Uint16(h[6:])
		if kind == kindPad {
			if n != toEnd || n > avail {
				return record{}, false, errCorrupt
			}
			c.tail += n
			continue
		}
		size := uint64(align8(int(n)))
		if n < recHeader || size > toEnd || size > avail {
			return record{}, false, errCorrupt
		}
		return record{kind: kind, flags: flags, body: c.r.data[pos+recHeader : pos+n], size: size}, true, nil
	}
}

func (c *consumer) advance(r record) { c.tail += r.size }

// release returns consumed space; true when the producer waits for space.
func (c *consumer) release() bool {
	atomic.StoreUint64(c.r.word64(ctlTail), c.tail)
	w := c.r.word32(ctlProducerWaiting)
	return atomic.LoadUint32(w) != 0 && atomic.SwapUint32(w, 0) != 0
}

func (c *consumer) empty() bool { return atomic.LoadUint64(c.r.word64(ctlHead)) == c.tail }

// prepareSleep announces the consumer is about to sleep; false (withdrawn)
// when records arrived meanwhile.
func (c *consumer) prepareSleep() bool {
	atomic.StoreUint32(c.r.word32(ctlConsumerWaiting), 1)
	if atomic.LoadUint64(c.r.word64(ctlHead)) != c.tail {
		atomic.StoreUint32(c.r.word32(ctlConsumerWaiting), 0)
		return false
	}
	return true
}

func (c *consumer) cancelSleep() { atomic.StoreUint32(c.r.word32(ctlConsumerWaiting), 0) }
