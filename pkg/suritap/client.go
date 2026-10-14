//go:build linux

package suritap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var (
	// ErrClosed is returned once the session with Suricata is gone.
	ErrClosed = errors.New("suritap: session closed")
	// ErrRingFull is returned by non-blocking sends when the ring is full.
	ErrRingFull = errors.New("suritap: ring full")
	errTooLarge = errors.New("suritap: record too large")
)

// Options configure a Client.
type Options struct {
	// Name is reported to Suricata (logged). Default "suritap-go".
	Name string
	// C2SSize is the request ring size per session (power of two,
	// default 1 MiB).
	C2SSize int
	// S2CSize is the verdict ring size per session (power of two,
	// default 256 KiB).
	S2CSize int
	// DialTimeout bounds the handshake and OPEN. Default 2s.
	DialTimeout time.Duration
	// Spin makes the verdict reader busy-poll this long before sleeping
	// (lower latency at the cost of CPU). Default 0.
	Spin time.Duration
}

func (o *Options) defaults() {
	if o.Name == "" {
		o.Name = "suritap-go"
	}
	if o.C2SSize == 0 {
		o.C2SSize = 1 << 20
	}
	if o.S2CSize == 0 {
		o.S2CSize = 256 << 10
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 2 * time.Second
	}
}

// SocketPath is the socket of Suricata worker i inside dir.
func SocketPath(dir string, i int) string {
	return filepath.Join(dir, fmt.Sprintf("worker-%d.sock", i))
}

type reply struct {
	v    Verdict
	pong bool
	err  error
}

type session struct {
	conn    *net.UnixConn
	c2sBell int
	s2cBell *os.File
	reg     *region

	mu           sync.Mutex // guards tx, spaceCh and the mapping
	tx           *producer
	spaceCh      chan struct{}
	spaceWaiters atomic.Int32

	waitMu    sync.Mutex
	waiters   map[uint32]chan reply
	credits   chan struct{}
	nextToken atomic.Uint32

	dead     atomic.Bool
	deadCh   chan struct{}
	failOnce sync.Once
	done     chan struct{}

	bypassed   sync.Map // cid -> struct{}
	flowErrors sync.Map // cid -> uint32

	// CLOSE records that did not fit yet; flushed before any other record
	// and whenever ring space frees up.
	closeMu sync.Mutex
	closes  []closeReq

	workerIndex, workerCount int
	maxPayload               int
	spin                     time.Duration
}

func dialSession(path string, o *Options) (*session, error) {
	reg, err := newRegion(o.C2SSize, o.S2CSize)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		reg.close()
		return nil, fmt.Errorf("suritap: %w", err)
	}
	fail := func(err error) (*session, error) {
		conn.Close()
		reg.close()
		return nil, err
	}
	if _, _, err := conn.WriteMsgUnix(encodeHello(o.Name), unix.UnixRights(reg.fd), nil); err != nil {
		return fail(fmt.Errorf("suritap: hello: %w", err))
	}
	// Suricata holds its own reference now.
	unix.Close(reg.fd)
	reg.fd = -1
	_ = conn.SetReadDeadline(time.Now().Add(o.DialTimeout))
	buf := make([]byte, 128)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return fail(fmt.Errorf("suritap: welcome: %w", err))
	}
	var fds []int
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for i := range msgs {
			if f, err := unix.ParseUnixRights(&msgs[i]); err == nil {
				fds = append(fds, f...)
			}
		}
	}
	closeFds := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	w, ok := decodeWelcome(buf[:n])
	switch {
	case flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || !ok:
		closeFds()
		return fail(errors.New("suritap: malformed welcome"))
	case w.status != stOK:
		closeFds()
		return fail(fmt.Errorf("suritap: session refused (%d): %s", w.status, w.message))
	case len(fds) != 2 || w.workerCount == 0:
		closeFds()
		return fail(errors.New("suritap: bad welcome"))
	}
	_ = conn.SetReadDeadline(time.Time{})
	credits := max(o.S2CSize/maxVerdictRecord/2, 1)
	s := &session{
		conn:        conn,
		c2sBell:     fds[0],
		s2cBell:     os.NewFile(uintptr(fds[1]), "suritap-s2c"),
		reg:         reg,
		tx:          newProducer(reg.c2s),
		spaceCh:     make(chan struct{}),
		waiters:     make(map[uint32]chan reply),
		credits:     make(chan struct{}, credits),
		deadCh:      make(chan struct{}),
		done:        make(chan struct{}),
		workerIndex: int(w.workerIndex),
		workerCount: int(w.workerCount),
		maxPayload:  min(int(w.maxPayload), o.C2SSize/4-recHeader-dataFixed),
		spin:        o.Spin,
	}
	go s.readLoop()
	go s.watch()
	return s, nil
}

// watch detects the server going away (it sends nothing after the
// handshake).
func (s *session) watch() {
	buf := make([]byte, 64)
	_, _ = s.conn.Read(buf)
	s.fail()
}

func (s *session) fail() {
	s.failOnce.Do(func() {
		s.dead.Store(true)
		close(s.deadCh)
		s.waitMu.Lock()
		for t, ch := range s.waiters {
			ch <- reply{err: ErrClosed}
			delete(s.waiters, t)
		}
		s.waitMu.Unlock()
		s.mu.Lock()
		close(s.spaceCh)
		s.spaceCh = make(chan struct{})
		s.mu.Unlock()
		s.conn.Close()
		s.s2cBell.Close() // wakes the reader
	})
}

// destroy tears the session down and unmaps the region once nothing can
// touch it anymore.
func (s *session) destroy() {
	s.fail()
	<-s.done
	s.mu.Lock()
	s.reg.close()
	if s.c2sBell >= 0 {
		unix.Close(s.c2sBell)
		s.c2sBell = -1
	}
	s.mu.Unlock()
}

func (s *session) readLoop() {
	defer close(s.done)
	rx := newConsumer(s.reg.s2c)
	var buf [8]byte
	for {
		n := 0
		for {
			r, ok, err := rx.peek()
			if err != nil {
				s.fail()
				return
			}
			if !ok {
				break
			}
			s.dispatch(r)
			rx.advance(r)
			n++
		}
		if n > 0 {
			rx.release()
		}
		s.flushCloses()
		s.notifySpace()
		if s.dead.Load() {
			return
		}
		if n > 0 {
			continue
		}
		if s.spin > 0 {
			// Yield while spinning: the goroutine woken by the last
			// verdict may be queued on this P.
			deadline := time.Now().Add(s.spin)
			for rx.empty() && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if !rx.empty() {
				continue
			}
		}
		if !rx.prepareSleep() {
			continue
		}
		_, err := s.s2cBell.Read(buf[:])
		rx.cancelSleep()
		if err != nil {
			s.fail()
			return
		}
	}
}

func (s *session) releaseCredit() {
	select {
	case <-s.credits:
	default:
	}
}

func (s *session) complete(token uint32, r reply) {
	s.waitMu.Lock()
	ch, ok := s.waiters[token]
	delete(s.waiters, token)
	s.waitMu.Unlock()
	if ok {
		ch <- r
	}
}

func (s *session) dispatch(r record) {
	switch r.kind {
	case kVerdict:
		if v, ok := decodeVerdict(r.body); ok {
			s.releaseCredit()
			s.complete(v.Token, reply{v: v})
		}
	case kPong:
		if len(r.body) >= smallBody {
			s.releaseCredit()
			s.complete(binary.LittleEndian.Uint32(r.body), reply{pong: true})
		}
	case kBypass:
		if len(r.body) >= smallBody {
			s.bypassed.Store(binary.LittleEndian.Uint64(r.body), struct{}{})
		}
	case kFlowError:
		if len(r.body) >= smallBody {
			s.flowErrors.Store(binary.LittleEndian.Uint64(r.body), binary.LittleEndian.Uint32(r.body[12:]))
		}
	}
}

type closeReq struct {
	cid uint64
	how uint8
}

// flushClosesLocked pushes queued CLOSEs while they fit. Caller holds s.mu.
func (s *session) flushClosesLocked() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	n := 0
	for _, c := range s.closes {
		if !s.tx.push(kClose, 0, small(c.cid, c.how, 0)) {
			break
		}
		n++
	}
	if n > 0 {
		s.closes = s.closes[n:]
		if s.tx.publish() {
			signal(s.c2sBell)
		}
	}
}

func (s *session) pendingCloses() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return len(s.closes) > 0
}

func (s *session) flushCloses() {
	if !s.pendingCloses() {
		return
	}
	s.mu.Lock()
	if !s.dead.Load() {
		s.flushClosesLocked()
	}
	s.mu.Unlock()
}

// closeConn closes a connection without blocking; the CLOSE is queued
// when the ring is full so the server never keeps a closed flow.
func (s *session) closeConn(cid uint64, how uint8) {
	s.bypassed.Delete(cid)
	s.flowErrors.Delete(cid)
	if s.dead.Load() {
		return
	}
	s.closeMu.Lock()
	s.closes = append(s.closes, closeReq{cid, how})
	s.closeMu.Unlock()
	s.flushCloses()
}

func (s *session) notifySpace() {
	if s.spaceWaiters.Load() > 0 {
		s.mu.Lock()
		close(s.spaceCh)
		s.spaceCh = make(chan struct{})
		s.mu.Unlock()
	}
}

func signal(fd int) {
	var one = [8]byte{1}
	_, _ = unix.Write(fd, one[:])
}

// push appends one record, waiting for ring space until ctx is done (no
// waiting when ctx is nil).
func (s *session) push(ctx context.Context, kind, flags uint16, parts ...[]byte) error {
	body := 0
	for _, b := range parts {
		body += len(b)
	}
	s.mu.Lock()
	for {
		if s.dead.Load() {
			s.mu.Unlock()
			return ErrClosed
		}
		if s.pendingCloses() {
			s.flushClosesLocked()
		}
		if s.tx.push(kind, flags, parts...) {
			if s.tx.publish() {
				signal(s.c2sBell)
			}
			s.mu.Unlock()
			return nil
		}
		if recHeader+body > s.tx.maxRecord() {
			s.mu.Unlock()
			return errTooLarge
		}
		if ctx == nil {
			s.mu.Unlock()
			return ErrRingFull
		}
		s.spaceWaiters.Add(1)
		ch := s.spaceCh
		waiting := s.tx.prepareWait(s.tx.need(body))
		s.mu.Unlock()
		if waiting {
			select {
			case <-ch:
			case <-ctx.Done():
				s.spaceWaiters.Add(-1)
				return ctx.Err()
			}
		}
		s.spaceWaiters.Add(-1)
		s.mu.Lock()
	}
}

func (s *session) request(ctx context.Context, send func(token uint32) error) (reply, error) {
	select {
	case s.credits <- struct{}{}:
	case <-ctx.Done():
		return reply{}, ctx.Err()
	case <-s.deadCh:
		return reply{}, ErrClosed
	}
	token := s.nextToken.Add(1)
	ch := make(chan reply, 1)
	s.waitMu.Lock()
	s.waiters[token] = ch
	s.waitMu.Unlock()
	if err := send(token); err != nil {
		s.waitMu.Lock()
		_, registered := s.waiters[token]
		delete(s.waiters, token)
		s.waitMu.Unlock()
		if registered {
			s.releaseCredit()
		}
		return reply{}, err
	}
	select {
	case r := <-ch:
		return r, r.err
	case <-ctx.Done():
		// A late verdict still returns the credit when it arrives.
		s.waitMu.Lock()
		delete(s.waiters, token)
		s.waitMu.Unlock()
		select {
		case r := <-ch:
			return r, r.err
		default:
		}
		return reply{}, ctx.Err()
	}
}

// Client talks to all workers of one Suricata suritap instance. It is safe
// for concurrent use.
type Client struct {
	dir     string
	opts    Options
	mu      sync.Mutex
	slots   []*session
	nextCID atomic.Uint64
	closed  atomic.Bool
}

func mix(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	return x ^ x>>33
}

// Dial connects to worker 0 of the plugin listening in dir to learn the
// worker count; other sessions are opened on first use.
func Dial(dir string, opts Options) (*Client, error) {
	opts.defaults()
	first, err := dialSession(SocketPath(dir, 0), &opts)
	if err != nil {
		return nil, err
	}
	c := &Client{dir: dir, opts: opts, slots: make([]*session, first.workerCount)}
	c.slots[0] = first
	c.nextCID.Store(mix(uint64(time.Now().UnixNano())) | 1)
	return c, nil
}

// Workers returns the number of Suricata workers.
func (c *Client) Workers() int { return len(c.slots) }

func (c *Client) session(idx int) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return nil, ErrClosed
	}
	if s := c.slots[idx]; s != nil {
		if !s.dead.Load() {
			return s, nil
		}
		go s.destroy()
		c.slots[idx] = nil
	}
	s, err := dialSession(SocketPath(c.dir, idx), &c.opts)
	if err != nil {
		return nil, err
	}
	if s.workerIndex != idx {
		go s.destroy()
		return nil, errors.New("suritap: worker index mismatch")
	}
	c.slots[idx] = s
	return s, nil
}

// Open announces a new proxied connection.
func (c *Client) Open(p OpenParams) (*Conn, error) {
	cid := c.nextCID.Add(1)
	s, err := c.session(int(mix(cid) % uint64(len(c.slots))))
	if err != nil {
		return nil, err
	}
	body, err := encodeOpen(cid, &p)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.DialTimeout)
	defer cancel()
	if err := s.push(ctx, kOpen, 0, body); err != nil {
		return nil, err
	}
	conn := &Conn{s: s, cid: cid}
	// A Conn dropped without Close must not leak its flow in Suricata.
	conn.cleanup = runtime.AddCleanup(conn, func(c closeReq) { s.closeConn(c.cid, c.how) }, closeReq{cid: cid})
	return conn, nil
}

// Ping measures a round trip through worker idx without the engine.
func (c *Client) Ping(ctx context.Context, idx int) (time.Duration, error) {
	s, err := c.session(idx)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	_, err = s.request(ctx, func(token uint32) error {
		b := make([]byte, smallBody)
		binary.LittleEndian.PutUint32(b, token)
		return s.push(ctx, kPing, 0, b)
	})
	return time.Since(start), err
}

// Close tears down all sessions.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed.Store(true)
	slots := c.slots
	c.slots = make([]*session, len(slots))
	c.mu.Unlock()
	for _, s := range slots {
		if s != nil {
			s.destroy()
		}
	}
	return nil
}

// Conn is one proxied connection. It is safe for concurrent use, but
// payload of one direction must be sent in order.
type Conn struct {
	s       *session
	cid     uint64
	closed  atomic.Bool
	cleanup runtime.Cleanup
}

// CID is the connection id (logged in EVE as suritap.cid).
func (c *Conn) CID() uint64 { return c.cid }

// Worker is the index of the Suricata worker inspecting the connection.
func (c *Conn) Worker() int { return c.s.workerIndex }

func (c *Conn) sendChunks(ctx context.Context, dir Dir, data []byte) error {
	var h [dataFixed]byte
	for len(data) > 0 {
		n := min(len(data), c.s.maxPayload)
		dataHeader(&h, c.cid, dir, 0)
		if err := c.s.push(ctx, kData, 0, h[:], data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Send streams payload without waiting for a verdict (detect-only mode).
func (c *Conn) Send(ctx context.Context, dir Dir, data []byte) error {
	return c.sendChunks(ctx, dir, data)
}

// Inspect sends payload (possibly empty) and waits for the verdict that
// covers everything sent so far in dir.
func (c *Conn) Inspect(ctx context.Context, dir Dir, data []byte) (Verdict, error) {
	split := 0
	if len(data) > 0 {
		split = (len(data) - 1) / c.s.maxPayload * c.s.maxPayload
	}
	if err := c.sendChunks(ctx, dir, data[:split]); err != nil {
		return Verdict{}, err
	}
	last := data[split:]
	r, err := c.s.request(ctx, func(token uint32) error {
		var h [dataFixed]byte
		dataHeader(&h, c.cid, dir, token)
		return c.s.push(ctx, kData, fWantVerdict, h[:], last)
	})
	if err != nil {
		return Verdict{}, err
	}
	if r.pong {
		return Verdict{}, errors.New("suritap: unexpected reply")
	}
	return r.v, nil
}

// Gap reports n bytes of dir that were not sent (e.g. skipped under load).
func (c *Conn) Gap(ctx context.Context, dir Dir, n uint64) error {
	for n > 0 {
		k := uint32(min(n, 1<<32-1))
		if err := c.s.push(ctx, kGap, 0, small(c.cid, uint8(dir), k)); err != nil {
			return err
		}
		n -= uint64(k)
	}
	return nil
}

// EOF half-closes one direction.
func (c *Conn) EOF(ctx context.Context, dir Dir) error {
	return c.s.push(ctx, kEOF, 0, small(c.cid, uint8(dir), 0))
}

// Close ends the connection (FIN both ways, or RST when reset). It never
// blocks: when the ring is full the CLOSE is queued and sent as soon as
// there is room.
func (c *Conn) Close(reset bool) error {
	if c.closed.Swap(true) {
		return nil
	}
	c.cleanup.Stop()
	if c.s.dead.Load() {
		return ErrClosed
	}
	var how uint8
	if reset {
		how = 1
	}
	c.s.closeConn(c.cid, how)
	return nil
}

// Bypassed reports that Suricata needs no more payload of this connection.
func (c *Conn) Bypassed() bool {
	_, ok := c.s.bypassed.Load(c.cid)
	return ok
}

// FlowError returns the FLOW_ERROR code reported for the connection (0 if
// none): 1 duplicate id, 2 too many flows, 3 invalid OPEN.
func (c *Conn) FlowError() uint32 {
	if v, ok := c.s.flowErrors.Load(c.cid); ok {
		return v.(uint32)
	}
	return 0
}
