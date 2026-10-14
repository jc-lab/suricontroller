// Package wire implements stream multiplexing and message framing on top of
// the secure channel: yamux sessions, uvarint length-prefixed protobuf
// messages, and a small request/notification RPC for the control stream.
package wire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

const (
	// Subprotocol is the WebSocket subprotocol of the agent endpoint.
	Subprotocol = "suricontroller.v1"
	// AgentPath is the default HTTP path of the agent endpoint.
	AgentPath = "/agent/v1/connect"
	// MaxClockSkew bounds the handshake timestamp difference.
	MaxClockSkew = 5 * time.Minute
)

// DefaultMaxMessageSize limits a single framed message.
const DefaultMaxMessageSize = 8 << 20

// ErrMessageTooLarge is returned when a frame exceeds the stream limit.
var ErrMessageTooLarge = errors.New("wire: message too large")

// YamuxConfig returns the yamux configuration shared by both peers.
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.StreamOpenTimeout = 30 * time.Second
	cfg.MaxStreamWindowSize = 1 << 20
	cfg.LogOutput = io.Discard
	return cfg
}

// MsgStream sends and receives length-prefixed protobuf messages over a
// stream. Send is safe for concurrent use; Recv must be called from a single
// goroutine.
type MsgStream struct {
	conn net.Conn
	r    *bufio.Reader
	max  int

	wmu  sync.Mutex
	wbuf []byte
	rbuf []byte
}

// NewMsgStream wraps conn. maxSize <= 0 selects DefaultMaxMessageSize.
func NewMsgStream(conn net.Conn, maxSize int) *MsgStream {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return &MsgStream{conn: conn, r: bufio.NewReader(conn), max: maxSize}
}

// Conn returns the underlying stream.
func (s *MsgStream) Conn() net.Conn { return s.conn }

// Reader returns the buffered reader used by Recv. Use it to read raw bytes
// that follow framed messages (blob streams).
func (s *MsgStream) Reader() io.Reader { return s.r }

// Send writes one message.
func (s *MsgStream) Send(m proto.Message) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	size := proto.Size(m)
	if size > s.max {
		return ErrMessageTooLarge
	}
	buf := binary.AppendUvarint(s.wbuf[:0], uint64(size))
	buf, err := proto.MarshalOptions{}.MarshalAppend(buf, m)
	if err != nil {
		return err
	}
	s.wbuf = buf[:0]
	_, err = s.conn.Write(buf)
	return err
}

// Recv reads one message into m.
func (s *MsgStream) Recv(m proto.Message) error {
	n, err := binary.ReadUvarint(s.r)
	if err != nil {
		return err
	}
	if n > uint64(s.max) {
		return ErrMessageTooLarge
	}
	if cap(s.rbuf) < int(n) {
		s.rbuf = make([]byte, n)
	}
	buf := s.rbuf[:n]
	if _, err := io.ReadFull(s.r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return proto.Unmarshal(buf, m)
}

// Close closes the underlying stream.
func (s *MsgStream) Close() error { return s.conn.Close() }

// OpenStream opens a new yamux stream and sends its header.
func OpenStream(sess *yamux.Session, hdr *agentv1.StreamHeader, maxSize int) (*MsgStream, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	ms := NewMsgStream(st, maxSize)
	if err := ms.Send(hdr); err != nil {
		st.Close()
		return nil, fmt.Errorf("wire: send stream header: %w", err)
	}
	return ms, nil
}

// AcceptStream accepts the next yamux stream and reads its header.
func AcceptStream(sess *yamux.Session, maxSize int) (*MsgStream, *agentv1.StreamHeader, error) {
	st, err := sess.AcceptStream()
	if err != nil {
		return nil, nil, err
	}
	ms := NewMsgStream(st, maxSize)
	_ = st.SetReadDeadline(time.Now().Add(30 * time.Second))
	hdr := &agentv1.StreamHeader{}
	if err := ms.Recv(hdr); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("wire: read stream header: %w", err)
	}
	_ = st.SetReadDeadline(time.Time{})
	return ms, hdr, nil
}
