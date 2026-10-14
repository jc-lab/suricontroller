package wire

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

// ErrPeerClosed is returned by Call and Notify after the peer stopped.
var ErrPeerClosed = errors.New("wire: peer closed")

// RemoteError is an Error envelope returned by the remote handler.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("remote error %s: %s", e.Code, e.Message)
}

// Handler processes an incoming request or notification. It runs on the
// peer's read loop, so it must not block for long and must not call
// Peer.Call. For requests (env.Id != 0) the returned envelope body is sent as
// the reply; a nil envelope is replied to with Ack. Returned errors are
// replied to as Error envelopes (and ignored for notifications).
type Handler func(ctx context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error)

// Peer runs request/notification RPC over a control MsgStream.
type Peer struct {
	s       *MsgStream
	handler Handler
	nextID  atomic.Uint64

	mu      sync.Mutex
	waiting map[uint64]chan *agentv1.Envelope
	closed  bool
	done    chan struct{}
	err     error
}

// NewPeer creates a peer. Call Run to start processing incoming messages.
func NewPeer(s *MsgStream, h Handler) *Peer {
	return &Peer{s: s, handler: h, waiting: map[uint64]chan *agentv1.Envelope{}, done: make(chan struct{})}
}

// Run reads messages until the stream fails or ctx is cancelled. It always
// returns a non-nil error.
func (p *Peer) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { p.s.Close() })
	defer stop()
	var err error
	for {
		env := &agentv1.Envelope{}
		if err = p.s.Recv(env); err != nil {
			break
		}
		if env.ReplyTo != 0 {
			p.deliver(env)
			continue
		}
		reply, herr := p.handler(ctx, env)
		if env.Id == 0 {
			continue
		}
		if herr != nil {
			reply = &agentv1.Envelope{Body: &agentv1.Envelope_Error{Error: toProtoError(herr)}}
		} else if reply == nil {
			reply = &agentv1.Envelope{Body: &agentv1.Envelope_Ack{Ack: &agentv1.Ack{}}}
		}
		reply.Id = 0
		reply.ReplyTo = env.Id
		if err = p.s.Send(reply); err != nil {
			break
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	p.shutdown(err)
	return err
}

func toProtoError(err error) *agentv1.Error {
	var re *RemoteError
	if errors.As(err, &re) {
		return &agentv1.Error{Code: re.Code, Message: re.Message}
	}
	return &agentv1.Error{Code: "internal", Message: err.Error()}
}

func (p *Peer) deliver(env *agentv1.Envelope) {
	p.mu.Lock()
	ch, ok := p.waiting[env.ReplyTo]
	delete(p.waiting, env.ReplyTo)
	p.mu.Unlock()
	if ok {
		ch <- env
	}
}

func (p *Peer) shutdown(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.err = err
	for id, ch := range p.waiting {
		close(ch)
		delete(p.waiting, id)
	}
	close(p.done)
	p.s.Close()
}

// Done is closed when the peer stops.
func (p *Peer) Done() <-chan struct{} { return p.done }

// Err returns the error that stopped the peer, if any.
func (p *Peer) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Close stops the peer.
func (p *Peer) Close() error {
	p.shutdown(ErrPeerClosed)
	return nil
}

// Notify sends a message that expects no reply.
func (p *Peer) Notify(env *agentv1.Envelope) error {
	select {
	case <-p.done:
		return ErrPeerClosed
	default:
	}
	env.Id, env.ReplyTo = 0, 0
	return p.s.Send(env)
}

// Call sends a request and waits for its reply. Error replies are returned as
// *RemoteError.
func (p *Peer) Call(ctx context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
	id := p.nextID.Add(1)
	ch := make(chan *agentv1.Envelope, 1)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPeerClosed
	}
	p.waiting[id] = ch
	p.mu.Unlock()

	env.Id, env.ReplyTo = id, 0
	if err := p.s.Send(env); err != nil {
		p.mu.Lock()
		delete(p.waiting, id)
		p.mu.Unlock()
		return nil, err
	}
	select {
	case reply, ok := <-ch:
		if !ok {
			return nil, ErrPeerClosed
		}
		if e := reply.GetError(); e != nil {
			return nil, &RemoteError{Code: e.Code, Message: e.Message}
		}
		return reply, nil
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.waiting, id)
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}
