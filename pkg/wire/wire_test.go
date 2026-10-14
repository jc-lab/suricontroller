package wire

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

func sessions(t *testing.T) (client, server *yamux.Session) {
	t.Helper()
	a, b := net.Pipe()
	var err error
	client, err = yamux.Client(a, YamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	server, err = yamux.Server(b, YamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return
}

func TestStreamHeaderAndMessages(t *testing.T) {
	cs, ss := sessions(t)
	type accepted struct {
		ms  *MsgStream
		hdr *agentv1.StreamHeader
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		ms, hdr, err := AcceptStream(ss, 0)
		ch <- accepted{ms, hdr, err}
	}()
	ms, err := OpenStream(cs, &agentv1.StreamHeader{Type: agentv1.StreamType_STREAM_TYPE_LOGS}, 0)
	if err != nil {
		t.Fatal(err)
	}
	acc := <-ch
	if acc.err != nil {
		t.Fatal(acc.err)
	}
	if acc.hdr.Type != agentv1.StreamType_STREAM_TYPE_LOGS {
		t.Fatalf("header type = %v", acc.hdr.Type)
	}
	for i := range 3 {
		if err := ms.Send(&agentv1.LogBatch{Seq: uint64(i), RecordCount: 7}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		var b agentv1.LogBatch
		if err := acc.ms.Recv(&b); err != nil {
			t.Fatal(err)
		}
		if b.Seq != uint64(i) || b.RecordCount != 7 {
			t.Fatalf("got %+v", &b)
		}
	}
	ms.Close()
	var b agentv1.LogBatch
	if err := acc.ms.Recv(&b); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestMessageTooLarge(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	small := NewMsgStream(a, 16)
	if err := small.Send(&agentv1.Error{Message: "this message is longer than sixteen bytes"}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("send err = %v", err)
	}
	big := NewMsgStream(a, 0)
	recv := NewMsgStream(b, 16)
	go big.Send(&agentv1.Error{Message: "this message is longer than sixteen bytes"})
	if err := recv.Recv(&agentv1.Error{}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("recv err = %v", err)
	}
}

func TestPeerCallNotify(t *testing.T) {
	a, b := net.Pipe()
	notified := make(chan *agentv1.Envelope, 1)
	server := NewPeer(NewMsgStream(b, 0), func(ctx context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
		switch {
		case env.GetHello() != nil:
			return &agentv1.Envelope{Body: &agentv1.Envelope_HelloAck{HelloAck: &agentv1.HelloAck{ControllerVersion: "v-test"}}}, nil
		case env.GetStatus() != nil:
			notified <- env
			return nil, nil
		case env.GetApplyReport() != nil:
			return nil, &RemoteError{Code: "bad", Message: "nope"}
		}
		return nil, nil
	})
	client := NewPeer(NewMsgStream(a, 0), func(ctx context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
		return nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Run(ctx)
	go client.Run(ctx)

	reply, err := client.Call(ctx, &agentv1.Envelope{Body: &agentv1.Envelope_Hello{Hello: &agentv1.Hello{NodeId: "n1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if reply.GetHelloAck().GetControllerVersion() != "v-test" {
		t.Fatalf("reply = %v", reply)
	}

	_, err = client.Call(ctx, &agentv1.Envelope{Body: &agentv1.Envelope_ApplyReport{ApplyReport: &agentv1.ApplyReport{}}})
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != "bad" {
		t.Fatalf("err = %v", err)
	}

	if err := client.Notify(&agentv1.Envelope{Body: &agentv1.Envelope_Status{Status: &agentv1.StatusReport{TimeUnixMs: 42}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case env := <-notified:
		if env.GetStatus().TimeUnixMs != 42 {
			t.Fatal("wrong notification")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notification not delivered")
	}

	// Pending calls fail once the peer closes.
	callErr := make(chan error, 1)
	go func() {
		_, err := client.Call(context.Background(), &agentv1.Envelope{Body: &agentv1.Envelope_Ack{Ack: &agentv1.Ack{}}})
		callErr <- err
	}()
	server.Close()
	select {
	case err := <-callErr:
		if err == nil {
			// The reply may have raced ahead of the close; that is fine too.
			break
		}
		if !errors.Is(err, ErrPeerClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("call err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not return after close")
	}
}
