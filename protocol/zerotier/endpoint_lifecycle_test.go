//go:build with_zerotier && with_gvisor

package zerotier

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type closeSignalingPacketConn struct {
	fakePacketConn
	closed chan struct{}
}

func (c *closeSignalingPacketConn) Close() error {
	if c.fakePacketConn.closed.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return nil
}

func TestEndpointScopeCloseKeepsStackAliveUntilManagedCallbacksExit(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	scope := adapter.NewScope(ep.ctx, ep.logger)
	if err := scope.Start(ep.Tag(), ep, adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	if err := ep.createStack(); err != nil {
		t.Fatal(err)
	}
	stackBeforeClose := ep.ipStack
	udpConn := &closeSignalingPacketConn{closed: make(chan struct{})}
	ep.udpConn = udpConn

	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	ep.goManaged(func() {
		<-ep.done
		close(callbackEntered)
		<-releaseCallback
	})

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- scope.Close()
	}()
	<-callbackEntered

	select {
	case <-udpConn.closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not close the UDP socket")
	}
	if ep.ipStack != stackBeforeClose {
		close(releaseCallback)
		<-closeResult
		t.Fatal("Close destroyed the gVisor stack before managed callbacks exited")
	}

	close(releaseCallback)
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after managed callback exited")
	}
	if ep.ipStack != nil {
		t.Fatal("Close left the gVisor stack attached")
	}
}

func TestEndpointCloseRejectsNewNodeCalls(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	node := &fakeNode{}
	ep.node = node

	closeStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	ep.goManaged(func() {
		<-ep.done
		close(closeStarted)
		<-releaseCallback
	})

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- ep.Close()
	}()
	<-closeStarted

	ep.subscribeMulticastGroupOnNode(zeroTierBroadcastGroup, "subscribe")
	if calls := node.multicastSubscribeCalls(); len(calls) != 0 {
		close(releaseCallback)
		<-closeResult
		t.Fatalf("new Node call admitted after Close started: %v", calls)
	}

	close(releaseCallback)
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
}
