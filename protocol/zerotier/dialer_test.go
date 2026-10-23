//go:build with_zerotier && with_gvisor

package zerotier

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestDialerRejectsNewCallsAfterCloseStarts(t *testing.T) {
	destination := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 53}
	tests := []struct {
		name string
		call func(*Endpoint) (ioCloser, error)
	}{
		{
			name: "DialContext",
			call: func(ep *Endpoint) (ioCloser, error) {
				return ep.DialContext(context.Background(), N.NetworkUDP, destination)
			},
		},
		{
			name: "ListenPacket",
			call: func(ep *Endpoint) (ioCloser, error) {
				return ep.ListenPacket(context.Background(), destination)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep := newTestEndpoint(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
			if err := ep.createStack(); err != nil {
				t.Fatal(err)
			}

			closeStarted := make(chan struct{})
			releaseClose := make(chan struct{})
			ep.goManaged(func() {
				<-ep.done
				close(closeStarted)
				<-releaseClose
			})
			closeResult := make(chan error, 1)
			go func() {
				closeResult <- ep.Close()
			}()
			<-closeStarted

			resource, err := test.call(ep)
			if resource != nil {
				_ = resource.Close()
			}
			if err == nil {
				close(releaseClose)
				<-closeResult
				t.Fatal("call succeeded after Close started")
			}
			if !isClosedError(err) {
				close(releaseClose)
				<-closeResult
				t.Fatalf("error = %v, want net.ErrClosed", err)
			}

			close(releaseClose)
			if err := <-closeResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type ioCloser interface {
	Close() error
}

func isClosedError(err error) bool {
	return err == net.ErrClosed
}

type blockingInfoContextLogger struct {
	logger.ContextLogger
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (l *blockingInfoContextLogger) InfoContext(context.Context, ...any) {
	l.once.Do(func() {
		close(l.entered)
	})
	<-l.release
}

func TestEndpointCloseWaitsForEnteredDial(t *testing.T) {
	loggerEntered := make(chan struct{})
	releaseLogger := make(chan struct{})
	blockingLogger := &blockingInfoContextLogger{
		ContextLogger: logger.NOP(),
		entered:       loggerEntered,
		release:       releaseLogger,
	}
	endpoint, err := NewEndpoint(context.Background(), nil, blockingLogger, "dial-close-wait", option.ZeroTierEndpointOptions{
		NetworkID: "0123456789abcdef",
		Address:   []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	ep := endpoint.(*Endpoint)
	if err := ep.createStack(); err != nil {
		t.Fatal(err)
	}
	udpConn := &closeSignalingPacketConn{closed: make(chan struct{})}
	ep.udpConn = udpConn

	dialResult := make(chan error, 1)
	go func() {
		conn, err := ep.DialContext(context.Background(), N.NetworkUDP, M.Socksaddr{
			Addr: netip.MustParseAddr("192.0.2.1"),
			Port: 53,
		})
		if conn != nil {
			_ = conn.Close()
		}
		dialResult <- err
	}()
	<-loggerEntered

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- ep.Close()
	}()
	<-udpConn.closed
	select {
	case err := <-closeResult:
		close(releaseLogger)
		t.Fatalf("Close returned before entered DialContext completed: %v", err)
	default:
	}

	close(releaseLogger)
	if err := <-dialResult; err != nil {
		t.Fatalf("entered DialContext failed: %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
}
