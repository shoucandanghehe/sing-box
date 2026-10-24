package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type probeOutbound struct {
	outbound.Adapter
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (o *probeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, destination)
}

func (o *probeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type urlTestFixture struct {
	ctx      context.Context
	service  *StartedService
	client   StartedServiceClient
	nodes    map[string]*probeOutbound
	selector *group.Selector
}

func newURLTestFixture(t *testing.T) *urlTestFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	factory := log.NewNOPFactory()
	history := urltest.NewHistoryStorage()
	t.Cleanup(func() { require.NoError(t, history.Close()) })
	registry := outbound.NewRegistry()
	nodes := make(map[string]*probeOutbound)
	outbound.Register(registry, "probe", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		node := &probeOutbound{
			Adapter: outbound.NewAdapter("probe", tag, []string{N.NetworkTCP}, nil),
			dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				return nil, errors.New("unconfigured probe")
			},
		}
		nodes[tag] = node
		return node, nil
	})
	group.RegisterSelector(registry)
	endpoints := endpoint.NewManager(nil)
	manager := outbound.NewManager(registry, endpoints, "selector")
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWithPtr(ctx, history)
	for _, tag := range []string{"chosen", "other"} {
		require.NoError(t, manager.Create(ctx, nil, factory.Logger(), tag, "probe", nil))
	}
	require.NoError(t, manager.Create(ctx, nil, factory.Logger(), "selector", "selector", &option.SelectorOutboundOptions{
		Outbounds: []string{"chosen", "other"}, Default: "chosen",
	}))
	selected, loaded := manager.Outbound("selector")
	require.True(t, loaded)
	selector := selected.(*group.Selector)
	scope := adapter.NewScope(ctx, factory.Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, scope.Start("selector", selector, adapter.StartStateStart))

	updates := observable.NewSubscriber[struct{}](1)
	updateObserver := observable.NewObserver(updates, 1)
	t.Cleanup(func() { require.NoError(t, updateObserver.Close()) })
	statuses := observable.NewSubscriber[*ServiceStatus](1)
	statusObserver := observable.NewObserver(statuses, 1)
	t.Cleanup(func() { require.NoError(t, statusObserver.Close()) })
	history.AddUpdateHook(updates)
	started := &StartedService{
		ctx: ctx, serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		urlTestSubscriber: updates, urlTestObserver: updateObserver,
		serviceStatusSubscriber: statuses, serviceStatusObserver: statusObserver,
		instance: &Instance{
			ctx: ctx, outboundManager: manager, endpointManager: endpoints,
			urlTestHistoryStorage: history, logFactory: factory,
		},
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterStartedServiceServer(server, started)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		server.Stop()
		require.NoError(t, <-serveDone)
	})
	connection, err := grpc.NewClient("passthrough:///urltest",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	return &urlTestFixture{ctx: ctx, service: started, client: NewStartedServiceClient(connection), nodes: nodes, selector: selector}
}

func TestURLTestResultSubscriptions(t *testing.T) {
	fixture := newURLTestFixture(t)
	groups, err := fixture.client.SubscribeGroups(fixture.ctx, &emptypb.Empty{})
	require.NoError(t, err)
	initialGroups, err := groups.Recv()
	require.NoError(t, err)
	require.Len(t, initialGroups.Group, 1)
	require.True(t, initialGroups.Group[0].Selectable)
	require.Nil(t, initialGroups.Group[0].Items[0].UrlTestResult)
	outbounds, err := fixture.client.SubscribeOutbounds(fixture.ctx, &emptypb.Empty{})
	require.NoError(t, err)
	initialOutbounds, err := outbounds.Recv()
	require.NoError(t, err)
	require.Nil(t, initialOutbounds.Outbounds[0].UrlTestResult)

	for _, step := range []struct {
		name       string
		delay      uint16
		err        error
		success    bool
		history    bool
		invalidate bool
		errorText  string
	}{
		{name: "failure", err: errors.New("connection refused"), errorText: "connection refused"},
		{name: "failure to zero success", success: true, history: true},
		{name: "success to empty error failure", err: errors.New("")},
		{name: "maximum delay success", delay: 65535, success: true, history: true},
		{name: "connection failure invalidates only history", delay: 65535, success: true, invalidate: true},
	} {
		t.Run(step.name, func(t *testing.T) {
			storage := fixture.service.instance.urlTestHistoryStorage
			if step.invalidate {
				storage.DeleteURLTestHistory("chosen")
			} else {
				storage.StoreURLTestResult("chosen", step.delay, step.err)
			}
			groupSnapshot, err := groups.Recv()
			require.NoError(t, err)
			outboundSnapshot, err := outbounds.Recv()
			require.NoError(t, err)
			item := groupSnapshot.Group[0].Items[0]
			require.Equal(t, "chosen", item.Tag)
			require.NotNil(t, item.UrlTestResult)
			require.Equal(t, step.success, item.UrlTestResult.Success)
			require.Equal(t, int32(step.delay), item.UrlTestResult.Delay)
			require.Equal(t, step.errorText, item.UrlTestResult.Error)
			require.Equal(t, storage.LoadURLTestResult("chosen").Time.Unix(), item.UrlTestResult.Time)
			if step.history {
				require.Equal(t, item.UrlTestResult.Time, item.UrlTestTime)
				require.Equal(t, int32(step.delay), item.UrlTestDelay)
			} else {
				require.Zero(t, item.UrlTestTime)
				require.Zero(t, item.UrlTestDelay)
			}
			require.True(t, proto.Equal(item.UrlTestResult, outboundSnapshot.Outbounds[0].UrlTestResult))
			require.True(t, proto.Equal(item.UrlTestResult, outboundSnapshot.Outbounds[2].UrlTestResult))
			require.Nil(t, groupSnapshot.Group[0].Items[1].UrlTestResult)
			require.Equal(t, "chosen", groupSnapshot.Group[0].Selected)
			require.Equal(t, "chosen", fixture.selector.Now())
		})
	}
}

func TestURLTestAcceptsBeforeProbeCompletes(t *testing.T) {
	fixture := newURLTestFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.nodes["chosen"].dial = func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		close(entered)
		select {
		case <-release:
			return nil, errors.New("probe dial failed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	groups, err := fixture.client.SubscribeGroups(fixture.ctx, &emptypb.Empty{})
	require.NoError(t, err)
	_, err = groups.Recv()
	require.NoError(t, err)
	_, err = fixture.client.URLTest(fixture.ctx, &URLTestRequest{OutboundTag: "chosen"})
	require.NoError(t, err)
	select {
	case <-entered:
	case <-fixture.ctx.Done():
		t.Fatal(fixture.ctx.Err())
	}
	require.Nil(t, fixture.service.instance.urlTestHistoryStorage.LoadURLTestResult("chosen"))
	close(release)
	groupsAfter, err := groups.Recv()
	require.NoError(t, err)
	result := groupsAfter.Group[0].Items[0].UrlTestResult
	require.NotNil(t, result)
	require.False(t, result.Success)
	require.Equal(t, "probe dial failed", result.Error)
}

func TestURLTestBatchRecordsTransitionsWithoutSelecting(t *testing.T) {
	fixture := newURLTestFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	var failing atomic.Bool
	probeError := errors.New("probe dial failed")
	for tag, node := range fixture.nodes {
		node.dial = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if tag == "chosen" && failing.Load() {
				return nil, probeError
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, destination.String())
		}
	}
	storage := fixture.service.instance.urlTestHistoryStorage
	for _, fail := range []bool{true, false, true} {
		failing.Store(fail)
		delays := group.URLTestOutbounds(fixture.ctx, fixture.service.instance.outboundManager, storage,
			log.NewNOPFactory().Logger(), []adapter.Outbound{fixture.selector}, server.URL, 0, true)
		result := storage.LoadURLTestResult("chosen")
		require.NotNil(t, result)
		if fail {
			require.ErrorIs(t, result.Error, probeError)
			require.NotContains(t, delays, "chosen")
			require.Nil(t, storage.LoadURLTestHistory("chosen"))
		} else {
			require.NoError(t, result.Error)
			require.Contains(t, delays, "chosen")
			require.Equal(t, delays["chosen"], result.Delay)
			require.NotNil(t, storage.LoadURLTestHistory("chosen"))
		}
		require.Contains(t, delays, "other")
		require.NoError(t, storage.LoadURLTestResult("other").Error)
		require.Equal(t, "chosen", fixture.selector.Now())
	}
}
