package libbox

import (
	"testing"

	"github.com/sagernet/sing-box/daemon"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestOutboundURLTestResultFromGRPC(t *testing.T) {
	for _, test := range []struct {
		name   string
		result *daemon.URLTestResult
		want   *URLTestResult
	}{
		{name: "untested"},
		{
			name:   "successful zero milliseconds",
			result: &daemon.URLTestResult{Time: 1729000000, Success: true},
			want:   &URLTestResult{Time: 1729000000, Success: true},
		},
		{
			name:   "successful maximum delay",
			result: &daemon.URLTestResult{Time: 1729000001, Delay: 65535, Success: true},
			want:   &URLTestResult{Time: 1729000001, Delay: 65535, Success: true},
		},
		{
			name:   "failed",
			result: &daemon.URLTestResult{Time: 1729000002, Error: "connection refused"},
			want:   &URLTestResult{Time: 1729000002, Error: "connection refused"},
		},
		{
			name:   "failed with empty error",
			result: &daemon.URLTestResult{Time: 1729000003},
			want:   &URLTestResult{Time: 1729000003},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := &daemon.GroupItem{
				Tag: "node", Type: "test", UrlTestTime: 101, UrlTestDelay: 23,
				UrlTestResult: test.result,
			}
			wire, err := proto.Marshal(&daemon.Groups{Group: []*daemon.Group{{Tag: "selector", Items: []*daemon.GroupItem{item}}}})
			require.NoError(t, err)
			var groups daemon.Groups
			require.NoError(t, proto.Unmarshal(wire, &groups))
			groupItem := outboundGroupIteratorFromGRPC(&groups).Next().GetItems().Next()
			require.Equal(t, test.want, groupItem.URLTestResult)
			require.Equal(t, int64(101), groupItem.URLTestTime)
			require.Equal(t, int32(23), groupItem.URLTestDelay)

			wire, err = proto.Marshal(&daemon.OutboundList{Outbounds: []*daemon.GroupItem{item}})
			require.NoError(t, err)
			var outbounds daemon.OutboundList
			require.NoError(t, proto.Unmarshal(wire, &outbounds))
			outboundItem := outboundGroupItemListFromGRPC(&outbounds).Next()
			require.Equal(t, groupItem, outboundItem)
		})
	}
}
