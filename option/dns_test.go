package option

import (
	"context"
	"os"
	"reflect"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type stubDNSTransportOptionsRegistry struct{}

func (stubDNSTransportOptionsRegistry) OptionTypes() []string {
	return []string{C.DNSTypeUDP, C.DNSTypeFakeIP}
}

func (stubDNSTransportOptionsRegistry) CreateOptions(transportType string) (any, bool) {
	switch transportType {
	case C.DNSTypeUDP:
		return new(RemoteDNSServerOptions), true
	case C.DNSTypeFakeIP:
		return new(FakeIPDNSServerOptions), true
	default:
		return nil, false
	}
}

func TestDNSOptionsRejectsLegacyFakeIPOptions(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	var options DNSOptions
	err := json.UnmarshalContext(ctx, []byte(`{
		"fakeip": {
			"enabled": true,
			"inet4_range": "198.18.0.0/15"
		}
	}`), &options)
	require.EqualError(t, err, legacyDNSFakeIPRemovedMessage)
}

func TestDNSServerOptionsRejectsLegacyFormats(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	testCases := []string{
		`{"address":"1.1.1.1"}`,
		`{"type":"legacy","address":"1.1.1.1"}`,
	}
	for _, content := range testCases {
		var options DNSServerOptions
		err := json.UnmarshalContext(ctx, []byte(content), &options)
		require.EqualError(t, err, legacyDNSServerRemovedMessage)
	}
}

func TestDomainResolverJSON(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		input    string
		output   string
		server   string
		fallback string
	}{
		{"fixed string", `"fixed"`, `"fixed"`, "fixed", ""},
		{"fixed object", `{"server":"fixed"}`, `"fixed"`, "fixed", ""},
		{"fixed options", `{"server":"fixed","strategy":"ipv4_only","disable_cache":true}`, `{"server":"fixed","strategy":"ipv4_only","disable_cache":true}`, "fixed", ""},
		{"fallback", `{"fallback_server":"local"}`, `{"fallback_server":"local"}`, "", "local"},
		{"fallback options", `{"fallback_server":"local","timeout":"2s","strategy":"prefer_ipv4","disable_cache":true,"disable_optimistic_cache":true,"rewrite_ttl":60,"client_subnet":"192.0.2.0/24"}`, `{"fallback_server":"local","timeout":"2s","strategy":"prefer_ipv4","disable_cache":true,"disable_optimistic_cache":true,"rewrite_ttl":60,"client_subnet":"192.0.2.0/24"}`, "", "local"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var options DomainResolveOptions
			require.NoError(t, json.Unmarshal([]byte(testCase.input), &options))
			require.Equal(t, testCase.server, options.Server)
			require.Equal(t, testCase.fallback, options.FallbackServer)
			content, err := json.Marshal(options)
			require.NoError(t, err)
			require.JSONEq(t, testCase.output, string(content))
			var decoded DomainResolveOptions
			require.NoError(t, json.Unmarshal(content, &decoded))
			require.Equal(t, options, decoded)
		})
	}
}

func TestDomainResolverJSONRejectsInvalidSelection(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{}`,
		`{"fallback_server":""}`,
		`{"server":"fixed","fallback_server":"local"}`,
		`{"server":"","fallback_server":"local"}`,
		`{"server":"fixed","fallback_server":""}`,
	} {
		var options DomainResolveOptions
		require.Error(t, json.Unmarshal([]byte(content), &options), content)
	}
	_, err := json.Marshal(DomainResolveOptions{Server: "fixed", FallbackServer: "local"})
	require.ErrorContains(t, err, "mutually exclusive")
}

func TestDomainResolverGeneratedSchema(t *testing.T) {
	t.Parallel()
	generated, err := schema.Generate(context.Background(), reflect.TypeFor[DomainResolveOptions]())
	require.NoError(t, err)
	var generatedSchema struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(generated, &generatedSchema))
	published, err := os.ReadFile("../docs/schema.json")
	require.NoError(t, err)
	var publishedSchema struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(published, &publishedSchema))
	require.JSONEq(t, string(generatedSchema.Defs["DomainResolver"]), string(publishedSchema.Defs["DomainResolver"]))
	var resolver struct {
		AnyOf []struct {
			Properties map[string]struct {
				TagReference string `json:"x-tag-reference"`
			} `json:"properties"`
			OneOf []struct {
				Required []string `json:"required"`
			} `json:"oneOf"`
		} `json:"anyOf"`
	}
	require.NoError(t, json.Unmarshal(generatedSchema.Defs["DomainResolver"], &resolver))
	require.Len(t, resolver.AnyOf, 2)
	object := resolver.AnyOf[1]
	require.Equal(t, "dns_server", object.Properties["fallback_server"].TagReference)
	require.Len(t, object.OneOf, 2)
	require.Equal(t, []string{"server"}, object.OneOf[0].Required)
	require.Equal(t, []string{"fallback_server"}, object.OneOf[1].Required)
}
