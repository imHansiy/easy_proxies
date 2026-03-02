package builder

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestBuildRelayChainOutbounds(t *testing.T) {
	hop1 := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass1")) + "@1.1.1.1:1001#hop1"
	hop2 := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass2")) + "@2.2.2.2:1002#hop2"

	query := url.Values{}
	query.Add("hop", base64.RawURLEncoding.EncodeToString([]byte(hop1)))
	query.Add("hop", base64.RawURLEncoding.EncodeToString([]byte(hop2)))
	relayURI := "relay://chain?" + query.Encode()

	final, auxiliary, err := buildRelayChainOutbounds("relay-node", relayURI, false)
	if err != nil {
		t.Fatalf("buildRelayChainOutbounds returned error: %v", err)
	}

	if len(auxiliary) != 1 {
		t.Fatalf("expected 1 auxiliary outbound, got %d", len(auxiliary))
	}
	if auxiliary[0].Tag != "relay-node-hop-1" {
		t.Fatalf("unexpected auxiliary tag: %s", auxiliary[0].Tag)
	}
	if final.Tag != "relay-node" {
		t.Fatalf("unexpected final tag: %s", final.Tag)
	}

	if got := outboundDetour(t, auxiliary[0]); got != "" {
		t.Fatalf("expected first hop detour to be empty, got %q", got)
	}
	if got := outboundDetour(t, final); got != auxiliary[0].Tag {
		t.Fatalf("expected final hop detour %q, got %q", auxiliary[0].Tag, got)
	}
}

func TestBuildRelayChainOutboundsRequiresTwoHops(t *testing.T) {
	hop := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass1")) + "@1.1.1.1:1001#hop1"
	query := url.Values{}
	query.Add("hop", base64.RawURLEncoding.EncodeToString([]byte(hop)))
	relayURI := "relay://chain?" + query.Encode()

	_, _, err := buildRelayChainOutbounds("relay-node", relayURI, false)
	if err == nil {
		t.Fatalf("expected error for single-hop relay, got nil")
	}
	if !strings.Contains(err.Error(), "at least two") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func outboundDetour(t *testing.T, outbound option.Outbound) string {
	t.Helper()
	wrapper, ok := outbound.Options.(option.DialerOptionsWrapper)
	if !ok {
		t.Fatalf("outbound %s does not implement DialerOptionsWrapper", outbound.Type)
	}
	return wrapper.TakeDialerOptions().Detour
}
