package subscription

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestParseClashYAMLRelayGroup(t *testing.T) {
	content := `proxies:
  - name: hop-1
    type: ss
    server: 1.1.1.1
    port: 1001
    cipher: aes-128-gcm
    password: pass1
  - name: hop-2
    type: ss
    server: 2.2.2.2
    port: 1002
    cipher: aes-128-gcm
    password: pass2
proxy-groups:
  - name: relay-chain
    type: relay
    proxies:
      - hop-1
      - hop-2
`

	nodes, err := parseClashYAML(content)
	if err != nil {
		t.Fatalf("parseClashYAML returned error: %v", err)
	}

	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes (2 proxies + 1 relay), got %d", len(nodes))
	}

	uriByName := make(map[string]string, len(nodes))
	for _, node := range nodes {
		uriByName[node.Name] = node.URI
	}
	relayURI, ok := uriByName["relay-chain"]
	if !ok {
		t.Fatalf("relay node not found")
	}
	if !isProxyURI(relayURI) {
		t.Fatalf("relay uri not recognized as proxy uri: %s", relayURI)
	}

	parsed, err := url.Parse(relayURI)
	if err != nil {
		t.Fatalf("parse relay uri failed: %v", err)
	}
	hops := parsed.Query()["hop"]
	if len(hops) != 2 {
		t.Fatalf("expected 2 relay hops, got %d", len(hops))
	}

	decodedHop1, err := base64.RawURLEncoding.DecodeString(hops[0])
	if err != nil {
		t.Fatalf("decode first hop failed: %v", err)
	}
	decodedHop2, err := base64.RawURLEncoding.DecodeString(hops[1])
	if err != nil {
		t.Fatalf("decode second hop failed: %v", err)
	}

	if string(decodedHop1) != uriByName["hop-1"] {
		t.Fatalf("first hop mismatch: got %q want %q", string(decodedHop1), uriByName["hop-1"])
	}
	if string(decodedHop2) != uriByName["hop-2"] {
		t.Fatalf("second hop mismatch: got %q want %q", string(decodedHop2), uriByName["hop-2"])
	}
}
