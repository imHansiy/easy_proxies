package config

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestParseClashYAMLNestedRelayGroup(t *testing.T) {
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
  - name: hop-3
    type: ss
    server: 3.3.3.3
    port: 1003
    cipher: aes-128-gcm
    password: pass3
proxy-groups:
  - name: relay-inner
    type: relay
    proxies:
      - hop-1
      - hop-2
  - name: relay-outer
    type: relay
    proxies:
      - relay-inner
      - hop-3
`

	nodes, err := parseClashYAML(content)
	if err != nil {
		t.Fatalf("parseClashYAML returned error: %v", err)
	}

	if len(nodes) != 5 {
		t.Fatalf("expected 5 nodes (3 proxies + 2 relay), got %d", len(nodes))
	}

	uriByName := make(map[string]string, len(nodes))
	for _, node := range nodes {
		uriByName[node.Name] = node.URI
	}

	outerURI, ok := uriByName["relay-outer"]
	if !ok {
		t.Fatalf("relay-outer node not found")
	}
	if !isProxyURI(outerURI) {
		t.Fatalf("relay uri not recognized as proxy uri: %s", outerURI)
	}

	parsed, err := url.Parse(outerURI)
	if err != nil {
		t.Fatalf("parse relay uri failed: %v", err)
	}
	hops := parsed.Query()["hop"]
	if len(hops) != 3 {
		t.Fatalf("expected 3 relay hops, got %d", len(hops))
	}

	decoded := make([]string, 0, len(hops))
	for idx, hop := range hops {
		raw, err := base64.RawURLEncoding.DecodeString(hop)
		if err != nil {
			t.Fatalf("decode hop %d failed: %v", idx+1, err)
		}
		decoded = append(decoded, string(raw))
	}

	if decoded[0] != uriByName["hop-1"] {
		t.Fatalf("first hop mismatch: got %q want %q", decoded[0], uriByName["hop-1"])
	}
	if decoded[1] != uriByName["hop-2"] {
		t.Fatalf("second hop mismatch: got %q want %q", decoded[1], uriByName["hop-2"])
	}
	if decoded[2] != uriByName["hop-3"] {
		t.Fatalf("third hop mismatch: got %q want %q", decoded[2], uriByName["hop-3"])
	}
}
