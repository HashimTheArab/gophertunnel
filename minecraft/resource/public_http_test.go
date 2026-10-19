package resource

import (
	"net/http"
	"net/url"
	"testing"
)

// TestPublicHTTPClient_AddressPolicy covers resolved addresses without network I/O.
func TestPublicHTTPClient_AddressPolicy(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "100.64.0.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443", "[fc00::1]:443", "[fe80::1]:443"} {
		if err := dialPublicOnly("tcp", address, nil); err == nil {
			t.Errorf("allowed %s", address)
		}
	}
	if err := dialPublicOnly("tcp", "1.1.1.1:443", nil); err != nil {
		t.Fatal(err)
	}
	client := NewPublicHTTPClient()
	if _, err := client.Get("http://127.0.0.1/pack"); err == nil {
		t.Fatal("allowed plaintext URL")
	}
	if _, err := client.Get("https://127.0.0.1/pack"); err == nil {
		t.Fatal("allowed loopback HTTPS URL")
	}
	for _, target := range []string{"http://example.com/pack", "file:///pack"} {
		u, _ := url.Parse(target)
		if err := client.CheckRedirect(&http.Request{URL: u}, nil); err == nil {
			t.Errorf("allowed redirect to %s", target)
		}
	}
	u, _ := url.Parse("https://example.com/pack")
	if err := client.CheckRedirect(&http.Request{URL: u}, make([]*http.Request, 5)); err == nil {
		t.Fatal("redirect limit ignored")
	}
}
