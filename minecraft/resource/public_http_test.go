package resource

import (
	"net/http"
	"net/url"
	"testing"
)

// TestPublicHTTPClient_AddressPolicy covers resolved addresses without network I/O.
func TestPublicHTTPClient_AddressPolicy(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "100.64.0.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443", "[fc00::1]:443", "[fe80::1]:443", "198.18.0.1:443", "198.19.255.255:443", "192.0.2.1:443", "198.51.100.1:443", "203.0.113.1:443", "240.0.0.1:443", "0.1.2.3:443", "192.0.0.8:443", "[2001:2::1]:443", "[2001:db8::1]:443", "[3fff::1]:443", "[5f00::1]:443", "[64:ff9b:1::1]:443", "[64:ff9b::7f00:1]:443", "192.88.99.2:443", "[100::1]:443", "[100:0:0:1::1]:443", "[2002:808:808::1]:443", "[2001:db8::1%eth0]:443"} {
		if err := dialPublicOnly("tcp", address, nil); err == nil {
			t.Errorf("allowed %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1:443", "192.0.0.9:443", "192.0.0.10:443", "[2001:4860:4860::8888]:443", "[2606:4700:4700::1111]:443", "[2001:1::1]:443", "[2001:1::2]:443", "[2001:1::3]:443", "[2001:3::1]:443", "[2001:4:112::1]:443", "[2001:20::1]:443", "[2001:30::1]:443", "[64:ff9b::101:101]:443", "[::ffff:1.1.1.1]:443"} {
		if err := dialPublicOnly("tcp", address, nil); err != nil {
			t.Errorf("rejected public %s: %v", address, err)
		}
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
