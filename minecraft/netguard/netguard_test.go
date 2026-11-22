package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/wlynxg/anet"
)

func TestPublic(t *testing.T) {
	tests := []struct {
		addr   string
		public bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"100.63.255.255", true},
		{"100.128.0.0", true},
		{"172.15.255.255", true},
		{"172.32.0.0", true},
		{"2606:4700:4700::1111", true},
		{"2a01:4f8::1", true},
		{"::ffff:1.1.1.1", true},

		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"127.0.0.1", false},
		{"127.255.255.254", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"100.127.255.255", false},
		{"169.254.169.254", false},
		{"192.0.0.170", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"224.0.0.251", false},
		{"239.255.255.250", false},
		{"240.0.0.1", false},
		{"192.88.99.2", false},
		{"168.63.129.16", false},
		{"255.255.255.255", false},

		{"::", false},
		{"::1", false},
		{"::127.0.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:100.64.0.1", false},
		{"64:ff9b::a00:1", false},
		{"64:ff9b::7f00:1", false},
		{"64:ff9b::101:101", true},
		{"64:ff9b:1::1", false},
		{"100::1", false},
		{"2001::1", false},
		{"2001:db8::1", false},
		{"2002:a00:1::1", false},
		{"3fff::1", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		{"fe80::1", false},
		{"fe80::1%eth0", false},
		{"fec0::1", false},
		{"ff02::1", false},
		{"fd00:ec2::254", false},
	}
	for _, test := range tests {
		if got := Public(netip.MustParseAddr(test.addr)); got != test.public {
			t.Errorf("Public(%s) = %v, want %v", test.addr, got, test.public)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("Public(zero Addr) = true, want false")
	}
}

// The host's own addresses, its subnets' network and broadcast addresses, and Deny are refused even
// when public: with host networking they reach services listening on every interface.
func TestCheckRefusesHostAddresses(t *testing.T) {
	addrs, err := anet.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, assigned := range addrs {
		subnet, ok := assigned.(*net.IPNet)
		if !ok {
			continue
		}
		addr, _ := netip.AddrFromSlice(subnet.IP)
		refused := []netip.Addr{addr}
		if ones, bits := subnet.Mask.Size(); addr.Unmap().Is4() && bits == 32 && ones < 31 {
			prefix := netip.PrefixFrom(addr.Unmap(), ones).Masked()
			refused = append(refused, prefix.Addr(), lastAddr(prefix))
		}
		for _, addr := range refused {
			if (Policy{}).Check(addr) == nil {
				t.Errorf("Check(%s) allowed an address of this host's subnet %s", addr, subnet)
			}
		}
	}
	if local(netip.MustParseAddr("1.1.1.1")) {
		t.Error("local(1.1.1.1) = true")
	}
	deny := Policy{Deny: []netip.Prefix{netip.MustParsePrefix("203.0.114.7/32")}}
	if deny.Check(netip.MustParseAddr("203.0.114.7")) == nil || deny.Check(netip.MustParseAddr("::ffff:203.0.114.7")) == nil {
		t.Error("Check allowed a denied address")
	}
	if err := deny.Check(netip.MustParseAddr("1.1.1.1")); err != nil {
		t.Errorf("Check(1.1.1.1) = %v with an unrelated deny list", err)
	}
}

// A dialer with Control refuses a private destination, including one reached through a host name.
func TestControlRefusesResolvedPrivateAddress(t *testing.T) {
	dialer := &net.Dialer{Control: Policy{}.Control, Timeout: time.Second}
	addresses := []string{"127.0.0.1:19132", "localhost:19132", "[::ffff:127.0.0.1]:19132"}
	if probe, err := net.ListenPacket("udp6", "[::1]:0"); err == nil {
		_ = probe.Close()
		addresses = append(addresses, "[::1]:19132")
	}
	for _, address := range addresses {
		for _, network := range []string{"udp", "tcp"} {
			conn, err := dialer.DialContext(context.Background(), network, address)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("%s dial %s succeeded, want refusal", network, address)
			}
			if !errors.Is(err, ErrNotPublic) {
				t.Fatalf("%s dial %s error = %v, want ErrNotPublic", network, address, err)
			}
		}
	}
}

func TestHTTPTransportRefusesPrivateServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if response, err := (&http.Client{}).Get(server.URL); err != nil {
		t.Fatalf("control request: %v", err)
	} else {
		_ = response.Body.Close()
	}
	client := &http.Client{Transport: Policy{}.HTTPTransport()}
	response, err := client.Get(server.URL)
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("request to a loopback server succeeded, want refusal")
	}
	if !errors.Is(err, ErrNotPublic) {
		t.Fatalf("request error = %v, want ErrNotPublic", err)
	}
}

func TestHTTPTransportIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	if (Policy{}).HTTPTransport().Proxy != nil {
		t.Fatal("HTTPTransport uses a proxy, whose address would be checked in place of the server's")
	}
}
