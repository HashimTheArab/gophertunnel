package minecraft

import (
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestDialContextNilContext(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DialContext panicked with nil context: %v", r)
		}
	}()
	_, err := Dialer{}.DialContext(nil, "missing", "127.0.0.1:19132")
	if err == nil || !strings.Contains(err.Error(), "no network") {
		t.Fatalf("DialContext error = %v, want no network error", err)
	}
}

func TestHandleNetworkSettingsRejectsUnknownCompression(t *testing.T) {
	t.Parallel()

	conn := &Conn{}
	err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: 255})
	if err == nil || !strings.Contains(err.Error(), "unknown compression algorithm") {
		t.Fatalf("handleNetworkSettings error = %v, want unknown compression error", err)
	}
}

func TestReadChainIdentityDataRejectsShortChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "empty", data: `{"chain":[]}`},
		{name: "one entry", data: `{"chain":["root"]}`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := readChainIdentityData([]byte(tt.data)); err == nil {
				t.Fatal("expected short chain error")
			}
		})
	}
}
