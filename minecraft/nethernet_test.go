package minecraft

import (
	"context"
	"testing"
)

func TestNetherNetNilSignaling(t *testing.T) {
	n := NetherNet{}
	if _, err := n.DialContext(context.Background(), "1"); err == nil {
		t.Fatal("DialContext succeeded with nil Signaling")
	}
	if _, err := n.Listen(""); err == nil {
		t.Fatal("Listen succeeded with nil Signaling")
	}
}
