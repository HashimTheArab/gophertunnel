package messaging

import (
	"testing"

	"github.com/google/uuid"
)

func TestConnNetworkIDReturnsConfiguredNetherNetID(t *testing.T) {
	playerMessagingID := uuid.MustParse("01890fa5-bae8-735c-99dc-29f89c4830bd")
	conn := &Conn{
		d:    Dialer{NetworkID: "12345"},
		pmid: playerMessagingID,
	}

	if got, want := conn.NetworkID(), "12345"; got != want {
		t.Fatalf("NetworkID() = %q, want configured NetherNet ID %q", got, want)
	}
}
