package minecraft

import (
	"testing"
	"time"
)

// testHold returns the Conn's hold in slot, or a new one if no hold holds that way.
func testHold(conn *Conn, slot **PacketHold) *PacketHold {
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if *slot != nil {
		return *slot
	}
	return conn.NewPacketHold()
}

// setPacketHold sets the Conn's manual hold to keep what sel keeps, up to limit packets, then flushes what
// that lets go of, as a caller owning the batch boundary would. A nil sel lets go of everything and stops.
func setPacketHold(conn *Conn, sel PacketSelector, limit int) error {
	if err := testHold(conn, &conn.holds.manual).Set(PacketHoldRule{Select: sel, Limit: limit}); err != nil {
		return err
	}
	return conn.Flush()
}

// setSendDelay sets the Conn's delay hold to delay everything it sends by d.
func setSendDelay(conn *Conn, d time.Duration) error {
	return testHold(conn, &conn.holds.delayed).Set(PacketHoldRule{Delay: d})
}

// mustFlush flushes conn, as the owner of its batch boundary does after a hold lets go of packets.
func mustFlush(t *testing.T, conn *Conn) {
	t.Helper()
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}
