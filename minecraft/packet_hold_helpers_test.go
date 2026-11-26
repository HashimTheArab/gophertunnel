package minecraft

import (
	"sync"
	"testing"
	"time"
)

// testManualHolds and testDelayHolds give each Conn in this package's tests one manual hold and one delay
// hold, as a single owner of each would use them.
var testManualHolds, testDelayHolds sync.Map

// setPacketHold sets the Conn's test manual hold to keep what sel keeps, up to limit packets, then
// flushes what that lets go of, as a caller owning the batch boundary would. A nil sel lets go of
// everything it keeps and stops holding.
func setPacketHold(conn *Conn, sel PacketSelector, limit int) error {
	h, _ := testManualHolds.LoadOrStore(conn, conn.NewPacketHold())
	if err := h.(*PacketHold).Set(PacketHoldRule{Select: sel, Limit: limit}); err != nil {
		return err
	}
	return conn.Flush()
}

// setSendDelay sets the Conn's test delay hold to delay everything it sends by d.
func setSendDelay(conn *Conn, d time.Duration) error {
	h, _ := testDelayHolds.LoadOrStore(conn, conn.NewPacketHold())
	return h.(*PacketHold).Set(PacketHoldRule{Delay: d})
}

// mustFlush flushes conn, as the owner of its batch boundary does after a hold lets go of packets.
func mustFlush(t *testing.T, conn *Conn) {
	t.Helper()
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}
