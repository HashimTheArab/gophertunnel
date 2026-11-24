package minecraft

import (
	"sync"
	"time"
)

// testManualHolds and testDelayHolds give each Conn in this package's tests one manual hold and one delay
// hold, as a single owner of each would use them.
var testManualHolds, testDelayHolds sync.Map

// setPacketHold sets the Conn's test manual hold to keep what sel keeps, up to limit packets. A nil sel
// lets go of everything it keeps and stops holding.
func setPacketHold(conn *Conn, sel PacketSelector, limit int) error {
	h, _ := testManualHolds.LoadOrStore(conn, conn.NewPacketHold())
	return h.(*PacketHold).Set(PacketHoldRule{Select: sel, Limit: limit})
}

// setSendDelay sets the Conn's test delay hold to delay everything it sends by d.
func setSendDelay(conn *Conn, d time.Duration) error {
	h, _ := testDelayHolds.LoadOrStore(conn, conn.NewPacketHold())
	return h.(*PacketHold).Set(PacketHoldRule{Delay: d})
}
