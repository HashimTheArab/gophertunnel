package minecraft

import "bytes"

const maxRetainedPacketBufferCap = 1 << 20

// packetQueue holds immutable packet frames backed by one reusable per-flush arena.
type packetQueue struct {
	packets [][]byte
	buffer  bytes.Buffer
}

// appendCopy snapshots packet into the queue's arena.
func (q *packetQueue) appendCopy(packet []byte) {
	start := q.buffer.Len()
	_, _ = q.buffer.Write(packet)
	q.appendRange(start)
}

// appendRange retains the bytes written since start as one immutable packet frame.
func (q *packetQueue) appendRange(start int) {
	data := q.buffer.Bytes()
	q.packets = append(q.packets, data[start:len(data):len(data)])
}

// reset releases packet references and prepares the arena for another flush.
func (q *packetQueue) reset() {
	clear(q.packets)
	q.packets = q.packets[:0]
	if q.buffer.Cap() > maxRetainedPacketBufferCap {
		q.buffer = bytes.Buffer{}
		return
	}
	q.buffer.Reset()
}
