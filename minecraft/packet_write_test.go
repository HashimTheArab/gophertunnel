package minecraft

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetWriteConn routes encoded batches to a test-controlled synchronous writer.
type packetWriteConn struct {
	benchmarkConn
	write func([]byte) (int, error)
}

// Write invokes the transport behavior selected by the test.
func (c packetWriteConn) Write(b []byte) (int, error) { return c.write(b) }

// newPacketWriteConn builds a connection without a background flush ticker.
func newPacketWriteConn(write func([]byte) (int, error)) *Conn {
	return newConn(packetWriteConn{write: write}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
}

// packetWriteBytes independently serializes a packet for wire comparisons.
func packetWriteBytes(pk packet.Packet) []byte {
	var buf bytes.Buffer
	hdr := packet.Header{PacketID: pk.ID()}
	_ = hdr.Write(&buf)
	pk.Marshal(protocol.NewWriter(&buf, 0))
	return buf.Bytes()
}

// decodeWrittenBatch splits a captured batch into owned packet bytes.
func decodeWrittenBatch(t *testing.T, batch []byte) [][]byte {
	t.Helper()
	packets, err := packet.NewDecoder(bytes.NewReader(batch)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

// TestWritePacketQueueOwnsMarshalingAcrossGrowth checks mixed owned and borrowed packets.
func TestWritePacketQueueOwnsMarshalingAcrossGrowth(t *testing.T) {
	var output bytes.Buffer
	conn := newPacketWriteConn(output.Write)
	defer conn.Abort()
	first := &packet.Unknown{PacketID: 777, Payload: bytes.Repeat([]byte{1}, 8)}
	last := &packet.Unknown{PacketID: 779, Payload: bytes.Repeat([]byte{3}, 64*1024)}
	borrowed := packetWriteBytes(&packet.Unknown{PacketID: 778, Payload: []byte{2, 2}})
	want := [][]byte{packetWriteBytes(first), bytes.Clone(borrowed), packetWriteBytes(last)}
	if err := conn.WritePacket(first); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(borrowed); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacket(last); err != nil {
		t.Fatal(err)
	}
	clear(first.Payload)
	clear(last.Payload)
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	got := decodeWrittenBatch(t, output.Bytes())
	if len(got) != len(want) {
		t.Fatalf("got %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d changed after queue growth or caller scratch reuse", i)
		}
	}
	// Borrowed storage must remain the caller's even after the pool is reused.
	if err := conn.WritePacket(&packet.Unknown{PacketID: 780, Payload: bytes.Repeat([]byte{4}, 64*1024)}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, want[1]) {
		t.Fatal("reusing the queue modified borrowed Write storage")
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestWritePacketQueueReleasesAfterEncodeFailure covers both send paths and prevents stale retries.
func TestWritePacketQueueReleasesAfterEncodeFailure(t *testing.T) {
	for _, direct := range []bool{false, true} {
		name := "buffered"
		if direct {
			name = "direct"
		}
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			fail := true
			conn := newPacketWriteConn(func(b []byte) (int, error) {
				if fail {
					return 0, io.ErrShortWrite
				}
				return output.Write(b)
			})
			defer conn.Abort()
			send := func(value byte) error {
				pk := &packet.Unknown{PacketID: 777, Payload: []byte{value}}
				if direct {
					return conn.WritePacketDirect(pk)
				}
				if err := conn.WritePacket(pk); err != nil {
					return err
				}
				return conn.Flush()
			}
			if err := send(1); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("send error = %v", err)
			}
			q := &conn.bufferedSendSpare
			if direct {
				q = &conn.directSend
			}
			if q.buf != nil || len(q.packets) != 0 {
				t.Fatalf("failed send retained its queue: %+v", q)
			}
			for _, retained := range q.packets[:cap(q.packets)] {
				if retained != nil {
					t.Fatal("failed send retained packet backing storage")
				}
			}
			fail = false
			if err := send(2); err != nil {
				t.Fatal(err)
			}
			got := decodeWrittenBatch(t, output.Bytes())
			want := packetWriteBytes(&packet.Unknown{PacketID: 777, Payload: []byte{2}})
			if len(got) != 1 || !bytes.Equal(got[0], want) {
				t.Fatalf("retry included stale packet data: %x", got)
			}
		})
	}
}

// TestWritePacketCanQueueWhileFlushBlocks checks ownership across concurrent batch swaps.
func TestWritePacketCanQueueWhileFlushBlocks(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	var unblockOnce sync.Once
	defer unblockOnce.Do(func() { close(unblock) })
	var batches [][]byte
	conn := newPacketWriteConn(func(b []byte) (int, error) {
		if len(batches) == 0 {
			close(started)
			<-unblock
		}
		batches = append(batches, bytes.Clone(b))
		return len(b), nil
	})
	defer conn.Abort()
	first := &packet.Unknown{PacketID: 777, Payload: []byte{1}}
	second := &packet.Unknown{PacketID: 778, Payload: bytes.Repeat([]byte{2}, 1024)}
	if err := conn.WritePacket(first); err != nil {
		t.Fatal(err)
	}
	flushed := make(chan error, 1)
	go func() { flushed <- conn.Flush() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("flush did not reach transport")
	}
	queued := make(chan error, 1)
	go func() { queued <- conn.WritePacket(second) }()
	select {
	case err := <-queued:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet marshaling blocked behind network write")
	}
	unblockOnce.Do(func() { close(unblock) })
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 {
		t.Fatalf("got %d batches", len(batches))
	}
	for i, pk := range []packet.Packet{first, second} {
		got := decodeWrittenBatch(t, batches[i])
		if len(got) != 1 || !bytes.Equal(got[0], packetWriteBytes(pk)) {
			t.Fatalf("batch %d changed during concurrent queueing", i)
		}
	}
}

// alternateWriterProtocol distinguishes a negotiated dialect's writer from the cached standard writer.
type alternateWriterProtocol struct {
	BasicProtocol
}

// NewWriter uses the alternate dialect's raw-payload encoding.
func (p alternateWriterProtocol) NewWriter(w ByteWriter, shieldID int32) protocol.IO {
	return alternatePacketWriter{IO: protocol.NewWriter(w, shieldID)}
}

// alternatePacketWriter marks raw payloads to make incorrect writer reuse observable.
type alternatePacketWriter struct{ protocol.IO }

// Bytes writes the dialect marker before a packet's remaining payload.
func (w alternatePacketWriter) Bytes(payload *[]byte) {
	marker := uint8(0xaa)
	w.Uint8(&marker)
	w.IO.Bytes(payload)
}

// TestWritePacketRefreshesWriterAfterLoginDialectSelection covers same-ID protocol negotiation.
func TestWritePacketRefreshesWriterAfterLoginDialectSelection(t *testing.T) {
	conn := newPacketWriteConn(func(b []byte) (int, error) { return len(b), nil })
	defer conn.Abort()
	older := BasicProtocol{Protocol: 900, Version: "1.26.40"}
	newer := alternateWriterProtocol{BasicProtocol{Protocol: 900, Version: "1.26.44"}}
	conn.setProtocol(older)
	pk := &packet.Unknown{PacketID: 777, Payload: []byte{1}}
	if err := conn.WritePacket(pk); err != nil {
		t.Fatal(err)
	}
	conn.acceptedProto = []Protocol{older, newer}
	conn.clientData.GameVersion = "1.26.44"
	if err := conn.selectProtocolByGameVersion(); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacket(pk); err != nil {
		t.Fatal(err)
	}
	got := conn.bufferedSend.packets[1]
	want := append(bytes.Clone(packetWriteBytes(pk)[:2]), 0xaa, 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("new dialect reused old writer: got %x want %x", got, want)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentDirectAndBufferedWrites checks that queue reuse never mixes packets or loses sends.
func TestConcurrentDirectAndBufferedWrites(t *testing.T) {
	var packets [][]byte
	conn := newPacketWriteConn(func(b []byte) (int, error) {
		packets = append(packets, decodeWrittenBatch(t, b)...)
		return len(b), nil
	})
	defer conn.Abort()
	const writers, perWriter = 4, 32
	var workers sync.WaitGroup
	for worker := range writers {
		workers.Go(func() {
			for i := range perWriter {
				pk := &packet.Unknown{PacketID: 777, Payload: []byte{byte(worker), byte(i)}}
				var err error
				if worker%2 == 0 {
					err = conn.WritePacketDirect(pk)
				} else if err = conn.WritePacket(pk); err == nil {
					err = conn.Flush()
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(packets) != writers*perWriter {
		t.Fatalf("got %d packets, want %d", len(packets), writers*perWriter)
	}
	seen := make(map[string]bool, len(packets))
	for _, encoded := range packets {
		if len(encoded) != 4 || encoded[2] >= writers || encoded[3] >= perWriter || seen[string(encoded)] {
			t.Fatalf("corrupt or duplicate packet %x", encoded)
		}
		seen[string(encoded)] = true
	}
}
