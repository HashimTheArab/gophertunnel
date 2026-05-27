package packet

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type packetReadQueue struct {
	packets [][]byte
}

func (r *packetReadQueue) Read([]byte) (int, error) {
	return 0, io.ErrNoProgress
}

func (r *packetReadQueue) ReadPacket() ([]byte, error) {
	if len(r.packets) == 0 {
		return nil, io.EOF
	}
	p := r.packets[0]
	r.packets = r.packets[1:]
	return p, nil
}

func TestDecodeFuncRejectsOverflowPacketLength(t *testing.T) {
	decoder := NewDecoder(bytes.NewReader([]byte{header, 0xff, 0xff, 0xff, 0xff, 0x10}))
	err := decoder.DecodeFunc(func([]byte) error {
		t.Fatal("packet callback called for malformed length")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("expected varuint32 overflow error, got %v", err)
	}
}

func TestDecodeFuncRejectsDecompressedBatchLimit(t *testing.T) {
	decoder := NewDecoder(bytes.NewReader(batchBytes([]byte{1, 2, 3, 4})))
	decoder.maxDecompressedLen = 3

	err := decoder.DecodeFunc(func([]byte) error {
		t.Fatal("packet callback called for over-limit batch")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "decompressed size") {
		t.Fatalf("expected decompressed size limit error, got %v", err)
	}
}

func TestDecodeReturnsOwnedPacketsFromPooledDecompression(t *testing.T) {
	firstPacket := []byte{1, 2, 3}
	secondPacket := []byte{4, 5, 6}
	reader := &packetReadQueue{packets: [][]byte{
		compressedBatch(t, batchPayload(firstPacket)),
		compressedBatch(t, batchPayload(secondPacket)),
	}}
	decoder := NewDecoder(reader)
	decoder.EnableCompression(FlateCompression, DefaultMaxDecompressedLen)

	first, err := decoder.Decode()
	if err != nil {
		t.Fatalf("decode first batch: %v", err)
	}
	if len(first) != 1 || !bytes.Equal(first[0], firstPacket) {
		t.Fatalf("unexpected first packet: %x", first)
	}

	if _, err := decoder.Decode(); err != nil {
		t.Fatalf("decode second batch: %v", err)
	}
	if !bytes.Equal(first[0], firstPacket) {
		t.Fatalf("first packet was mutated after decoder buffer reuse: %x", first[0])
	}
}

func TestFlateDecompressRejectsLimit(t *testing.T) {
	decompressed := bytes.Repeat([]byte{1}, 128)
	compressed, err := FlateCompression.Compress(decompressed)
	if err != nil {
		t.Fatalf("compress flate: %v", err)
	}

	_, err = FlateCompression.Decompress(compressed, len(decompressed)-1)
	if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
		t.Fatalf("expected flate size limit error, got %v", err)
	}
}

func batchBytes(packets ...[]byte) []byte {
	return append([]byte{header}, batchPayload(packets...)...)
}

func batchPayload(packets ...[]byte) []byte {
	var buf bytes.Buffer
	var lenBuf [5]byte
	for _, packet := range packets {
		_, _ = buf.Write(lenBuf[:putVaruint32(&lenBuf, uint32(len(packet)))])
		_, _ = buf.Write(packet)
	}
	return buf.Bytes()
}

func compressedBatch(t *testing.T, payload []byte) []byte {
	t.Helper()
	compressed, err := FlateCompression.Compress(payload)
	if err != nil {
		t.Fatalf("compress flate: %v", err)
	}
	out := []byte{header, byte(FlateCompression.EncodeCompression())}
	return append(out, compressed...)
}
