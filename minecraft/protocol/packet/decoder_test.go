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

func TestDecodeFuncValidatesWholeBatchBeforeCallback(t *testing.T) {
	batch := append(batchBytes([]byte{1}), 2, 2)
	decoder := NewDecoder(bytes.NewReader(batch))
	called := 0

	err := decoder.DecodeFunc(func([]byte) error {
		called++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds remaining") {
		t.Fatalf("expected truncated packet error, got %v", err)
	}
	if called != 0 {
		t.Fatalf("callback called %d times for malformed batch, want 0", called)
	}
}

func TestDecodeFuncCallbackCannotOverwriteFollowingPacket(t *testing.T) {
	decoder := NewDecoder(bytes.NewReader(batchBytes([]byte{1}, []byte{2})))
	var packets [][]byte

	err := decoder.DecodeFunc(func(packet []byte) error {
		packets = append(packets, bytes.Clone(packet))
		_ = append(packet, 9)
		return nil
	})
	if err != nil {
		t.Fatalf("DecodeFunc: %v", err)
	}
	if len(packets) != 2 || !bytes.Equal(packets[1], []byte{2}) {
		t.Fatalf("decoded packets = %v, want [[1] [2]]", packets)
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

func TestDecompressAppendPreservesPrefix(t *testing.T) {
	decompressed := bytes.Repeat([]byte{1, 2, 3, 4}, 1024)
	for _, test := range []struct {
		name        string
		compression Compression
	}{
		{name: "flate", compression: FlateCompression},
		{name: "snappy", compression: SnappyCompression},
	} {
		t.Run(test.name, func(t *testing.T) {
			compression := test.compression
			compressed, err := compression.Compress(decompressed)
			if err != nil {
				t.Fatalf("compress: %v", err)
			}
			appender := compression.(appendDecompression)
			prefix := []byte{9, 8, 7}
			got, err := appender.DecompressAppend(bytes.Clone(prefix), compressed, len(decompressed))
			if err != nil {
				t.Fatalf("decompress append: %v", err)
			}
			want := append(bytes.Clone(prefix), decompressed...)
			if !bytes.Equal(got, want) {
				t.Fatal("decompressed output did not preserve its prefix")
			}
		})
	}
}

func TestFlateDecompressAppendLargeBatch(t *testing.T) {
	decompressed := bytes.Repeat([]byte("large-batch-payload"), 80*1024)
	compressed, err := FlateCompression.Compress(decompressed)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	got, err := FlateCompression.DecompressAppend(nil, compressed, len(decompressed))
	if err != nil {
		t.Fatalf("decompress append: %v", err)
	}
	if !bytes.Equal(got, decompressed) {
		t.Fatal("large decompressed batch differs from input")
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

func TestDecoderUsesDeclaredBatchCompressionAlgorithm(t *testing.T) {
	payload := bytes.Repeat([]byte{42}, 2048)
	var batch bytes.Buffer
	encoder := NewEncoder(&batch)
	encoder.EnableCompression(SnappyCompression, 1)
	if err := encoder.Encode([][]byte{payload}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoder := NewDecoder(bytes.NewReader(batch.Bytes()))
	decoder.EnableCompression(FlateCompression, 1<<20)
	packets, err := decoder.Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("len(packets) = %d, want 1", len(packets))
	}
	if !bytes.Equal(packets[0], payload) {
		t.Fatal("decoded payload differs from encoded payload")
	}
}

func TestDecoderSkipsEmptyPacketsWhenBatchPacketLimitDisabled(t *testing.T) {
	payload := []byte{42}
	batch := []byte{header, 0, byte(len(payload))}
	batch = append(batch, payload...)

	strictDecoder := NewDecoder(bytes.NewReader(batch))
	if _, err := strictDecoder.Decode(); err == nil {
		t.Fatal("Decode strict = nil, want empty packet error")
	}

	serverDecoder := NewDecoder(bytes.NewReader(batch))
	serverDecoder.DisableBatchPacketLimit()
	packets, err := serverDecoder.Decode()
	if err != nil {
		t.Fatalf("Decode server: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("len(packets) = %d, want 1", len(packets))
	}
	if !bytes.Equal(packets[0], payload) {
		t.Fatalf("packets[0] = %v, want %v", packets[0], payload)
	}
}
