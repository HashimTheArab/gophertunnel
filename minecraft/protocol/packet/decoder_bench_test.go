package packet

import (
	"bytes"
	"io"
	"testing"
)

var benchmarkDecodedBytes int

type benchmarkPacketReader struct {
	packet []byte
}

func (r *benchmarkPacketReader) Read([]byte) (int, error) {
	return 0, io.ErrNoProgress
}

func (r *benchmarkPacketReader) ReadPacket() ([]byte, error) {
	return r.packet, nil
}

func BenchmarkDecodeFuncFlateBatch(b *testing.B) {
	batch, decompressedLen := benchmarkFlateBatch(b)
	reader := &benchmarkPacketReader{packet: batch}
	decoder := NewDecoder(reader)
	decoder.EnableCompression(FlateCompression, 16*1024*1024)

	b.ReportAllocs()
	b.SetBytes(int64(decompressedLen))
	b.ResetTimer()

	var decoded int
	for i := 0; i < b.N; i++ {
		if err := decoder.DecodeFunc(func(packet []byte) error {
			decoded += len(packet)
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	benchmarkDecodedBytes = decoded
}

func BenchmarkFlateDecompressBatch(b *testing.B) {
	_, decompressed := benchmarkBatchPayload()
	compressed, err := FlateCompression.Compress(decompressed)
	if err != nil {
		b.Fatalf("compress flate: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(decompressed)))
	b.ResetTimer()

	var decoded int
	for i := 0; i < b.N; i++ {
		data, err := FlateCompression.Decompress(compressed, 16*1024*1024)
		if err != nil {
			b.Fatal(err)
		}
		decoded += len(data)
	}
	benchmarkDecodedBytes = decoded
}

func BenchmarkFlateDecompressAppendBatch(b *testing.B) {
	_, decompressed := benchmarkBatchPayload()
	compressed, err := FlateCompression.Compress(decompressed)
	if err != nil {
		b.Fatalf("compress flate: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(decompressed)))
	b.ResetTimer()

	var decoded int
	var dst []byte
	for i := 0; i < b.N; i++ {
		var err error
		dst, err = FlateCompression.DecompressAppend(dst[:0], compressed, 16*1024*1024)
		if err != nil {
			b.Fatal(err)
		}
		decoded += len(dst)
	}
	benchmarkDecodedBytes = decoded
}

func benchmarkFlateBatch(b *testing.B) ([]byte, int) {
	b.Helper()
	_, payload := benchmarkBatchPayload()
	compressed, err := FlateCompression.Compress(payload)
	if err != nil {
		b.Fatalf("compress flate: %v", err)
	}
	batch := []byte{header, byte(FlateCompression.EncodeCompression())}
	return append(batch, compressed...), len(payload)
}

func benchmarkBatchPayload() ([][]byte, []byte) {
	const (
		packetCount = 64
		packetSize  = 1024
	)

	packets := make([][]byte, packetCount)
	var buf bytes.Buffer
	var lenBuf [5]byte
	for i := range packets {
		packet := make([]byte, packetSize)
		for j := range packet {
			packet[j] = byte(i*31 + j*17 + j/7)
		}
		packets[i] = packet
		_, _ = buf.Write(lenBuf[:putVaruint32(&lenBuf, uint32(len(packet)))])
		_, _ = buf.Write(packet)
	}
	return packets, buf.Bytes()
}
