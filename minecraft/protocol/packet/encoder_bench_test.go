package packet

import (
	"bytes"
	"testing"
)

func BenchmarkEncoderEncodeFlate(b *testing.B) {
	benchmarkEncoderEncode(b, FlateCompression)
}

func BenchmarkEncoderEncodeSnappy(b *testing.B) {
	benchmarkEncoderEncode(b, SnappyCompression)
}

func BenchmarkFlateCompressionCompress(b *testing.B) {
	payload := benchmarkPayload(8192)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		compressed, err := FlateCompression.Compress(payload)
		if err != nil {
			b.Fatal(err)
		}
		if len(compressed) == 0 {
			b.Fatal("empty compressed payload")
		}
	}
}

func benchmarkEncoderEncode(b *testing.B, compression Compression) {
	var out bytes.Buffer
	encoder := NewEncoder(&out)
	encoder.EnableCompression(compression, 0)
	packets := benchmarkPackets(16, 512)

	var batchBytes int64
	for _, pk := range packets {
		batchBytes += int64(len(pk))
	}
	b.SetBytes(batchBytes)
	b.ReportAllocs()
	for b.Loop() {
		out.Reset()
		if err := encoder.Encode(packets); err != nil {
			b.Fatal(err)
		}
		if out.Len() == 0 {
			b.Fatal("empty encoded batch")
		}
	}
}

func benchmarkPackets(count, size int) [][]byte {
	packets := make([][]byte, count)
	for i := range packets {
		pk := make([]byte, size)
		for j := range pk {
			pk[j] = byte(i + j)
		}
		packets[i] = pk
	}
	return packets
}

func benchmarkPayload(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}
