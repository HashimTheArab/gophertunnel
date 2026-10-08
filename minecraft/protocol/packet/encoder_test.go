package packet

import (
	"bytes"
	"io"
	"testing"
)

var benchmarkBatchStats BatchEncodeStats

func TestEncoderBatchEncodeObserverBelowThreshold(t *testing.T) {
	var out bytes.Buffer
	enc := NewEncoder(&out)
	enc.EnableCompression(SnappyCompression, 1024)

	var stats BatchEncodeStats
	enc.SetBatchEncodeObserver(func(s BatchEncodeStats) {
		stats = s
	})

	payload := []byte{1, 2, 3}
	if err := enc.Encode([][]byte{payload}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if stats.PacketCount != 1 {
		t.Fatalf("PacketCount = %d, want 1", stats.PacketCount)
	}
	if !stats.BelowThreshold {
		t.Fatal("BelowThreshold = false, want true")
	}
	if stats.Compressed {
		t.Fatal("Compressed = true, want false")
	}
	if stats.CompressionID != CompressionAlgorithmNone {
		t.Fatalf("CompressionID = %d, want %d", stats.CompressionID, CompressionAlgorithmNone)
	}
	if stats.UncompressedLen == 0 || stats.OutputLen == 0 {
		t.Fatalf("stats lengths were not populated: %+v", stats)
	}
	if stats.EncodeDuration <= 0 {
		t.Fatalf("EncodeDuration = %v, want positive", stats.EncodeDuration)
	}
	if stats.CompressionDuration != 0 {
		t.Fatalf("CompressionDuration = %v below threshold, want zero", stats.CompressionDuration)
	}
}

func TestEncoderBatchEncodeObserverCompressed(t *testing.T) {
	var out bytes.Buffer
	enc := NewEncoder(&out)
	enc.EnableCompression(SnappyCompression, 1)

	var stats BatchEncodeStats
	enc.SetBatchEncodeObserver(func(s BatchEncodeStats) {
		stats = s
	})

	payload := bytes.Repeat([]byte{7}, 2048)
	if err := enc.Encode([][]byte{payload}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !stats.Compressed {
		t.Fatal("Compressed = false, want true")
	}
	if stats.CompressionID != CompressionAlgorithmSnappy {
		t.Fatalf("CompressionID = %d, want %d", stats.CompressionID, CompressionAlgorithmSnappy)
	}
	if stats.MaxCompressedLen == 0 {
		t.Fatalf("MaxCompressedLen = 0, want populated stats: %+v", stats)
	}
	if stats.BufferCap == 0 || !stats.PooledBuffer {
		t.Fatalf("pool stats not populated as expected: %+v", stats)
	}
	if stats.UncompressedLen == 0 || stats.OutputLen == 0 {
		t.Fatalf("stats lengths were not populated: %+v", stats)
	}
	if stats.CompressionDuration <= 0 {
		t.Fatalf("CompressionDuration = %v, want positive", stats.CompressionDuration)
	}
	if stats.EncodeDuration < stats.CompressionDuration {
		t.Fatalf("EncodeDuration = %v, want >= CompressionDuration %v", stats.EncodeDuration, stats.CompressionDuration)
	}
}

func TestEncoderBatchEncodeObserverOutputLenIncludesEncryptionChecksum(t *testing.T) {
	var out bytes.Buffer
	enc := NewEncoder(&out)
	enc.EnableEncryption([32]byte{1})

	var stats BatchEncodeStats
	enc.SetBatchEncodeObserver(func(s BatchEncodeStats) {
		stats = s
	})

	payload := []byte{1, 2, 3}
	if err := enc.Encode([][]byte{payload}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if got, want := stats.OutputLen, stats.UncompressedLen+8; got != want {
		t.Fatalf("OutputLen = %d, want %d", got, want)
	}
}

func BenchmarkEncoderBatchEncodeObserver(b *testing.B) {
	payload := bytes.Repeat([]byte{7}, 2048)
	packets := [][]byte{payload}
	for _, tt := range []struct {
		name     string
		observer BatchEncodeObserver
	}{
		{name: "disabled"},
		{name: "enabled", observer: func(stats BatchEncodeStats) { benchmarkBatchStats = stats }},
	} {
		b.Run(tt.name, func(b *testing.B) {
			enc := NewEncoder(io.Discard)
			enc.EnableCompression(SnappyCompression, 1)
			enc.SetBatchEncodeObserver(tt.observer)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := enc.Encode(packets); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// A batch over the decoder's packet limit is split so a limit-checking peer can decode every part.
func TestEncoderSplitsBatchesAtThePacketLimit(t *testing.T) {
	var writes batchWrites
	enc := NewEncoder(&writes)
	packets := make([][]byte, maximumInBatch*2+1)
	for i := range packets {
		packets[i] = []byte{byte(i)}
	}
	if err := enc.Encode(packets); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var sizes []int
	var decoded int
	for _, batch := range writes {
		payloads, err := NewDecoder(bytes.NewReader(batch)).Decode()
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		sizes = append(sizes, len(payloads))
		for _, payload := range payloads {
			if payload[0] != byte(decoded) {
				t.Fatalf("packet %d out of order", decoded)
			}
			decoded++
		}
	}
	if len(sizes) != 3 || sizes[0] != maximumInBatch || sizes[2] != 1 || decoded != len(packets) {
		t.Fatalf("batch sizes = %v, decoded %d of %d", sizes, decoded, len(packets))
	}
}

func TestEncoderBatchWriterReceivesActualPacketCounts(t *testing.T) {
	var counts []int
	enc := NewEncoderFor(io.Discard, func(data []byte, packetCount int) (int, error) {
		payloads, err := NewDecoder(bytes.NewReader(data)).Decode()
		if err != nil {
			t.Fatal(err)
		}
		if len(payloads) != packetCount {
			t.Fatalf("batch contains %d packets, sink was told %d", len(payloads), packetCount)
		}
		counts = append(counts, packetCount)
		return len(data), nil
	})
	packets := make([][]byte, maximumInBatch+1)
	for i := range packets {
		packets[i] = []byte{1}
	}
	if err := enc.Encode(packets); err != nil {
		t.Fatal(err)
	}
	if len(counts) != 2 || counts[0] != maximumInBatch || counts[1] != 1 {
		t.Fatalf("batch counts = %v, want [%d 1]", counts, maximumInBatch)
	}
}

// batchWrites keeps each encoded batch as its own write, as a datagram transport would.
type batchWrites [][]byte

func (w *batchWrites) Write(b []byte) (int, error) {
	*w = append(*w, bytes.Clone(b))
	return len(b), nil
}
