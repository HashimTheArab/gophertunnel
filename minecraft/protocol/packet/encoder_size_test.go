package packet

import (
	"bytes"
	"io"
	"testing"
)

func TestEncoder_SplitsBatchesAtTheDecompressedLimit(t *testing.T) {
	for _, compression := range []struct {
		name string
		alg  Compression
	}{
		{name: "uncompressed"},
		{name: "flate", alg: FlateCompression},
		{name: "snappy", alg: SnappyCompression},
	} {
		for _, header := range [][]byte{{0xfe}, nil} {
			name := compression.name + "/raknet"
			if header == nil {
				name = compression.name + "/nethernet"
			}
			t.Run(name, func(t *testing.T) {
				// Payload bytes alone fit the cap; their two length prefixes do not.
				packets := [][]byte{
					bytes.Repeat([]byte{1}, DefaultMaxDecompressedLen/2),
					bytes.Repeat([]byte{2}, DefaultMaxDecompressedLen/2),
					{3},
				}
				transport := &sizeTestTransport{header: header}
				var counts []int
				encoder := NewEncoderFor(transport, func(data []byte, count int) (int, error) {
					counts = append(counts, count)
					return transport.Write(data)
				})
				if compression.alg != nil {
					encoder.EnableCompression(compression.alg, 0)
				}
				// Compression and encryption overhead are outside the decoded byte limit.
				key := [32]byte{1}
				encoder.EnableEncryption(key)
				if err := encoder.Encode(packets); err != nil {
					t.Fatalf("Encode: %v", err)
				}
				if len(counts) != 2 || counts[0] != 1 || counts[1] != 2 {
					t.Fatalf("batch packet counts = %v, want [1 2]", counts)
				}
				decoder := NewDecoder(transport)
				if compression.alg != nil {
					decoder.EnableCompression(compression.alg, 0)
				}
				decoder.EnableEncryption(key)
				var decoded int
				for _, count := range counts {
					batch, err := decoder.Decode()
					if err != nil {
						t.Fatalf("Decode batch: %v", err)
					}
					if len(batch) != count {
						t.Fatalf("decoded %d packets, sink was told %d", len(batch), count)
					}
					for _, payload := range batch {
						if !bytes.Equal(payload, packets[decoded]) {
							t.Fatalf("packet %d changed or reordered", decoded)
						}
						decoded++
					}
				}
				if decoded != len(packets) {
					t.Fatalf("decoded %d of %d packets", decoded, len(packets))
				}
			})
		}
	}
}

func TestEncoder_AllowsAnExactlyFullBatch(t *testing.T) {
	var writes batchWrites
	encoder := NewEncoder(&writes)
	encoder.EnableCompression(FlateCompression, 0)
	// These payload lengths use four-byte prefixes, making their batch exactly full.
	packets := [][]byte{
		bytes.Repeat([]byte{1}, DefaultMaxDecompressedLen/2-4),
		bytes.Repeat([]byte{2}, DefaultMaxDecompressedLen/2-4),
		{3},
	}
	var stats []BatchEncodeStats
	encoder.SetBatchEncodeObserver(func(s BatchEncodeStats) { stats = append(stats, s) })
	if err := encoder.Encode(packets); err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 || stats[0].PacketCount != 2 || stats[0].UncompressedLen != DefaultMaxDecompressedLen || stats[1].PacketCount != 1 {
		t.Fatalf("batch stats = %+v, want a full two-packet batch followed by one packet", stats)
	}
	for _, batch := range writes {
		decoder := NewDecoder(bytes.NewReader(batch))
		decoder.EnableCompression(FlateCompression, 0)
		if _, err := decoder.Decode(); err != nil {
			t.Fatalf("Decode: %v", err)
		}
	}
}

func TestEncoder_RejectsAnOversizedIndividualPacket(t *testing.T) {
	var writes batchWrites
	encoder := NewEncoder(&writes)
	encoder.EnableCompression(FlateCompression, 0)
	// The payload fits, but its prefix pushes it one byte over the cap.
	if err := encoder.Encode([][]byte{{1}, make([]byte, DefaultMaxDecompressedLen-3)}); err == nil {
		t.Fatal("Encode accepted an individual packet above the byte limit")
	}
	if len(writes) != 0 {
		t.Fatal("Encode wrote an oversized packet")
	}
}

// sizeTestTransport retains complete batches and supplies either RakNet or NetherNet framing.
type sizeTestTransport struct {
	batchWrites
	header []byte
}

func (t *sizeTestTransport) BatchHeader() []byte { return t.header }

// DisableEncryption matches NetherNet, whose transport already encrypts its data.
func (t *sizeTestTransport) DisableEncryption() bool { return len(t.header) == 0 }

func (*sizeTestTransport) Read([]byte) (int, error) { return 0, io.ErrNoProgress }

func (t *sizeTestTransport) ReadPacket() ([]byte, error) {
	if len(t.batchWrites) == 0 {
		return nil, io.EOF
	}
	batch := t.batchWrites[0]
	t.batchWrites = t.batchWrites[1:]
	return batch, nil
}
