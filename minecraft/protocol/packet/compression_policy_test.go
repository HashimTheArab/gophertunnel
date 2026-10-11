package packet

import (
	"bytes"
	"testing"
)

// sizeOnlyCompression returns synthetic candidates to exercise the benefit boundary.
type sizeOnlyCompression struct {
	extra int
}

func (c sizeOnlyCompression) EncodeCompression() uint16 { return CompressionAlgorithmFlate }

func (c sizeOnlyCompression) Compress(b []byte) ([]byte, error) {
	return bytes.Repeat([]byte{0x7f}, len(b)+c.extra), nil
}

func (c sizeOnlyCompression) Decompress(b []byte, _ int) ([]byte, error) { return b, nil }

// appendSizeOnlyCompression exercises compressors that append into the encoder's buffer.
type appendSizeOnlyCompression struct {
	sizeOnlyCompression
}

func (c appendSizeOnlyCompression) MaxCompressedLen(n int) int { return n + c.extra }

func (c appendSizeOnlyCompression) CompressAppend(dst, b []byte) ([]byte, error) {
	candidate, err := c.Compress(b)
	return append(dst, candidate...), err
}

func TestEncoderCompressionBenefit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		compression Compression
		payload     []byte
		compressed  bool
	}{
		{name: "equal", compression: sizeOnlyCompression{}, payload: []byte{1, 2, 3}},
		{name: "expanding", compression: sizeOnlyCompression{extra: 1}, payload: []byte{1, 2, 3}},
		{name: "append equal", compression: appendSizeOnlyCompression{}, payload: []byte{1, 2, 3}},
		{name: "append expanding", compression: appendSizeOnlyCompression{sizeOnlyCompression: sizeOnlyCompression{extra: 1}}, payload: []byte{1, 2, 3}},
		{name: "flate handshake", compression: FlateCompression, payload: []byte{IDClientToServerHandshake}},
		{name: "snappy handshake", compression: SnappyCompression, payload: []byte{IDClientToServerHandshake}},
		{name: "flate shrinking", compression: FlateCompression, payload: bytes.Repeat([]byte{7}, 2048), compressed: true},
		{name: "snappy shrinking", compression: SnappyCompression, payload: bytes.Repeat([]byte{7}, 2048), compressed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, encrypted := range []bool{false, true} {
				name := "plain"
				if encrypted {
					name = "encrypted"
				}
				t.Run(name, func(t *testing.T) {
					var out bytes.Buffer
					enc := NewEncoder(&out)
					enc.EnableCompression(tc.compression, 1)
					dec := NewDecoder(&out)
					dec.EnableCompression(tc.compression, 0)
					var stats BatchEncodeStats
					enc.SetBatchEncodeObserver(func(s BatchEncodeStats) { stats = s })
					if encrypted {
						key := [32]byte{1, 2, 3}
						enc.EnableEncryption(key)
						dec.EnableEncryption(key)
					}
					// Repeated batches must preserve cipher and checksum progress and buffer ownership.
					for range 2 {
						if err := enc.Encode([][]byte{tc.payload}); err != nil {
							t.Fatal(err)
						}
						wantID := uint16(CompressionAlgorithmNone)
						if tc.compressed {
							wantID = tc.compression.EncodeCompression()
						}
						if stats.Compressed != tc.compressed || stats.CompressionID != wantID || stats.BelowThreshold {
							t.Fatalf("unexpected compression stats: %+v", stats)
						}
						if !tc.compressed {
							wantLen := stats.UncompressedLen + 1
							if encrypted {
								wantLen += 8
							}
							if stats.OutputLen != wantLen {
								t.Fatalf("OutputLen = %d, want %d", stats.OutputLen, wantLen)
							}
						}
						if !encrypted && out.Bytes()[1] != byte(wantID) {
							t.Fatalf("compression byte = %x, want %x", out.Bytes()[1], byte(wantID))
						}
						packets, err := dec.Decode()
						if err != nil {
							t.Fatal(err)
						}
						if len(packets) != 1 || !bytes.Equal(packets[0], tc.payload) {
							t.Fatalf("decoded packets = %x, want %x", packets, tc.payload)
						}
					}
				})
			}
		})
	}
}
