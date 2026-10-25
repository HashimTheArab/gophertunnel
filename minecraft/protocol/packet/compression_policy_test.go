package packet

import (
	"bytes"
	"testing"
)

// sizeOnlyCompression returns synthetic candidates to exercise the benefit boundary.
type sizeOnlyCompression struct {
	extra int
}

// EncodeCompression identifies synthetic candidates as Flate so fallback must avoid decoding them.
func (c sizeOnlyCompression) EncodeCompression() uint16 { return CompressionAlgorithmFlate }

// Compress produces a candidate with the requested size difference and unrelated contents.
func (c sizeOnlyCompression) Compress(b []byte) ([]byte, error) {
	return bytes.Repeat([]byte{0x7f}, len(b)+c.extra), nil
}

// Decompress leaves candidate bytes intact so an incorrect compressed send fails byte preservation.
func (c sizeOnlyCompression) Decompress(b []byte, _ int) ([]byte, error) { return b, nil }

// appendSizeOnlyCompression exercises compressors that append into the encoder's buffer.
type appendSizeOnlyCompression struct {
	sizeOnlyCompression
}

// MaxCompressedLen reports the exact synthetic candidate size.
func (c appendSizeOnlyCompression) MaxCompressedLen(n int) int { return n + c.extra }

// CompressAppend appends the synthetic candidate after the caller's envelope.
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

// callCountingCompression checks that disabled and below-threshold batches do no compression work.
type callCountingCompression struct {
	Compression
	calls int
}

// Compress counts calls before delegating to the real algorithm.
func (c *callCountingCompression) Compress(b []byte) ([]byte, error) {
	c.calls++
	return c.Compression.Compress(b)
}

func TestEncoderCompressionThreshold(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 2048)
	// A 2048-byte packet uses a two-byte length prefix in the inner batch.
	const innerLen = 2050
	for _, tc := range []struct {
		name       string
		threshold  int
		compressed bool
	}{
		{name: "zero", threshold: 0},
		{name: "below", threshold: innerLen + 1},
		{name: "equal", threshold: innerLen, compressed: true},
		{name: "above", threshold: innerLen - 1, compressed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			compression := &callCountingCompression{Compression: FlateCompression}
			enc := NewEncoder(&out)
			enc.EnableCompression(compression, tc.threshold)
			var stats BatchEncodeStats
			enc.SetBatchEncodeObserver(func(s BatchEncodeStats) { stats = s })
			if err := enc.Encode([][]byte{payload}); err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			wantID := byte(0xff)
			if tc.compressed {
				wantCalls = 1
				wantID = byte(CompressionAlgorithmFlate)
			}
			if compression.calls != wantCalls || out.Bytes()[1] != wantID {
				t.Fatalf("compression calls = %d, byte = %x; want %d, %x", compression.calls, out.Bytes()[1], wantCalls, wantID)
			}
			if stats.UncompressedLen != innerLen || stats.Compressed != tc.compressed || stats.BelowThreshold != (tc.name == "below") {
				t.Fatalf("unexpected stats: %+v", stats)
			}
			dec := NewDecoder(&out)
			dec.EnableCompression(FlateCompression, 0)
			packets, err := dec.Decode()
			if err != nil {
				t.Fatal(err)
			}
			if len(packets) != 1 || !bytes.Equal(packets[0], payload) {
				t.Fatalf("decoded packets = %x, want %x", packets, payload)
			}
		})
	}
}
