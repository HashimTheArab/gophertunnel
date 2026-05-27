package packet

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"slices"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/s2"
	"github.com/sandertv/gophertunnel/minecraft/internal"
)

// Compression represents a compression algorithm that can compress and decompress data.
type Compression interface {
	// EncodeCompression encodes the compression algorithm into a uint16 ID.
	EncodeCompression() uint16
	// Compress compresses the given data and returns the compressed data.
	Compress(decompressed []byte) ([]byte, error)
	// Decompress decompresses the given data and returns the decompressed data.
	Decompress(compressed []byte, limit int) ([]byte, error)
}

type appendCompression interface {
	CompressAppend(dst, decompressed []byte) ([]byte, error)
	MaxCompressedLen(decompressedLen int) int
}

type appendDecompression interface {
	DecompressAppend(dst, compressed []byte, limit int) ([]byte, error)
}

var (
	// NopCompression is an empty implementation that does not compress data.
	NopCompression nopCompression
	// FlateCompression is the implementation of the Flate compression
	// algorithm. This is used by default.
	FlateCompression flateCompression
	// SnappyCompression is the implementation of the Snappy compression
	// algorithm. Snappy currently crashes devices without `avx2`.
	SnappyCompression snappyCompression

	DefaultCompression Compression = FlateCompression
)

type (
	// nopCompression is an empty implementation that does not compress data.
	nopCompression struct{}
	// flateCompression is the implementation of the Flate compression algorithm.
	flateCompression struct{}
	// snappyCompression is the implementation of the Snappy compression algorithm.
	snappyCompression struct{}
)

// flateDecompressPool is a sync.Pool for io.ReadCloser flate readers. These are
// pooled for connections.
var (
	flateDecompressPool = sync.Pool{
		New: func() any { return flate.NewReader(bytes.NewReader(nil)) },
	}
	flateCompressPool = sync.Pool{
		New: func() any {
			w, _ := flate.NewWriter(io.Discard, 6)
			return w
		},
	}
)

// EncodeCompression ...
func (nopCompression) EncodeCompression() uint16 {
	return CompressionAlgorithmNone
}

// Compress ...
func (nopCompression) Compress(decompressed []byte) ([]byte, error) {
	return decompressed, nil
}

// Decompress ...
func (nopCompression) Decompress(compressed []byte, limit int) ([]byte, error) {
	limit = normalizeDecompressionLimit(limit)
	if len(compressed) > limit {
		return nil, fmt.Errorf("nop decompression: size %d exceeds limit %d", len(compressed), limit)
	}
	return compressed, nil
}

// EncodeCompression ...
func (flateCompression) EncodeCompression() uint16 {
	return CompressionAlgorithmFlate
}

// Compress ...
func (flateCompression) Compress(decompressed []byte) ([]byte, error) {
	compressed := internal.BufferPool.Get().(*bytes.Buffer)
	w := flateCompressPool.Get().(*flate.Writer)

	defer func() {
		// Reset the buffer, so we can return it to the buffer pool safely.
		compressed.Reset()
		internal.BufferPool.Put(compressed)
		flateCompressPool.Put(w)
	}()

	w.Reset(compressed)
	if _, err := w.Write(decompressed); err != nil {
		return nil, fmt.Errorf("compress flate: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close flate writer: %w", err)
	}
	return append([]byte(nil), compressed.Bytes()...), nil
}

// Decompress ...
func (c flateCompression) Decompress(compressed []byte, limit int) ([]byte, error) {
	pooled := getDecompressBuffer()
	defer putDecompressBuffer(pooled)

	data, err := c.DecompressAppend(*pooled, compressed, limit)
	if err != nil {
		return nil, err
	}
	*pooled = data
	return append([]byte(nil), data...), nil
}

func (flateCompression) DecompressAppend(dst, compressed []byte, limit int) ([]byte, error) {
	limit = normalizeDecompressionLimit(limit)
	r := flateDecompressPool.Get().(io.ReadCloser)
	defer func() {
		_ = r.Close()
		flateDecompressPool.Put(r)
	}()

	if err := r.(flate.Resetter).Reset(bytes.NewReader(compressed), nil); err != nil {
		return nil, fmt.Errorf("reset flate: %w", err)
	}

	decompressed, err := appendReader(dst, r, limit)
	if err != nil {
		return nil, fmt.Errorf("decompress flate: %w", err)
	}
	return decompressed, nil
}

// EncodeCompression ...
func (snappyCompression) EncodeCompression() uint16 {
	return CompressionAlgorithmSnappy
}

// Compress ...
func (snappyCompression) Compress(decompressed []byte) ([]byte, error) {
	// Use the fast Snappy-compatible S2 encoder. The snappy.Encode wrapper uses
	// EncodeSnappyBetter, which trades more CPU and retained scratch memory for a
	// smaller output size.
	return s2.EncodeSnappy(nil, decompressed), nil
}

func (snappyCompression) CompressAppend(dst, decompressed []byte) ([]byte, error) {
	// Append into the caller-provided output buffer so Encoder can keep the
	// batch header and compression ID in the same allocation as the payload.
	n := s2.MaxEncodedLen(len(decompressed))
	if n < 0 {
		panic(s2.ErrTooLarge)
	}
	offset := len(dst)
	dst = slices.Grow(dst, n)
	encoded := s2.EncodeSnappy(dst[offset:offset:cap(dst)], decompressed)
	return dst[:offset+len(encoded)], nil
}

func (snappyCompression) MaxCompressedLen(decompressedLen int) int {
	return s2.MaxEncodedLen(decompressedLen)
}

// Decompress ...
func (c snappyCompression) Decompress(compressed []byte, limit int) ([]byte, error) {
	return c.DecompressAppend(nil, compressed, limit)
}

func (snappyCompression) DecompressAppend(dst, compressed []byte, limit int) ([]byte, error) {
	limit = normalizeDecompressionLimit(limit)
	// Snappy writes a decoded data length prefix, so reject over-limit batches
	// before giving the decoder's destination buffer to the decompressor.
	decodedLen, err := s2.DecodedLen(compressed)
	if err != nil {
		return nil, fmt.Errorf("snappy decoded length: %w", err)
	}
	if decodedLen > limit {
		return nil, fmt.Errorf("snappy decoded size %d exceeds limit %d", decodedLen, limit)
	}
	offset := len(dst)
	dst = slices.Grow(dst, decodedLen)
	decompressed, err := s2.Decode(dst[offset:offset:cap(dst)], compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress snappy: %w", err)
	}
	return dst[:offset+len(decompressed)], nil
}

func normalizeDecompressionLimit(limit int) int {
	if limit < 0 {
		return math.MaxInt
	}
	return limit
}

func appendReader(dst []byte, r io.Reader, limit int) ([]byte, error) {
	const chunkSize = 32 * 1024

	start := len(dst)
	for {
		readLen := cap(dst) - len(dst)
		if readLen == 0 {
			grow := chunkSize
			if limit != math.MaxInt {
				remaining := limit + 1 - (len(dst) - start)
				if remaining <= 0 {
					return nil, fmt.Errorf("size exceeds limit %d", limit)
				}
				grow = min(grow, remaining)
			}
			dst = slices.Grow(dst, grow)
			readLen = cap(dst) - len(dst)
		}
		readLen = min(readLen, chunkSize)
		if limit != math.MaxInt {
			remaining := limit + 1 - (len(dst) - start)
			if remaining <= 0 {
				return nil, fmt.Errorf("size exceeds limit %d", limit)
			}
			readLen = min(readLen, remaining)
		}

		n := len(dst)
		dst = dst[:n+readLen]
		read, err := r.Read(dst[n:])
		dst = dst[:n+read]
		if limit != math.MaxInt && len(dst)-start > limit {
			return nil, fmt.Errorf("size exceeds limit %d", limit)
		}
		if err == io.EOF {
			return dst, nil
		}
		if err != nil {
			return nil, err
		}
		if read == 0 {
			return nil, io.ErrNoProgress
		}
	}
}

// init registers all valid compressions with the protocol.
func init() {
	RegisterCompression(flateCompression{})
	RegisterCompression(snappyCompression{})
}

var compressions = map[uint16]Compression{}

// RegisterCompression registers a compression so that it can be used by the protocol.
func RegisterCompression(compression Compression) {
	compressions[compression.EncodeCompression()] = compression
}

// CompressionByID attempts to return a compression by the ID it was registered with. If found, the compression found
// is returned and the bool is true.
func CompressionByID(id uint16) (Compression, bool) {
	c, ok := compressions[id]
	if !ok {
		c = DefaultCompression
	}
	return c, ok
}
