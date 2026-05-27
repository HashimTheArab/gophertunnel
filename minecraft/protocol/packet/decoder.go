package packet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"math"
	"sync"
)

// Decoder handles the decoding of Minecraft packets sent through an io.Reader. These packets in turn contain
// multiple compressed packets.
type Decoder struct {
	// r holds the io.Reader that packets are read from if the reader does not implement packetReader. When
	// this is the case, the buf field has a non-zero length.
	r   io.Reader
	buf []byte

	// pr holds a packetReader (and io.Reader) that packets are read from if the io.Reader passed to
	// NewDecoder implements the packetReader interface.
	pr packetReader

	// header holds the batch header that is expected on the beginning of input packet data.
	header             []byte
	decompress         bool
	compression        Compression
	maxDecompressedLen int
	encrypt            *encrypt
	// disableEncryption indicates whether to prevent encryption from being enabled
	// even if it is requested on handshake during login.
	disableEncryption bool

	checkPacketLimit bool
}

// packetReader is used to read packets immediately instead of copying them in a buffer first. This is a
// specific case made to reduce RAM usage.
type packetReader interface {
	ReadPacket() ([]byte, error)
}

// NewDecoder returns a new decoder decoding data from the io.Reader passed. One read call from the reader is
// assumed to consume an entire packet.
func NewDecoder(reader io.Reader) *Decoder {
	var batch []byte
	if b, ok := reader.(batchHeader); ok {
		batch = b.BatchHeader()
	} else {
		batch = []byte{header}
	}
	var disableEncryption bool
	if d, ok := reader.(encryptionDisabler); ok {
		disableEncryption = d.DisableEncryption()
	}
	if pr, ok := reader.(packetReader); ok {
		return &Decoder{
			checkPacketLimit:  true,
			pr:                pr,
			header:            batch,
			disableEncryption: disableEncryption,
		}
	}
	return &Decoder{
		r:                 reader,
		buf:               make([]byte, 1024*1024*3),
		header:            batch,
		checkPacketLimit:  true,
		disableEncryption: disableEncryption,
	}
}

// EnableEncryption enables encryption for the Decoder using the secret key bytes passed. Each packet received
// will be decrypted.
func (decoder *Decoder) EnableEncryption(keyBytes [32]byte) {
	if decoder.disableEncryption {
		return
	}
	block, _ := aes.NewCipher(keyBytes[:])
	first12 := append([]byte(nil), keyBytes[:12]...)
	stream := cipher.NewCTR(block, append(first12, 0, 0, 0, 2))
	decoder.encrypt = newEncrypt(keyBytes[:], stream)
}

// EnableCompression enables compression for the Decoder.
func (decoder *Decoder) EnableCompression(compression Compression, maxDecompressedLen int) {
	decoder.decompress = true
	decoder.compression = compression
	if maxDecompressedLen == 0 {
		maxDecompressedLen = DefaultMaxDecompressedLen
	} else if maxDecompressedLen < 0 {
		maxDecompressedLen = math.MaxInt
	}
	decoder.maxDecompressedLen = maxDecompressedLen
}

// DisableBatchPacketLimit disables the check that limits the number of packets allowed in a single packet
// batch. This should typically be called for Decoders decoding from a server connection.
func (decoder *Decoder) DisableBatchPacketLimit() {
	decoder.checkPacketLimit = false
}

const (
	// header is the header of compressed 'batches' from Minecraft.
	header = 0xfe
	// maximumInBatch is the maximum amount of packets that may be found in a batch. If a compressed batch has
	// more than this amount, decoding will fail.
	maximumInBatch = 1600
	// DefaultMaxDecompressedLen is the default maximum decompressed batch size.
	DefaultMaxDecompressedLen = 16 * 1024 * 1024
	maxPooledDecoderBufferCap = DefaultMaxDecompressedLen
)

var decompressBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 32*1024)
		return &b
	},
}

// Decode decodes one packet batch from the io.Reader passed in NewDecoder(), producing a slice of packets that it
// held and an error if not successful. The returned packet slices are owned by the caller.
func (decoder *Decoder) Decode() (packets [][]byte, err error) {
	err = decoder.DecodeFunc(func(packet []byte) error {
		packets = append(packets, append([]byte(nil), packet...))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return packets, nil
}

// DecodeFunc decodes one packet batch and calls f for each packet in the batch. The packet slice passed to f is
// valid only until f returns.
func (decoder *Decoder) DecodeFunc(f func([]byte) error) error {
	data, release, err := decoder.readBatch()
	if release != nil {
		defer release()
	}
	if err != nil {
		return err
	}
	return decoder.decodeBatch(data, f)
}

func (decoder *Decoder) readBatch() (data []byte, release func(), err error) {
	if decoder.pr == nil {
		var n int
		n, err = decoder.r.Read(decoder.buf)
		data = decoder.buf[:n]
	} else {
		data, err = decoder.pr.ReadPacket()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read batch: %w", err)
	}

	if len(data) == 0 {
		return nil, nil, nil
	}
	h := len(decoder.header)
	if len(data) < h {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if !bytes.Equal(data[:h], decoder.header) {
		return nil, nil, fmt.Errorf("decode batch: invalid header %x, expected %x", data[:h], decoder.header)
	}
	data = data[h:]
	if decoder.encrypt != nil {
		decoder.encrypt.decrypt(data)
		if err := decoder.encrypt.verify(data); err != nil {
			// The packet did not have a correct checksum.
			return nil, nil, fmt.Errorf("verify batch: %w", err)
		}
		data = data[:len(data)-8]
	}

	if decoder.decompress {
		if len(data) == 0 {
			return nil, nil, fmt.Errorf("decompress batch: missing compression algorithm")
		}
		if data[0] == 0xff {
			data = data[1:]
		} else {
			compression, ok := CompressionByID(uint16(data[0]))
			if !ok {
				return nil, nil, fmt.Errorf("decompress batch: unknown compression algorithm %v", data[0])
			}
			if compression != decoder.compression {
				return nil, nil, fmt.Errorf("decompress batch: unexpected compression algorithm: got %v, expected %v", compression, decoder.compression)
			}
			data, release, err = decoder.decompressBatch(compression, data[1:])
			if err != nil {
				if release != nil {
					release()
				}
				return nil, nil, fmt.Errorf("decompress batch: %w", err)
			}
		}
	}

	if err := decoder.checkBatchLength(data); err != nil {
		if release != nil {
			release()
		}
		return nil, nil, err
	}
	return data, release, nil
}

func (decoder *Decoder) decompressBatch(compression Compression, compressed []byte) ([]byte, func(), error) {
	if decompressor, ok := compression.(appendDecompression); ok {
		pooled := getDecompressBuffer()
		data, err := decompressor.DecompressAppend(*pooled, compressed, decoder.maxDecompressedLen)
		if err != nil {
			putDecompressBuffer(pooled)
			return nil, nil, err
		}
		*pooled = data
		return data, func() {
			putDecompressBuffer(pooled)
		}, nil
	}

	data, err := compression.Decompress(compressed, decoder.maxDecompressedLen)
	if err != nil {
		return nil, nil, err
	}
	return data, nil, nil
}

func (decoder *Decoder) decodeBatch(data []byte, f func([]byte) error) error {
	limit := decoder.maxPacketLength()
	var packetCount int
	for len(data) != 0 {
		length, n, err := readPacketLength(data)
		if err != nil {
			return fmt.Errorf("decode batch: read packet length: %w", err)
		}
		data = data[n:]
		if length == 0 {
			return fmt.Errorf("decode batch: empty packet")
		}
		if uint64(length) > uint64(limit) {
			return fmt.Errorf("decode batch: packet length %v exceeds limit %v", length, limit)
		}
		if length > uint32(len(data)) {
			return fmt.Errorf("decode batch: packet length %v exceeds remaining %v", length, len(data))
		}
		if packetCount >= maximumInBatch && decoder.checkPacketLimit {
			return fmt.Errorf("decode batch: number of packets exceeds max=%v", maximumInBatch)
		}
		if err := f(data[:length]); err != nil {
			return err
		}
		packetCount++
		data = data[length:]
	}
	return nil
}

func (decoder *Decoder) checkBatchLength(data []byte) error {
	if limit := decoder.maxPacketLength(); uint64(len(data)) > uint64(limit) {
		return fmt.Errorf("decode batch: decompressed size %v exceeds limit %v", len(data), limit)
	}
	return nil
}

func (decoder *Decoder) maxPacketLength() int {
	if decoder.maxDecompressedLen > 0 {
		return decoder.maxDecompressedLen
	}
	return DefaultMaxDecompressedLen
}

func getDecompressBuffer() *[]byte {
	b := decompressBufferPool.Get().(*[]byte)
	*b = (*b)[:0]
	return b
}

func putDecompressBuffer(b *[]byte) {
	if cap(*b) <= maxPooledDecoderBufferCap {
		*b = (*b)[:0]
		decompressBufferPool.Put(b)
	}
}

func readPacketLength(data []byte) (uint32, int, error) {
	var length uint32
	for i := 0; i < 5; i++ {
		if i >= len(data) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		b := data[i]
		if i == 4 && b&0xf0 != 0 {
			return 0, 0, fmt.Errorf("varuint32 overflows 32 bits")
		}
		length |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return length, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("varuint32 did not terminate after 5 bytes")
}
