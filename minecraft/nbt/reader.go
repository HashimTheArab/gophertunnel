package nbt

import (
	"io"
)

// offsetReader is a wrapper around an io.Reader, used to track the offset (amount of bytes read) of the data
// that is being read, so that errors may have offset data.
type offsetReader struct {
	io.Reader
	off int64
	buf [8]byte

	// byteReader is the io.Reader as an io.ByteReader, or nil if it is not one.
	byteReader io.ByteReader
	// nexter is the io.Reader if it has a Next method, or nil if it does not.
	nexter interface{ Next(n int) []byte }
}

// newOffsetReader returns a new offset reader for the io.Reader passed, reading
// bytes through its ReadByte and Next methods when it has them.
func newOffsetReader(r io.Reader) *offsetReader {
	reader := &offsetReader{Reader: r}
	reader.byteReader, _ = r.(io.ByteReader)
	reader.nexter, _ = r.(interface{ Next(n int) []byte })
	return reader
}

// ReadByte reads one byte and increases the reader's offset by one.
func (b *offsetReader) ReadByte() (byte, error) {
	if b.byteReader != nil {
		b.off++
		return b.byteReader.ReadByte()
	}
	data := make([]byte, 1)
	_, err := io.ReadAtLeast(b, data, 1)
	return data[0], err
}

// Next reads up to n bytes and increases the reader's offset by the amount read.
func (b *offsetReader) Next(n int) []byte {
	if b.nexter != nil {
		data := b.nexter.Next(n)
		b.off += int64(len(data))
		return data
	}
	data := make([]byte, n)
	read, _ := io.ReadFull(b, data)
	return data[:read]
}

// Read reads from the io.Reader and increases the reader's offset by exactly n.
func (b *offsetReader) Read(p []byte) (n int, err error) {
	n, err = io.ReadAtLeast(b.Reader, p, len(p))
	b.off += int64(n)
	return
}

// readArrayBytes validates a fixed-width array and only allocates for bytes actually received.
func (b *offsetReader) readArrayBytes(count int32, width int, op string) ([]byte, error) {
	if count < 0 || int64(count) > int64(int(^uint(0)>>1)/width) {
		return nil, BufferOverrunError{Op: op}
	}
	length := int64(count) * int64(width)
	if remaining, ok := b.Reader.(interface{ Len() int }); ok {
		if length > int64(remaining.Len()) {
			return nil, BufferOverrunError{Op: op}
		}
		data := make([]byte, int(length))
		if _, err := b.Read(data); err != nil {
			return nil, BufferOverrunError{Op: op}
		}
		return data, nil
	}
	data, err := io.ReadAll(io.LimitReader(b.Reader, length))
	b.off += int64(len(data))
	if err != nil || int64(len(data)) != length {
		return nil, BufferOverrunError{Op: op}
	}
	return data, nil
}

// sliceCap bounds the capacity preallocated for count variable-width elements of at least minWidth bytes
// each. A reader that reports its length rejects more elements than it can hold; otherwise the capacity
// starts small and the slice grows with the elements actually read.
func (b *offsetReader) sliceCap(count int32, minWidth int, op string) (int, error) {
	if count < 0 {
		return 0, BufferOverrunError{Op: op}
	}
	if remaining, ok := b.Reader.(interface{ Len() int }); ok {
		if int64(count)*int64(minWidth) > int64(remaining.Len()) {
			return 0, BufferOverrunError{Op: op}
		}
		return int(count), nil
	}
	return min(int(count), 256), nil
}
