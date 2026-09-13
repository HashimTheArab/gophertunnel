package internal

import (
	"bytes"
	"sync"
)

// MaxPooledBufferCap bounds retained packet, batch, and compression scratch buffers.
const MaxPooledBufferCap = 1 << 20

// BufferPool shares bounded scratch buffers between packet and batch encoders.
var BufferPool = bufferPool{pool: sync.Pool{
	New: func() any { return bytes.NewBuffer(make([]byte, 0, 256)) },
}}

// bufferPool resets buffers on return and excludes oversized backing arrays.
type bufferPool struct {
	pool sync.Pool
}

// Get returns an empty buffer that the caller owns until Put.
func (p *bufferPool) Get() *bytes.Buffer {
	return p.pool.Get().(*bytes.Buffer)
}

// Put returns a buffer for reuse unless its retained capacity exceeds the limit.
func (p *bufferPool) Put(buf *bytes.Buffer) {
	if buf.Cap() > MaxPooledBufferCap {
		return
	}
	buf.Reset()
	p.pool.Put(buf)
}
