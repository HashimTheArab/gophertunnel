package internal

import (
	"bytes"
	"sync"
	"testing"
)

// TestBufferPoolDropsOversizedBuffers ensures a large batch cannot populate the shared pool.
func TestBufferPoolDropsOversizedBuffers(t *testing.T) {
	fresh := &bytes.Buffer{}
	pool := bufferPool{pool: sync.Pool{New: func() any { return fresh }}}
	large := bytes.NewBuffer(make([]byte, 1, MaxPooledBufferCap+1))
	pool.Put(large)
	if got := pool.Get(); got != fresh {
		t.Fatalf("oversized buffer retained with capacity %d", got.Cap())
	}
}

// TestBufferPoolResetsReturnedBuffers checks that the next encoder sees an empty destination.
func TestBufferPoolResetsReturnedBuffers(t *testing.T) {
	buf := bytes.NewBufferString("previous packet")
	BufferPool.Put(buf)
	if buf.Len() != 0 {
		t.Fatal("returned buffer still contains the previous packet")
	}
}
