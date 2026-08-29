package minecraft

import "sync"

const (
	minOwnedPacketBufferClass              = 256
	maxOwnedPacketBuffersPerClass          = 64
	maxOwnedPacketBufferRetainedClassBytes = 1 << 20
)

type ownedPacketBufferClass struct {
	size    int
	mu      sync.Mutex
	buffers [][]byte
}

var ownedPacketBufferClasses = newOwnedPacketBufferClasses()

// newOwnedPacketBufferClasses derives every power-of-two class from the retention limit.
func newOwnedPacketBufferClasses() []ownedPacketBufferClass {
	classes := make([]ownedPacketBufferClass, 0, 13)
	for size := minOwnedPacketBufferClass; size <= maxRetainedPacketBufferCap; size <<= 1 {
		classes = append(classes, newOwnedPacketBufferClass(size))
	}
	return classes
}

// newOwnedPacketBufferClass bounds each size class by both buffer count and retained bytes.
func newOwnedPacketBufferClass(size int) ownedPacketBufferClass {
	count := min(maxOwnedPacketBuffersPerClass, maxOwnedPacketBufferRetainedClassBytes/size)
	return ownedPacketBufferClass{size: size, buffers: make([][]byte, 0, count)}
}

// acquireOwnedPacketBuffer returns a size-classed buffer that may outlive the decoder callback.
func acquireOwnedPacketBuffer(length int) []byte {
	for i := range ownedPacketBufferClasses {
		class := &ownedPacketBufferClasses[i]
		if length > class.size {
			continue
		}
		class.mu.Lock()
		if n := len(class.buffers); n != 0 {
			buffer := class.buffers[n-1]
			class.buffers[n-1] = nil
			class.buffers = class.buffers[:n-1]
			class.mu.Unlock()
			return buffer[:length]
		}
		class.mu.Unlock()
		return make([]byte, length, class.size)
	}
	return make([]byte, length)
}

// releaseOwnedPacketBuffer returns a class-sized buffer without retaining oversized traffic.
func releaseOwnedPacketBuffer(buffer []byte) {
	for i := range ownedPacketBufferClasses {
		class := &ownedPacketBufferClasses[i]
		if cap(buffer) != class.size {
			continue
		}
		class.mu.Lock()
		if len(class.buffers) < cap(class.buffers) {
			class.buffers = append(class.buffers, buffer[:class.size])
		}
		class.mu.Unlock()
		return
	}
}
