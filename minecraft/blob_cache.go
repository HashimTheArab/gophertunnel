package minecraft

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

var (
	// ErrBlobCacheLimit is returned when accepting another cache-backed terrain packet would exceed a configured limit.
	ErrBlobCacheLimit = errors.New("client blob cache limit exceeded")
	// ErrBlobHashMismatch is returned when a stored or received blob does not match its advertised XXHash64 hash.
	ErrBlobHashMismatch = errors.New("client blob cache hash mismatch")
	// ErrUnexpectedBlob is returned when a server sends a blob that the resolver did not request.
	ErrUnexpectedBlob = errors.New("unexpected client blob cache blob")
	// ErrInvalidBlobCachePacket is returned when a cache-backed terrain packet has no blob dependencies.
	ErrInvalidBlobCachePacket = errors.New("invalid client blob cache packet")
)

// BlobStore stores client blob-cache payloads by their protocol XXHash64 hash. A store must be scoped to an upstream
// protocol and block-registry domain: identical bytes may have different runtime-ID semantics in another domain. Calls
// are serialised by ClientBlobCache. Put implementations that retain payload must copy it before returning.
type BlobStore interface {
	Get(hash uint64) (payload []byte, ok bool, err error)
	Put(hash uint64, payload []byte) error
}

// ClientBlobCacheLimits bounds terrain retained while the resolver waits for missing blobs.
type ClientBlobCacheLimits struct {
	// MaxPendingPackets is the maximum number of cache-backed terrain packets waiting for missing blobs.
	MaxPendingPackets int
	// MaxPendingHashes is the maximum number of unique unresolved hashes across pending packets.
	MaxPendingHashes int
	// MaxPendingBytes is the maximum retained variable-size packet data across pending packets.
	MaxPendingBytes int
}

// BlobCacheResult is produced when a cache-backed terrain packet is handled.
type BlobCacheResult struct {
	// Packets contains materialised, cache-disabled terrain packets ready for ordinary processing.
	Packets []packet.Packet
	// Status acknowledges every unique hash in the handled packet as a hit or miss. It must be sent to the server when
	// non-nil, including when every hash was already present locally.
	Status *packet.ClientCacheBlobStatus
}

// ClientBlobCache resolves cache-backed LevelChunk and SubChunk packets into ordinary terrain packets. It terminates
// the upstream cache protocol: cache status and miss-response packets must not be forwarded to another cache domain.
// Reset must be called when the upstream connection or its cache domain changes.
type ClientBlobCache struct {
	mu sync.Mutex

	store  BlobStore
	limits ClientBlobCacheLimits

	pending      []pendingBlobPacket
	outstanding  map[uint64]struct{}
	pendingBytes int
}

type pendingBlobPacket struct {
	level         *packet.LevelChunk
	sub           *packet.SubChunk
	hashes        []uint64
	retainedBytes int
}

// NewClientBlobCache creates a client blob-cache resolver backed by store.
func NewClientBlobCache(store BlobStore, limits ClientBlobCacheLimits) (*ClientBlobCache, error) {
	if store == nil {
		return nil, errors.New("client blob cache store is nil")
	}
	if limits.MaxPendingPackets <= 0 || limits.MaxPendingHashes <= 0 || limits.MaxPendingBytes <= 0 {
		return nil, errors.New("client blob cache limits must be positive")
	}
	return &ClientBlobCache{
		store:       store,
		limits:      limits,
		outstanding: make(map[uint64]struct{}),
	}, nil
}

// HandleLevelChunk resolves a LevelChunk or retains it until its missing blobs arrive. Uncached packets are returned
// unchanged and do not produce a cache status packet.
func (c *ClientBlobCache) HandleLevelChunk(pk *packet.LevelChunk) (BlobCacheResult, error) {
	if pk == nil {
		return BlobCacheResult{}, fmt.Errorf("%w: nil LevelChunk", ErrInvalidBlobCachePacket)
	}
	if !pk.CacheEnabled {
		return BlobCacheResult{Packets: []packet.Packet{pk}}, nil
	}
	if len(pk.BlobHashes) == 0 {
		return BlobCacheResult{}, fmt.Errorf("%w: LevelChunk has caching enabled without hashes", ErrInvalidBlobCachePacket)
	}
	pending := pendingBlobPacket{
		level:         cloneLevelChunk(pk),
		hashes:        uniqueBlobHashes(pk.BlobHashes),
		retainedBytes: len(pk.RawPayload) + len(pk.BlobHashes)*8,
	}
	return c.handlePending(pending)
}

// HandleSubChunk resolves a SubChunk or retains it until its missing blobs arrive. A present per-entry BlobHash marks
// an entry as cache-backed even when the packet-wide CacheEnabled flag is false.
func (c *ClientBlobCache) HandleSubChunk(pk *packet.SubChunk) (BlobCacheResult, error) {
	if pk == nil {
		return BlobCacheResult{}, fmt.Errorf("%w: nil SubChunk", ErrInvalidBlobCachePacket)
	}
	hashes := subChunkBlobHashes(pk)
	if len(hashes) == 0 {
		if !pk.CacheEnabled {
			return BlobCacheResult{Packets: []packet.Packet{pk}}, nil
		}
		out := cloneSubChunk(pk)
		out.CacheEnabled = false
		return BlobCacheResult{Packets: []packet.Packet{out}}, nil
	}
	pending := pendingBlobPacket{
		sub:           cloneSubChunk(pk),
		hashes:        uniqueBlobHashes(hashes),
		retainedBytes: subChunkRetainedBytes(pk),
	}
	return c.handlePending(pending)
}

// HandleMissResponse validates and stores requested blobs, returning terrain packets whose dependencies are now
// complete. Packets are returned in the order they were retained.
func (c *ClientBlobCache) HandleMissResponse(pk *packet.ClientCacheMissResponse) ([]packet.Packet, error) {
	if pk == nil {
		return nil, errors.New("nil ClientCacheMissResponse")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, blob := range pk.Blobs {
		if _, ok := c.outstanding[blob.Hash]; !ok {
			stored, found, err := c.getBlob(blob.Hash)
			if err != nil {
				return nil, err
			}
			if !found || !bytes.Equal(stored, blob.Payload) {
				return nil, fmt.Errorf("%w: 0x%x", ErrUnexpectedBlob, blob.Hash)
			}
			continue
		}
		if xxhash.Sum64(blob.Payload) != blob.Hash {
			return nil, fmt.Errorf("%w: 0x%x", ErrBlobHashMismatch, blob.Hash)
		}
	}
	for _, blob := range pk.Blobs {
		if _, ok := c.outstanding[blob.Hash]; !ok {
			continue
		}
		if err := c.store.Put(blob.Hash, slices.Clone(blob.Payload)); err != nil {
			return nil, fmt.Errorf("store client blob 0x%x: %w", blob.Hash, err)
		}
	}

	ready := make([]packet.Packet, 0, len(c.pending))
	left := make([]pendingBlobPacket, 0, len(c.pending))
	nextOutstanding := make(map[uint64]struct{}, len(c.outstanding))
	leftBytes := 0
	for _, pending := range c.pending {
		complete, err := c.dependenciesPresent(pending.hashes)
		if err != nil {
			return nil, err
		}
		if !complete {
			left = append(left, pending)
			leftBytes += pending.retainedBytes
			for _, hash := range pending.hashes {
				_, ok, err := c.getBlob(hash)
				if err != nil {
					return nil, err
				}
				if !ok {
					nextOutstanding[hash] = struct{}{}
				}
			}
			continue
		}
		materialised, err := c.materialise(pending)
		if err != nil {
			return nil, err
		}
		ready = append(ready, materialised)
	}
	c.pending = left
	c.outstanding = nextOutstanding
	c.pendingBytes = leftBytes
	return ready, nil
}

// Reset drops all retained packets and outstanding hash expectations without changing the backing store.
func (c *ClientBlobCache) Reset() {
	c.mu.Lock()
	c.pending = nil
	clear(c.outstanding)
	c.pendingBytes = 0
	c.mu.Unlock()
}

// handlePending classifies one packet's dependencies and either materialises or retains it.
func (c *ClientBlobCache) handlePending(pending pendingBlobPacket) (BlobCacheResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hits, misses, err := c.classify(pending.hashes)
	if err != nil {
		return BlobCacheResult{}, err
	}
	status := &packet.ClientCacheBlobStatus{HitHashes: hits, MissHashes: misses}
	if len(misses) == 0 {
		materialised, err := c.materialise(pending)
		if err != nil {
			return BlobCacheResult{}, err
		}
		return BlobCacheResult{Packets: []packet.Packet{materialised}, Status: status}, nil
	}

	additionalHashes := 0
	for _, hash := range misses {
		if _, ok := c.outstanding[hash]; !ok {
			additionalHashes++
		}
	}
	if len(c.pending)+1 > c.limits.MaxPendingPackets ||
		len(c.outstanding)+additionalHashes > c.limits.MaxPendingHashes ||
		c.pendingBytes+pending.retainedBytes > c.limits.MaxPendingBytes {
		return BlobCacheResult{}, ErrBlobCacheLimit
	}
	c.pending = append(c.pending, pending)
	c.pendingBytes += pending.retainedBytes
	for _, hash := range misses {
		c.outstanding[hash] = struct{}{}
	}
	return BlobCacheResult{Status: status}, nil
}

// classify splits hashes into locally available hits and unresolved misses while preserving their first occurrence.
func (c *ClientBlobCache) classify(hashes []uint64) (hits, misses []uint64, err error) {
	for _, hash := range hashes {
		_, ok, getErr := c.getBlob(hash)
		if getErr != nil {
			return nil, nil, getErr
		}
		if ok {
			hits = append(hits, hash)
		} else {
			misses = append(misses, hash)
		}
	}
	return hits, misses, nil
}

// getBlob retrieves and validates one stored blob.
func (c *ClientBlobCache) getBlob(hash uint64) ([]byte, bool, error) {
	payload, ok, err := c.store.Get(hash)
	if err != nil {
		return nil, false, fmt.Errorf("get client blob 0x%x: %w", hash, err)
	}
	if !ok {
		return nil, false, nil
	}
	if xxhash.Sum64(payload) != hash {
		return nil, false, fmt.Errorf("%w: stored blob 0x%x", ErrBlobHashMismatch, hash)
	}
	return payload, true, nil
}

// dependenciesPresent reports whether every hash is available in the backing store.
func (c *ClientBlobCache) dependenciesPresent(hashes []uint64) (bool, error) {
	for _, hash := range hashes {
		_, ok, err := c.getBlob(hash)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// materialise reconstructs a retained packet with cache metadata removed.
func (c *ClientBlobCache) materialise(pending pendingBlobPacket) (packet.Packet, error) {
	if pending.level != nil {
		return c.materialiseLevelChunk(pending.level)
	}
	return c.materialiseSubChunk(pending.sub)
}

// materialiseLevelChunk concatenates sub-chunk and biome blobs in advertised order before the packet's trailing data.
func (c *ClientBlobCache) materialiseLevelChunk(pk *packet.LevelChunk) (*packet.LevelChunk, error) {
	total := len(pk.RawPayload)
	blobs := make([][]byte, len(pk.BlobHashes))
	for i, hash := range pk.BlobHashes {
		blob, ok, err := c.getBlob(hash)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("client blob 0x%x is unavailable", hash)
		}
		blobs[i] = blob
		total += len(blob)
	}
	payload := make([]byte, 0, total)
	for _, blob := range blobs {
		payload = append(payload, blob...)
	}
	payload = append(payload, pk.RawPayload...)
	out := cloneLevelChunk(pk)
	out.CacheEnabled = false
	out.BlobHashes = nil
	out.RawPayload = payload
	return out, nil
}

// materialiseSubChunk prepends each cached sub-chunk blob to its entry-local trailing payload.
func (c *ClientBlobCache) materialiseSubChunk(pk *packet.SubChunk) (*packet.SubChunk, error) {
	out := cloneSubChunk(pk)
	out.CacheEnabled = false
	for i := range out.SubChunkEntries {
		entry := &out.SubChunkEntries[i]
		hash, ok := entry.BlobHash.Value()
		if !ok {
			continue
		}
		blob, found, err := c.getBlob(hash)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("client blob 0x%x is unavailable", hash)
		}
		tail, _ := entry.RawPayload.Value()
		payload := make([]byte, 0, len(blob)+len(tail))
		payload = append(payload, blob...)
		payload = append(payload, tail...)
		entry.RawPayload = protocol.Option(payload)
		entry.BlobHash = protocol.Optional[uint64]{}
	}
	return out, nil
}

// uniqueBlobHashes returns the first occurrence of every hash in hashes.
func uniqueBlobHashes(hashes []uint64) []uint64 {
	unique := make([]uint64, 0, len(hashes))
	seen := make(map[uint64]struct{}, len(hashes))
	for _, hash := range hashes {
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		unique = append(unique, hash)
	}
	return unique
}

// subChunkBlobHashes returns every present per-entry blob hash.
func subChunkBlobHashes(pk *packet.SubChunk) []uint64 {
	hashes := make([]uint64, 0, len(pk.SubChunkEntries))
	for _, entry := range pk.SubChunkEntries {
		if hash, ok := entry.BlobHash.Value(); ok {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

// subChunkRetainedBytes estimates retained variable-size packet data for limit enforcement.
func subChunkRetainedBytes(pk *packet.SubChunk) int {
	total := len(pk.SubChunkEntries) * 8
	for _, entry := range pk.SubChunkEntries {
		if payload, ok := entry.RawPayload.Value(); ok {
			total += len(payload)
		}
		if heightMap, ok := entry.HeightMapData.Value(); ok {
			total += len(heightMap)
		}
		if renderHeightMap, ok := entry.RenderHeightMapData.Value(); ok {
			total += len(renderHeightMap)
		}
	}
	return total
}

// cloneLevelChunk clones slices retained or replaced by the resolver.
func cloneLevelChunk(pk *packet.LevelChunk) *packet.LevelChunk {
	out := *pk
	out.BlobHashes = slices.Clone(pk.BlobHashes)
	out.RawPayload = slices.Clone(pk.RawPayload)
	return &out
}

// cloneSubChunk clones entry slices retained or replaced by the resolver.
func cloneSubChunk(pk *packet.SubChunk) *packet.SubChunk {
	out := *pk
	out.SubChunkEntries = slices.Clone(pk.SubChunkEntries)
	for i := range out.SubChunkEntries {
		entry := &out.SubChunkEntries[i]
		entry.RawPayload = cloneOptionalSlice(entry.RawPayload)
		entry.HeightMapData = cloneOptionalSlice(entry.HeightMapData)
		entry.RenderHeightMapData = cloneOptionalSlice(entry.RenderHeightMapData)
	}
	return &out
}

// cloneOptionalSlice clones the value held by an Optional slice while preserving absence and present-empty state.
func cloneOptionalSlice[T any](value protocol.Optional[[]T]) protocol.Optional[[]T] {
	slice, ok := value.Value()
	if !ok {
		return protocol.Optional[[]T]{}
	}
	return protocol.Option(slices.Clone(slice))
}
