package minecraft

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"unsafe"

	"github.com/cespare/xxhash/v2"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

const maxClientBlobStatusHashes = 4095

var (
	// ErrBlobCacheLimit is returned when accepting another cache-backed terrain packet would exceed a configured limit.
	ErrBlobCacheLimit = errors.New("client blob cache limit exceeded")
	// ErrBlobHashMismatch is returned when a received blob does not match its advertised XXHash64 hash.
	ErrBlobHashMismatch = errors.New("client blob cache hash mismatch")
	// ErrInvalidBlobCachePacket is returned when a cache-backed terrain packet is malformed.
	ErrInvalidBlobCachePacket = errors.New("invalid client blob cache packet")
)

// BlobStore stores client blob-cache payloads by their protocol XXHash64 hash. A store must be scoped to an upstream
// protocol and block-registry domain: identical bytes may have different runtime-ID semantics in another domain. A
// single resolver serialises its own calls; a store shared between resolvers must be safe for concurrent use. Stored
// blobs must be immutable and already validated against their keys. Put must be idempotent: It must succeed without
// replacing the stored payload when hash already exists. Implementations that retain payload must copy it before
// returning and must keep it available while the resolver has pending packets.
type BlobStore interface {
	Get(hash uint64) (payload []byte, ok bool, err error)
	Put(hash uint64, payload []byte) error
}

// ClientBlobCacheLimits bounds terrain retained while the resolver waits for missing blobs.
type ClientBlobCacheLimits struct {
	// MaxPendingPackets is the maximum number of cache-backed terrain packets waiting for missing blobs.
	MaxPendingPackets int
	// MaxPendingBytes is the maximum retained variable-size data across pending packets and the maximum materialised
	// data returned by one call.
	MaxPendingBytes int
}

// BlobCacheResult is produced when a cache-backed terrain packet is handled.
type BlobCacheResult struct {
	// Packet is a materialised, cache-disabled terrain packet ready for ordinary processing, or nil if blobs are
	// still missing or an earlier terrain packet is not ready.
	Packet packet.Packet
	// Statuses acknowledge every unique hash in the handled packet as a hit or miss. They must be sent to the server in
	// order, including when every hash was already present locally.
	Statuses []*packet.ClientCacheBlobStatus
}

// ClientBlobCache resolves cache-backed LevelChunk and SubChunk packets into ordinary terrain packets. It terminates
// the upstream cache protocol and preserves arrival order across every terrain packet passed to it. Cache status and
// miss-response packets must not be forwarded to another cache domain. HandleLevelChunk and HandleSubChunk take
// ownership of their packet argument. The caller must not mutate it after the call. Reset must be called when the
// upstream connection changes.
type ClientBlobCache struct {
	mu sync.Mutex

	store  BlobStore
	limits ClientBlobCacheLimits

	pending      []*pendingBlobPacket
	outstanding  map[uint64][]*pendingBlobPacket
	pendingBytes int
}

type pendingBlobPacket struct {
	pk            packet.Packet
	missing       int
	retainedBytes int
}

type materialisePlan struct {
	pk    packet.Packet
	blobs map[uint64][]byte
}

// NewClientBlobCache creates a resolver backed by store. Every limit must be positive.
func NewClientBlobCache(store BlobStore, limits ClientBlobCacheLimits) (*ClientBlobCache, error) {
	if store == nil {
		return nil, errors.New("client blob cache store is nil")
	}
	if limits.MaxPendingPackets <= 0 || limits.MaxPendingBytes <= 0 {
		return nil, errors.New("client blob cache limits must be positive")
	}
	return &ClientBlobCache{
		store:       store,
		limits:      limits,
		outstanding: make(map[uint64][]*pendingBlobPacket),
	}, nil
}

// HandleLevelChunk resolves a LevelChunk or retains it until it and every earlier terrain packet are ready. Uncached
// packets do not produce cache status packets.
func (c *ClientBlobCache) HandleLevelChunk(pk *packet.LevelChunk) (BlobCacheResult, error) {
	if pk == nil {
		return BlobCacheResult{}, fmt.Errorf("%w: nil LevelChunk", ErrInvalidBlobCachePacket)
	}
	if !pk.CacheEnabled {
		return c.handleReady(pendingBlobPacket{pk: pk, retainedBytes: len(pk.RawPayload) + len(pk.BlobHashes)*8})
	}
	if uint64(len(pk.BlobHashes)) != uint64(pk.SubChunkCount)+1 {
		return BlobCacheResult{}, fmt.Errorf(
			"%w: LevelChunk has %d hashes for %d sub-chunks",
			ErrInvalidBlobCachePacket, len(pk.BlobHashes), pk.SubChunkCount,
		)
	}
	return c.handlePending(pendingBlobPacket{
		pk:            pk,
		retainedBytes: len(pk.RawPayload) + len(pk.BlobHashes)*8,
	}, uniqueBlobHashes(pk.BlobHashes))
}

// HandleSubChunk resolves a SubChunk or retains it until it and every earlier terrain packet are ready. A present
// per-entry BlobHash marks an entry as cache-backed even when the packet-wide CacheEnabled flag is false.
func (c *ClientBlobCache) HandleSubChunk(pk *packet.SubChunk) (BlobCacheResult, error) {
	if pk == nil {
		return BlobCacheResult{}, fmt.Errorf("%w: nil SubChunk", ErrInvalidBlobCachePacket)
	}
	hashes := subChunkBlobHashes(pk)
	if len(hashes) == 0 {
		pk.CacheEnabled = false
		return c.handleReady(pendingBlobPacket{pk: pk, retainedBytes: subChunkRetainedBytes(pk)})
	}
	return c.handlePending(pendingBlobPacket{
		pk:            pk,
		retainedBytes: subChunkRetainedBytes(pk),
	}, uniqueBlobHashes(hashes))
}

// HandleMissResponse validates and stores requested blobs, returning terrain packets whose dependencies are now
// complete. Packets are returned in the order they were retained.
func (c *ClientBlobCache) HandleMissResponse(pk *packet.ClientCacheMissResponse) ([]packet.Packet, error) {
	if pk == nil {
		return nil, errors.New("nil ClientCacheMissResponse")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	received := make(map[uint64]struct{}, len(pk.Blobs))
	expected := make([]protocol.CacheBlob, 0, len(pk.Blobs))
	for _, blob := range pk.Blobs {
		if xxhash.Sum64(blob.Payload) != blob.Hash {
			return nil, fmt.Errorf("%w: 0x%x", ErrBlobHashMismatch, blob.Hash)
		}
		if len(c.outstanding[blob.Hash]) == 0 {
			continue
		}
		if _, duplicate := received[blob.Hash]; duplicate {
			continue
		}
		received[blob.Hash] = struct{}{}
		expected = append(expected, blob)
	}
	for _, blob := range expected {
		if err := c.store.Put(blob.Hash, blob.Payload); err != nil {
			return nil, fmt.Errorf("store client blob 0x%x: %w", blob.Hash, err)
		}
	}

	resolved := make(map[*pendingBlobPacket]int)
	for hash := range received {
		for _, pending := range c.outstanding[hash] {
			resolved[pending]++
		}
	}
	plans := make([]materialisePlan, 0, len(c.pending))
	left := make([]*pendingBlobPacket, 0, len(c.pending))
	leftBytes := 0
	remainingBytes := c.limits.MaxPendingBytes
	blocked := false
	for _, pending := range c.pending {
		if blocked || pending.missing != resolved[pending] {
			blocked = true
			left = append(left, pending)
			leftBytes += pending.retainedBytes
			continue
		}
		if !packetUsesBlobCache(pending.pk) {
			if pending.retainedBytes > remainingBytes {
				return nil, ErrBlobCacheLimit
			}
			remainingBytes -= pending.retainedBytes
			plans = append(plans, materialisePlan{pk: pending.pk})
			continue
		}
		blobs, err := c.loadPacketBlobs(pending.pk)
		if err != nil {
			return nil, err
		}
		size, err := materialisedPacketSize(pending.pk, blobs, remainingBytes)
		if err != nil {
			return nil, err
		}
		remainingBytes -= size
		plans = append(plans, materialisePlan{pk: pending.pk, blobs: blobs})
	}
	ready := make([]packet.Packet, 0, len(plans))
	for _, plan := range plans {
		if plan.blobs == nil {
			ready = append(ready, plan.pk)
		} else {
			ready = append(ready, materialise(plan.pk, plan.blobs))
		}
	}
	for pending, count := range resolved {
		pending.missing -= count
	}
	c.pending = left
	c.pendingBytes = leftBytes
	for hash := range received {
		delete(c.outstanding, hash)
	}
	return ready, nil
}

// handleReady returns an ordinary terrain packet immediately, or retains it behind an earlier pending packet.
func (c *ClientBlobCache) handleReady(pending pendingBlobPacket) (BlobCacheResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.pending) == 0 {
		return BlobCacheResult{Packet: pending.pk}, nil
	}
	if err := c.retain(pending, nil); err != nil {
		return BlobCacheResult{}, err
	}
	return BlobCacheResult{}, nil
}

// Reset drops all retained packets and outstanding hash expectations without changing the backing store.
func (c *ClientBlobCache) Reset() {
	c.mu.Lock()
	c.pending = nil
	clear(c.outstanding)
	c.pendingBytes = 0
	c.mu.Unlock()
}

// handlePending materialises a packet whose blobs are all held locally, or retains it until the missing ones arrive.
func (c *ClientBlobCache) handlePending(pending pendingBlobPacket, hashes []uint64) (BlobCacheResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	blobs, hits, misses, err := c.resolve(hashes)
	if err != nil {
		return BlobCacheResult{}, err
	}
	statuses := clientBlobStatuses(misses, hits)
	if len(misses) == 0 {
		if _, err := materialisedPacketSize(pending.pk, blobs, c.limits.MaxPendingBytes); err != nil {
			return BlobCacheResult{}, err
		}
		if len(c.pending) == 0 {
			return BlobCacheResult{Packet: materialise(pending.pk, blobs), Statuses: statuses}, nil
		}
		if err := c.retain(pending, nil); err != nil {
			return BlobCacheResult{}, err
		}
		return BlobCacheResult{Statuses: statuses}, nil
	}

	if err := c.retain(pending, misses); err != nil {
		return BlobCacheResult{}, err
	}
	return BlobCacheResult{Statuses: statuses}, nil
}

// retain appends pending to the arrival queue and records its unresolved hashes. The caller must hold c.mu.
func (c *ClientBlobCache) retain(pending pendingBlobPacket, misses []uint64) error {
	if len(c.pending)+1 > c.limits.MaxPendingPackets ||
		c.pendingBytes+pending.retainedBytes > c.limits.MaxPendingBytes {
		return ErrBlobCacheLimit
	}
	pending.missing = len(misses)
	retained := &pending
	c.pending = append(c.pending, retained)
	c.pendingBytes += pending.retainedBytes
	for _, hash := range misses {
		c.outstanding[hash] = append(c.outstanding[hash], retained)
	}
	return nil
}

// clientBlobStatuses splits missing and hit hashes into protocol-sized, missing-first status packets.
func clientBlobStatuses(misses, hits []uint64) []*packet.ClientCacheBlobStatus {
	statuses := make([]*packet.ClientCacheBlobStatus, 0, (len(misses)+len(hits)+maxClientBlobStatusHashes-1)/maxClientBlobStatusHashes)
	for len(misses) != 0 || len(hits) != 0 {
		missingCount := min(len(misses), maxClientBlobStatusHashes)
		status := &packet.ClientCacheBlobStatus{MissHashes: misses[:missingCount]}
		misses = misses[missingCount:]
		hitCount := min(len(hits), maxClientBlobStatusHashes-missingCount)
		status.HitHashes = hits[:hitCount]
		hits = hits[hitCount:]
		statuses = append(statuses, status)
	}
	return statuses
}

// resolve reads every hash from the store once, splitting them into locally available hits and unresolved misses in
// first-occurrence order. The returned payloads let a caller materialise without reading the store again.
func (c *ClientBlobCache) resolve(hashes []uint64) (blobs map[uint64][]byte, hits, misses []uint64, err error) {
	blobs = make(map[uint64][]byte, len(hashes))
	hits = make([]uint64, 0, len(hashes))
	for _, hash := range hashes {
		payload, ok, getErr := c.getBlob(hash)
		if getErr != nil {
			return nil, nil, nil, getErr
		}
		if !ok {
			misses = append(misses, hash)
			continue
		}
		blobs[hash] = payload
		hits = append(hits, hash)
	}
	return blobs, hits, misses, nil
}

// getBlob retrieves one stored blob.
func (c *ClientBlobCache) getBlob(hash uint64) ([]byte, bool, error) {
	payload, ok, err := c.store.Get(hash)
	if err != nil {
		return nil, false, fmt.Errorf("get client blob 0x%x: %w", hash, err)
	}
	if !ok {
		return nil, false, nil
	}
	return payload, true, nil
}

// loadPacketBlobs retrieves all blobs needed to materialise pk.
func (c *ClientBlobCache) loadPacketBlobs(pk packet.Packet) (map[uint64][]byte, error) {
	var hashes []uint64
	switch pk := pk.(type) {
	case *packet.LevelChunk:
		hashes = uniqueBlobHashes(pk.BlobHashes)
	case *packet.SubChunk:
		hashes = uniqueBlobHashes(subChunkBlobHashes(pk))
	default:
		return nil, fmt.Errorf("%w: %T is not cache-backed", ErrInvalidBlobCachePacket, pk)
	}
	blobs, _, misses, err := c.resolve(hashes)
	if err != nil {
		return nil, err
	}
	if len(misses) != 0 {
		return nil, fmt.Errorf("client blob 0x%x is unavailable after being acknowledged", misses[0])
	}
	return blobs, nil
}

// packetUsesBlobCache reports whether pk still needs cached blobs materialised.
func packetUsesBlobCache(pk packet.Packet) bool {
	switch pk := pk.(type) {
	case *packet.LevelChunk:
		return pk.CacheEnabled
	case *packet.SubChunk:
		for _, entry := range pk.SubChunkEntries {
			if _, ok := entry.BlobHash.Value(); ok {
				return true
			}
		}
	}
	return false
}

// materialisedPacketSize returns the variable-size data held by a materialised packet, rejecting sizes above limit.
func materialisedPacketSize(pk packet.Packet, blobs map[uint64][]byte, limit int) (int, error) {
	total := 0
	add := func(size int) error {
		if size > limit-total {
			return ErrBlobCacheLimit
		}
		total += size
		return nil
	}
	switch pk := pk.(type) {
	case *packet.LevelChunk:
		if err := add(len(pk.RawPayload)); err != nil {
			return 0, err
		}
		for _, hash := range pk.BlobHashes {
			blob, ok := blobs[hash]
			if !ok {
				return 0, fmt.Errorf("client blob 0x%x is unavailable", hash)
			}
			if err := add(len(blob)); err != nil {
				return 0, err
			}
		}
	case *packet.SubChunk:
		if err := add(subChunkRetainedBytes(pk)); err != nil {
			return 0, err
		}
		for _, entry := range pk.SubChunkEntries {
			if hash, ok := entry.BlobHash.Value(); ok {
				blob, found := blobs[hash]
				if !found {
					return 0, fmt.Errorf("client blob 0x%x is unavailable", hash)
				}
				if err := add(len(blob)); err != nil {
					return 0, err
				}
			}
		}
	default:
		return 0, fmt.Errorf("%w: %T is not cache-backed", ErrInvalidBlobCachePacket, pk)
	}
	return total, nil
}

// materialise rebuilds the owned pk with its cached payloads inlined and cache metadata cleared.
func materialise(pk packet.Packet, blobs map[uint64][]byte) packet.Packet {
	switch pk := pk.(type) {
	case *packet.LevelChunk:
		return materialiseLevelChunk(pk, blobs)
	case *packet.SubChunk:
		return materialiseSubChunk(pk, blobs)
	}
	panic(fmt.Sprintf("cannot materialise client blob-cache packet %T", pk))
}

// materialiseLevelChunk concatenates sub-chunk and biome blobs in advertised order before the packet's trailing data.
func materialiseLevelChunk(pk *packet.LevelChunk, blobs map[uint64][]byte) *packet.LevelChunk {
	payloads := make([][]byte, 0, len(pk.BlobHashes)+1)
	for _, hash := range pk.BlobHashes {
		payloads = append(payloads, blobs[hash])
	}
	pk.CacheEnabled = false
	pk.BlobHashes = nil
	pk.RawPayload = slices.Concat(append(payloads, pk.RawPayload)...)
	return pk
}

// materialiseSubChunk prepends each cached sub-chunk blob to its entry-local trailing payload.
func materialiseSubChunk(pk *packet.SubChunk, blobs map[uint64][]byte) *packet.SubChunk {
	pk.CacheEnabled = false
	for i := range pk.SubChunkEntries {
		entry := &pk.SubChunkEntries[i]
		hash, ok := entry.BlobHash.Value()
		if !ok {
			continue
		}
		tail, _ := entry.RawPayload.Value()
		entry.RawPayload = protocol.Option(slices.Concat(blobs[hash], tail))
		entry.BlobHash = protocol.Optional[uint64]{}
	}
	return pk
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

// subChunkBlobHashes returns the per-entry blob hashes, which may repeat: entries commonly share one blob.
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
	total := len(pk.SubChunkEntries) * int(unsafe.Sizeof(protocol.SubChunkEntry{}))
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
