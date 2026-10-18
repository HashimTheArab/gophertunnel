package minecraft

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// maxConcurrentResourcePackURLs bounds simultaneous HTTP requests for one offer.
const maxConcurrentResourcePackURLs = 4

// resourcePackAcquisition keeps each accepted offer in order while URL work overlaps.
type resourcePackAcquisition struct {
	info       protocol.TexturePackInfo
	key        ResourcePackCacheKey
	pack       *resource.Pack
	downloaded bool
}

// acquireResourcePacksParallel resolves admitted packs with bounded URL overlap and ordered results.
// Admission and cache callbacks remain serial; duplicate accepted UUIDs use their first offer.
func (conn *Conn) acquireResourcePacksParallel(pk *packet.ResourcePacksInfo) []string {
	acquisitions := make([]*resourcePackAcquisition, 0, len(pk.TexturePacks))
	seen := make(map[string]struct{}, len(pk.TexturePacks))
	for index, pack := range pk.TexturePacks {
		id := pack.UUID.String()
		if _, ok := seen[id]; ok {
			conn.log.Warn("handle ResourcePacksInfo: duplicate texture pack", "UUID", pack.UUID)
			conn.packQueue.packAmount--
			continue
		}
		if conn.downloadResourcePack != nil && !conn.downloadResourcePack(pack.UUID, pack.Version, index, len(pk.TexturePacks)) {
			conn.ignoredResourcePacks = append(conn.ignoredResourcePacks, exemptedResourcePack{uuid: id, version: pack.Version})
			conn.packQueue.packAmount--
			continue
		}
		seen[id] = struct{}{}
		acquisition := &resourcePackAcquisition{info: pack, key: ResourcePackCacheKey{UUID: pack.UUID, Version: pack.Version, Size: pack.Size}}
		if conn.resourcePackCache != nil {
			cachedPack, err := conn.resourcePackCache.Load(conn.ctx, acquisition.key)
			switch {
			case err != nil:
				conn.log.Warn("handle ResourcePacksInfo: failed to load resource pack from cache", "UUID", pack.UUID, "version", pack.Version, "err", err)
			case cachedPack != nil && !acquisition.key.Matches(cachedPack):
				conn.log.Warn("handle ResourcePacksInfo: cached resource pack did not match advertised pack", "UUID", pack.UUID, "version", pack.Version, "cached_UUID", cachedPack.UUID(), "cached_version", cachedPack.Version(), "cached_size", cachedPack.Size())
			case cachedPack != nil:
				acquisition.pack = cachedPack
				conn.reportResourcePack(ResourcePackEvent{Kind: ResourcePackFinished, Source: ResourcePackSourceCache, UUID: pack.UUID, Version: pack.Version, Size: uint64(max(cachedPack.Size(), 0))})
			}
		}
		acquisitions = append(acquisitions, acquisition)
	}
	conn.downloadResourcePackURLs(acquisitions)
	packsToDownload := make([]string, 0, len(pk.TexturePacks))
	for _, acquisition := range acquisitions {
		pack := acquisition.info
		if acquisition.pack != nil {
			conn.resourcePacks = append(conn.resourcePacks, acquisition.pack.WithContentKey(pack.ContentKey))
			conn.packQueue.packAmount--
			continue
		}
		id := pack.UUID.String()
		// This UUID_Version is a hack Mojang put in place.
		packsToDownload = append(packsToDownload, id+"_"+pack.Version)
		conn.packQueue.downloadingPacks[id] = &downloadingPack{
			size:       pack.Size,
			buf:        bytes.NewBuffer(make([]byte, 0, min(pack.Size, maxResourcePackPrealloc))),
			contentKey: pack.ContentKey,
			cacheKey:   acquisition.key,
		}
	}

	return packsToDownload
}

// downloadResourcePackURLs resolves uncached URL offers with a bounded worker pool.
// Results remain in offer order. Failed URLs remain unresolved for chunk fallback.
// Cache operations stay on the caller, so caches need not support concurrent stores.
func (conn *Conn) downloadResourcePackURLs(acquisitions []*resourcePackAcquisition) {
	var pending []*resourcePackAcquisition
	for _, acquisition := range acquisitions {
		if acquisition.pack == nil && acquisition.info.DownloadURL != "" {
			pending = append(pending, acquisition)
		}
	}
	if len(pending) == 0 {
		return
	}
	jobs := make(chan *resourcePackAcquisition)
	var workers sync.WaitGroup
	for range min(maxConcurrentResourcePackURLs, len(pending)) {
		workers.Go(func() {
			for acquisition := range jobs {
				conn.downloadResourcePackURL(acquisition)
			}
		})
	}
	for _, acquisition := range pending {
		jobs <- acquisition
	}
	close(jobs)
	workers.Wait()
	for _, acquisition := range acquisitions {
		if acquisition.downloaded {
			conn.storeResourcePack(acquisition.key, acquisition.pack.WithContentKey(acquisition.info.ContentKey))
		}
	}
}

// downloadResourcePackURL validates one URL archive before exposing it to the offer.
func (conn *Conn) downloadResourcePackURL(acquisition *resourcePackAcquisition) {
	if conn.ctx.Err() != nil {
		return
	}
	info := acquisition.info
	event := ResourcePackEvent{Source: ResourcePackSourceURL, UUID: info.UUID, Version: info.Version}
	conn.reportResourcePack(event.with(ResourcePackStarted, info.Size, nil))
	pack, err := resource.ReadURLWithProgress(conn.ctx, conn.packHTTPClient(), info.DownloadURL, info.Size, func(n int) {
		conn.reportResourcePack(event.with(ResourcePackReceived, uint64(n), nil))
	})
	if err == nil && (pack.UUID() != info.UUID || pack.Version() != info.Version) {
		err = fmt.Errorf("downloaded pack %v_%v does not match the advertised pack", pack.UUID(), pack.Version())
	}
	if err != nil {
		conn.log.Warn("handle ResourcePacksInfo: failed to download pack from URL", "UUID", info.UUID, "version", info.Version, "download_url", info.DownloadURL, "err", err)
		conn.reportResourcePack(event.with(ResourcePackFailed, 0, err))
		return
	}
	acquisition.pack = pack
	acquisition.downloaded = true
	conn.reportResourcePack(event.with(ResourcePackFinished, 0, nil))
}
