package minecraft

import (
	"fmt"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
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
