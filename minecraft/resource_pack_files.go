package minecraft

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// newPackFile reserves space and creates a download file on the cache's filesystem when available.
// Registration checks cancellation under the cleanup lock so a late open cannot escape Abort.
func (conn *Conn) newPackFile(size uint64) (*os.File, error) {
	if err := conn.resourcePackDownload.validateSize(size); err != nil {
		return nil, err
	}
	if err := conn.ctx.Err(); err != nil {
		return nil, conn.closeErr("create resource pack file")
	}
	budget := conn.resourcePackDownload.Budget
	if err := budget.reserve(size); err != nil {
		return nil, err
	}
	var f *os.File
	var err error
	if cache, ok := conn.resourcePackCache.(interface{ TempFile() (*os.File, error) }); ok {
		f, err = cache.TempFile()
	} else {
		f, err = os.CreateTemp("", "gophertunnel-pack-*")
	}
	if err != nil {
		budget.release(size)
		return nil, fmt.Errorf("create resource pack file: %w", err)
	}
	conn.packFilesMu.Lock()
	defer conn.packFilesMu.Unlock()
	if conn.ctx.Err() != nil {
		removePackFile(f)
		budget.release(size)
		return nil, conn.closeErr("create resource pack file")
	}
	if conn.packFiles == nil {
		conn.packFiles = make(map[*os.File]uint64)
	}
	conn.packFiles[f] = size
	return f, nil
}

// resizePackFile checks a revised size and adjusts its reservation before accepting more bytes.
func (conn *Conn) resizePackFile(f *os.File, size uint64) error {
	if err := conn.resourcePackDownload.validateSize(size); err != nil {
		return err
	}
	conn.packFilesMu.Lock()
	defer conn.packFilesMu.Unlock()
	old, ok := conn.packFiles[f]
	if !ok || conn.ctx.Err() != nil {
		return conn.closeErr("resize resource pack file")
	}
	budget := conn.resourcePackDownload.Budget
	if size > old {
		if err := budget.reserve(size - old); err != nil {
			return err
		}
	} else {
		budget.release(old - size)
	}
	conn.packFiles[f] = size
	return nil
}

// discardPackFile releases a failed or replaced download without waiting for the connection to end.
func (conn *Conn) discardPackFile(f *os.File) {
	conn.packFilesMu.Lock()
	size, ok := conn.packFiles[f]
	delete(conn.packFiles, f)
	conn.packFilesMu.Unlock()
	if ok {
		removePackFile(f)
		conn.resourcePackDownload.Budget.release(size)
	}
}

// removePackFile closes an archive before removing it, including on platforms that require that order.
func removePackFile(f *os.File) {
	_ = f.Close()
	_ = os.Remove(f.Name())
}

// downloadPackURL fetches an advertised pack and immediately discards failed or mismatching responses.
func (conn *Conn) downloadPackURL(info protocol.TexturePackInfo) (pack *resource.Pack, err error) {
	f, err := conn.newPackFile(info.Size)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			conn.discardPackFile(f)
		}
	}()
	client := conn.resourcePackHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	pack, err = resource.ReadURLToFile(conn.ctx, client, info.DownloadURL, info.Size, f)
	if err != nil {
		return nil, err
	}
	if pack.UUID() != info.UUID || pack.Version() != info.Version {
		return nil, fmt.Errorf("downloaded pack identity %s/%s does not match %s/%s", pack.UUID(), pack.Version(), info.UUID, info.Version)
	}
	if err := conn.resizePackFile(f, uint64(pack.Size())); err != nil {
		return nil, err
	}
	return pack, nil
}

// readDownloadedPack preserves the single nested ZIP accepted by Read while keeping both archives on
// disk. The nested archive must fit the same per-pack and shared limits before extraction starts.
func (conn *Conn) readDownloadedPack(f *os.File, size uint64) (*resource.Pack, error) {
	nested, err := resource.NestedArchive(f, int64(size))
	if err != nil {
		return nil, err
	}
	if nested == nil {
		return resource.ReadFile(f, int64(size))
	}
	dst, err := conn.newPackFile(nested.UncompressedSize64)
	if err != nil {
		return nil, err
	}
	reader, err := nested.Open()
	if err != nil {
		conn.discardPackFile(dst)
		return nil, fmt.Errorf("open nested archive: %w", err)
	}
	defer reader.Close()
	if _, err = io.CopyN(dst, reader, int64(nested.UncompressedSize64)); err == nil {
		var extra [1]byte
		if n, readErr := io.ReadFull(reader, extra[:]); n != 0 {
			err = errors.New("nested archive exceeds its declared size")
		} else if !errors.Is(readErr, io.EOF) {
			err = fmt.Errorf("validate nested archive: %w", readErr)
		}
	}
	if err != nil {
		conn.discardPackFile(dst)
		return nil, fmt.Errorf("extract nested archive: %w", err)
	}
	pack, err := resource.ReadFile(dst, int64(nested.UncompressedSize64))
	if err != nil {
		conn.discardPackFile(dst)
		return nil, err
	}
	conn.discardPackFile(f)
	return pack, nil
}

// trackLoadedPack takes ownership of a cache load, closing it immediately if the connection has ended.
func (conn *Conn) trackLoadedPack(pack *resource.Pack) error {
	conn.packFilesMu.Lock()
	defer conn.packFilesMu.Unlock()
	if conn.ctx.Err() != nil {
		_ = pack.Close()
		return conn.closeErr("load resource pack")
	}
	conn.loadedPacks = append(conn.loadedPacks, pack)
	return nil
}

// removePackFiles releases every connection-owned archive and returns its download reservation.
func (conn *Conn) removePackFiles() {
	conn.packFilesMu.Lock()
	files, loaded := conn.packFiles, conn.loadedPacks
	conn.packFiles, conn.loadedPacks = nil, nil
	conn.packFilesMu.Unlock()
	for f, size := range files {
		removePackFile(f)
		conn.resourcePackDownload.Budget.release(size)
	}
	for _, pack := range loaded {
		_ = pack.Close()
	}
}
