package realms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

const failedPingLatencyMS = 1500

// QoSEnvironment maps Azure region identifiers to their UDP QoS beacon addresses.
type QoSEnvironment map[string]string

// ServiceName returns the discovery name of the QoS beacon service.
func (QoSEnvironment) ServiceName() string {
	return "qos-beacons"
}

// PingRegion measures the round-trip latency to the QoS beacon for region.
func (e QoSEnvironment) PingRegion(ctx context.Context, region string) (PingResult, error) {
	address, ok := e[region]
	if !ok {
		return failedPingResult(region), fmt.Errorf("region not found: %q", region)
	}
	return e.ping(ctx, region, address)
}

// ping exchanges a single payload with a QoS beacon and measures its round-trip latency.
func (QoSEnvironment) ping(ctx context.Context, region, address string) (PingResult, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "3075")
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return failedPingResult(region), fmt.Errorf("dial QoS beacon: %w", err)
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	request := make([]byte, 10)
	binary.LittleEndian.PutUint16(request[:2], 0xffff)
	if _, err := rand.Read(request[2:]); err != nil {
		return failedPingResult(region), fmt.Errorf("fill QoS payload: %w", err)
	}

	started := time.Now()
	if _, err := conn.Write(request); err != nil {
		return failedPingResult(region), fmt.Errorf("write QoS payload: %w", err)
	}
	response := make([]byte, len(request))
	if n, err := conn.Read(response); err != nil {
		return failedPingResult(region), fmt.Errorf("read QoS payload: %w", err)
	} else if n != len(response) {
		return failedPingResult(region), fmt.Errorf("QoS response length: got %d, want %d", n, len(response))
	}
	if binary.LittleEndian.Uint16(response[:2]) != 0 || !bytes.Equal(response[2:], request[2:]) {
		return failedPingResult(region), errors.New("QoS response did not match request")
	}
	return PingResult{LatencyMS: time.Since(started).Milliseconds(), Region: region}, nil
}

// PingRegions measures all regions in the environment concurrently. Failed regions are returned with the vanilla
// fallback latency, and their errors are joined in the returned error.
func (e QoSEnvironment) PingRegions(ctx context.Context) ([]PingResult, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]PingResult, 0, len(e))
	errs := make([]error, 0, len(e))
	wg.Add(len(e))
	for region, address := range e {
		go func() {
			defer wg.Done()
			result, err := e.ping(ctx, region, address)
			mu.Lock()
			results = append(results, result)
			if err != nil {
				errs = append(errs, err)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results, errors.Join(append(errs, ctx.Err())...)
}

// PingRegions discovers the current QoS environment and measures all available regions.
func PingRegions(ctx context.Context) ([]PingResult, error) {
	discovery, err := service.Default(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover service endpoints: %w", err)
	}
	environment := make(QoSEnvironment)
	if err := discovery.Environment(&environment); err != nil {
		return nil, fmt.Errorf("discover %q environment: %w", environment.ServiceName(), err)
	}
	return environment.PingRegions(ctx)
}

// PingResult contains the measured latency to an Azure region used by Realms.
type PingResult struct {
	// LatencyMS is the measured round-trip latency in milliseconds.
	LatencyMS int64 `json:"latencyMs"`
	// Region is the Azure region identifier.
	Region string `json:"region"`
}

// failedPingResult returns the latency value used by the vanilla client when a QoS measurement fails.
func failedPingResult(region string) PingResult {
	return PingResult{LatencyMS: failedPingLatencyMS, Region: region}
}
