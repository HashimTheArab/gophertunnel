package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// Environment represents the configuration for a network service in Minecraft: Bedrock Edition.
// Each service must implement Environment as a struct representing a JSON object
// to be decoded from the nested value from [Discovery.ServiceEnvironments].
type Environment interface {
	// ServiceName returns the name of the service.
	// It is used as the top-most keys of [Discovery.ServiceEnvironments].
	ServiceName() string
}

// Discovery provides environments for various services for Minecraft: Bedrock Edition.
//
// A Discovery can be obtained from [Discover] using a specific application type with
// a build version.
type Discovery struct {
	// ServiceEnvironments is a map where each key represent a service name.
	// Each value contains a nested map where keys are environment types like
	// 'prod' and values are service-specific data represented as [json.RawMessage].
	//
	// Normally, 'prod' will be the only available type for the environment on
	// retail versions of the game.
	ServiceEnvironments map[string]map[string]json.RawMessage `json:"serviceEnvironments"`

	// SupportedEnvironments is a map where each key is the version of the game
	// and each value is a slice of supported environment types for the version.
	// Typically, the only environment type available for a version is "prod".
	SupportedEnvironments map[string][]string `json:"supportedEnvironments,omitempty"`
}

const (
	// ApplicationTypeDedicatedServer is the application type for Bedrock Dedicated Server.
	// distributed by Mojang/Microsoft. For only usage for listeners, it might be preferred
	// over ApplicationTypeMinecraftPE.
	ApplicationTypeDedicatedServer = "MinecraftDedicatedServer"

	// ApplicationTypeMinecraftPE is the application type for Minecraft: Bedrock Edition
	// clients on all platform.
	//
	// ApplicationTypeMinecraftPE should be the default application type used in most services
	// as indicates both server and client.
	ApplicationTypeMinecraftPE = "MinecraftPE"
)

var (
	// discoveryURL is the base URL used to make a GET request for obtaining a Discovery
	// from [Discover] with a specific application type and build version.
	discoveryURL = &url.URL{
		Scheme: "https",
		Host:   "client.discovery.minecraft-services.net",
	}

	// discoveryCache is a map where keys are the string composed of <appType>-<version>
	// and the values are the result of [Discover], cached to reduce network time.
	discoveryCache   = make(map[string]*Discovery)
	discoveryCacheMu sync.Mutex
	// discoveryFlights holds the request shared by callers discovering the same URL with the same client,
	// guarded by discoveryCacheMu.
	discoveryFlights = make(map[string]*discoveryFlight)
)

// discoveryFlight is one discovery request shared by the callers waiting for it.
type discoveryFlight struct {
	done    chan struct{}
	result  *Discovery
	err     error
	waiters int
	cancel  context.CancelFunc
}

// Environment looks up for a value in [Discovery.ServiceEnvironments]
// using [Environment.ServiceName] as the key, then decodes the nested
// payload into the Environment.
//
// It is called by various network services on Minecraft: Bedrock Edition
// and is used to set up the environment based on remote configuration.
func (d *Discovery) Environment(env Environment) error {
	m, ok := d.ServiceEnvironments[env.ServiceName()]
	if !ok {
		return fmt.Errorf("minecraft/service: %q is not present in ServiceEnvironments", env.ServiceName())
	}
	m2, ok := m["prod"]
	if !ok {
		return fmt.Errorf("minecraft/service: %q is not present on %q in ServiceEnvironments", "prod", env.ServiceName())
	}
	return json.Unmarshal(m2, env)
}

// Default obtains a Discovery using [ApplicationTypeMinecraftPE] and
// [protocol.CurrentVersion] as the application type and version. It is
// a convenience wrapper around [Discover] for callers that do not need
// to specify these parameters explicitly.
func Default(ctx context.Context) (*Discovery, error) {
	return Discover(ctx, ApplicationTypeMinecraftPE, protocol.CurrentVersion)
}

// Discover obtains a Discover for the specific version for the specific
// application type. The returned Discovery contains environments for
// various services in Minecraft: Bedrock Edition and will be used as
// the configuration for each service.
//
// The version typically doesn't matter in any way, but it is still recommended
// to specify [protocol.CurrentVersion] to keep up the compatibility with the
// `protocol` package.
//
// Discover caches the result and can be called multiple times by various
// services without waiting for network latency each time if cache was hit.
func Discover(ctx context.Context, appType, version string) (*Discovery, error) {
	requestURL := discoveryURL.JoinPath("/api/v1.0/discovery", appType, "builds", version).String()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client := auth.ContextClient(ctx)
	key := fmt.Sprintf("%p %s", client, requestURL)

	discoveryCacheMu.Lock()
	if d, ok := discoveryCache[requestURL]; ok {
		discoveryCacheMu.Unlock()
		return d, nil
	}
	f, ok := discoveryFlights[key]
	if !ok {
		// The shared request outlives the caller that started it, until every caller waiting for it has gone.
		flightCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		f = &discoveryFlight{done: make(chan struct{}), cancel: cancel}
		discoveryFlights[key] = f
		go func() {
			d, err := discover(flightCtx, client, requestURL)
			cancel()
			discoveryCacheMu.Lock()
			if err == nil {
				discoveryCache[requestURL] = d
			}
			if discoveryFlights[key] == f {
				delete(discoveryFlights, key)
			}
			f.result, f.err = d, err
			discoveryCacheMu.Unlock()
			close(f.done)
		}()
	}
	f.waiters++
	discoveryCacheMu.Unlock()

	select {
	case <-ctx.Done():
		discoveryCacheMu.Lock()
		if f.waiters--; f.waiters == 0 {
			f.cancel()
			if discoveryFlights[key] == f {
				delete(discoveryFlights, key)
			}
		}
		discoveryCacheMu.Unlock()
		return nil, ctx.Err()
	case <-f.done:
		return f.result, f.err
	}
}

// discover bounds one service lookup and retries transient HTTP failures.
func discover(ctx context.Context, client *http.Client, requestURL string) (*Discovery, error) {
	resp, err := authclient.Call(ctx, client, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, fmt.Errorf("make request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", internal.UserAgent)
		return req, nil
	}, authclient.CallOptions{Retry: authclient.RetryOptions{Attempts: 5}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, NewResponseError(resp)
	}

	var result internal.Result[Discovery]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}
	return &result.Data, nil
}
