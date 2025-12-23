package franchise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/auth/franchise/internal"
)

const userAgent = "libhttpclient/1.0.0.0"

var (
	discovered  = map[string]*Discovery{}
	discoveryMu sync.Mutex
)

func Discover(ctx context.Context, c *authclient.AuthClient, build string) (*Discovery, error) {
	discoveryMu.Lock()
	if discovery, ok := discovered[build]; ok {
		discoveryMu.Unlock()
		return discovery, nil
	}
	discoveryMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL.JoinPath(build).String(), nil)
	if err != nil {
		return nil, fmt.Errorf("make request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL, resp.Status)
	}
	var result internal.Result[*Discovery]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}
	if result.Data == nil {
		return nil, errors.New("franchise: Discover: result.Data is nil")
	}

	discoveryMu.Lock()
	discovered[build] = result.Data
	discoveryMu.Unlock()

	return result.Data, nil
}

type Discovery struct {
	ServiceEnvironments   map[string]map[string]json.RawMessage `json:"serviceEnvironments"`
	SupportedEnvironments map[string][]string                   `json:"supportedEnvironments"`
}

func (d *Discovery) Environment(env Environment, typ string) error {
	e, ok := d.ServiceEnvironments[env.EnvironmentName()]
	if !ok {
		return errors.New("franchise: environment not found")
	}
	data, ok := e[typ]
	if !ok {
		return errors.New("franchise: environment with type not found")
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("decode environment: %w", err)
	}
	return nil
}

type Environment interface {
	EnvironmentName() string
}

const (
	EnvironmentTypeProduction  = "prod"
	EnvironmentTypeDevelopment = "dev"
	EnvironmentTypeStaging     = "stage"
)

var discoveryURL = &url.URL{
	Scheme: "https",
	Host:   "client.discovery.minecraft-services.net",
	Path:   "/api/v1.0/discovery/MinecraftPE/builds/",
}
