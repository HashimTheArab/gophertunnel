package signaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// DefaultPingFrequency is used when the signaling service does not provide a
// positive ping interval.
const DefaultPingFrequency = time.Second * 15

// AFDEnvironment represents an environment for the signaling AFD (Azure Front Door) service,
// which resolves the URI of the signaling service nearest to the user.
type AFDEnvironment struct {
	internal.ServiceEnvironment
}

// ServiceName implements [service.Environment]. It always returns 'signaling-afd'.
func (e *AFDEnvironment) ServiceName() string {
	return "signaling-afd"
}

// Configuration dynamically resolves the configuration for the nearest signaling service.
func (e *AFDEnvironment) Configuration(ctx context.Context, client *http.Client, src service.TokenSource) (*Configuration, error) {
	resp, err := authclient.Call(ctx, client, func(ctx context.Context) (*http.Request, error) {
		token, err := src.ServiceToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("request service token: %w", err)
		}

		requestURL := e.ServiceURI.JoinPath("/api/v1.0/configuration").String()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, fmt.Errorf("request environment: %w", err)
		}
		req.Header.Set("User-Agent", "libhttpclient/1.0.0.0")
		token.SetAuthHeader(req)
		return req, nil
	}, authclient.CallOptions{Retry: configurationRetry})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var result internal.Result[*Configuration]
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("decode response body: %w", err)
		}
		if result.Data == nil {
			return nil, errors.New("service/signaling: AFDEnvironment: invalid configuration result")
		}
		return result.Data, nil
	default:
		return nil, service.NewResponseError(resp)
	}
}

// configurationRetry retries a configuration request that failed transiently, doubling the delay from
// one second up to 30 seconds as vanilla does, for as long as the dial's context allows.
var configurationRetry = authclient.RetryOptions{Attempts: 6, MinDelay: 500 * time.Millisecond, MaxDelay: 30 * time.Second}

// Environment is the signaling service discovery lists as 'signaling'. Vanilla connects to it directly
// when the configuration from [AFDEnvironment] cannot be fetched.
type Environment struct {
	internal.ServiceEnvironment
}

// ServiceName implements [service.Environment]. It always returns 'signaling'.
func (e *Environment) ServiceName() string {
	return "signaling"
}

// discoveredConfiguration resolves the signaling service as vanilla does: from the [AFDEnvironment]
// configuration, or the discovered [Environment] with [DefaultPingFrequency] when that request fails.
type discoveredConfiguration struct {
	afd      *AFDEnvironment // nil when discovery has no 'signaling-afd' service
	fallback *url.URL        // nil when discovery has no 'signaling' service
	log      *slog.Logger
}

// Configuration implements [ConfigurationProvider].
func (p discoveredConfiguration) Configuration(ctx context.Context, client *http.Client, src service.TokenSource) (*Configuration, error) {
	err := errors.New("service/signaling: discovery has no signaling-afd service")
	if p.afd != nil {
		var cfg *Configuration
		if cfg, err = p.afd.Configuration(ctx, client, src); err == nil {
			return cfg, nil
		}
	}
	if p.fallback == nil || ctx.Err() != nil {
		return nil, err
	}
	p.log.Warn("signaling configuration unavailable, connecting to the discovered signaling service", slog.Any("error", err))
	return &Configuration{ServiceURI: p.fallback, PingFrequency: DefaultPingFrequency}, nil
}

// ConfigurationProvider resolves the signaling service a [Dialer] connects to, such as [AFDEnvironment].
type ConfigurationProvider interface {
	// Configuration resolves a configuration for a long-lived connection with the signaling
	// service. The given HTTP client must be used for invoking HTTP requests. The token source
	// may be used for endpoints that require authorization.
	Configuration(ctx context.Context, client *http.Client, src service.TokenSource) (*Configuration, error)
}

// Configuration represents the parameters for establishing a long-lived connection with the
// signaling service. It is populated by a ConfigurationProvider and consumed by a Dialer.
type Configuration struct {
	// ServiceURI is the 'wss://' endpoint URI for the signaling service.
	// It may be locating to the nearest regional service to the caller.
	ServiceURI *url.URL `json:"signalingUri"`
	// PingFrequency is the interval at which a Conn pings the service to keep the connection alive.
	PingFrequency time.Duration `json:"pingFrequency"`
}

// UnmarshalJSON decodes the given JSON data into [Configuration].
// Some of the fields cannot be decoded directly into Go types so
// we first decode them as strings then manually parse them into appropriate types.
func (cfg *Configuration) UnmarshalJSON(b []byte) (err error) {
	type Alias Configuration
	data := struct {
		*Alias
		ServiceURI    string `json:"signalingUri"`
		PingFrequency string `json:"pingFrequency"`
	}{Alias: (*Alias)(cfg)}
	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}
	// [url.Parse] accepts empty strings and returns a valid url.URL with no error,
	// so we must explicitly validate that ServiceURI is not empty.
	if data.ServiceURI == "" {
		return errors.New("service/signaling: Configuration.ServiceURI cannot be empty string")
	}
	cfg.ServiceURI, err = url.Parse(data.ServiceURI)
	if err != nil {
		return fmt.Errorf("service/signaling: parse Configuration.ServiceURI: %w", err)
	}
	// An interval that is missing or does not parse falls back to the default instead of failing the dial.
	cfg.PingFrequency = DefaultPingFrequency
	if d, ok := parseTimeSpan(data.PingFrequency); ok && d > 0 {
		cfg.PingFrequency = d
	}
	return nil
}

// parseTimeSpan parses an interval in .NET's TimeSpan format, [d.]hh:mm:ss[.fffffff], as the signaling
// service writes pingFrequency.
func parseTimeSpan(s string) (time.Duration, bool) {
	var days int
	if day, rest, ok := strings.Cut(s, "."); ok && !strings.Contains(day, ":") {
		n, err := strconv.Atoi(day)
		if err != nil || n < 0 {
			return 0, false
		}
		days, s = n, rest
	}
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, false
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	sec, errS := strconv.ParseFloat(parts[2], 64)
	if errH != nil || errM != nil || errS != nil || h < 0 || m < 0 || sec < 0 {
		return 0, false
	}
	return time.Duration(days)*24*time.Hour + time.Duration(h)*time.Hour + time.Duration(m)*time.Minute +
		time.Duration(sec*float64(time.Second)), true
}
