package signaling

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// DefaultPingFrequency is the ping interval used when the signaling service gives no usable one of at least
// a second, or when the dial falls back to the discovered 'signaling' service.
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
	}, authclient.CallOptions{Timeout: configurationTimeout, Retry: configurationRetry})
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

// configurationRetry retries a configuration request that failed transiently after 1, 2, 4, 8, 16 and 30
// seconds, as vanilla does, for as long as the request's context allows.
var configurationRetry = authclient.RetryOptions{Attempts: 7, MinDelay: 500 * time.Millisecond, MaxDelay: 30 * time.Second}

// configurationTimeout fits the whole retry schedule, so the caller's context is what usually ends it.
const configurationTimeout = 2 * time.Minute

// maxConfigurationWait bounds the configuration request when a fallback exists; it also takes at most
// half of the dial's remaining time, so the fallback can still connect.
const maxConfigurationWait = 10 * time.Second

// directEnvironment is the signaling service discovery lists as 'signaling'. Vanilla connects to it
// directly when the configuration from [AFDEnvironment] cannot be fetched.
type directEnvironment struct {
	internal.ServiceEnvironment
}

// ServiceName implements [service.Environment]. It always returns 'signaling'.
func (e *directEnvironment) ServiceName() string {
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
	fallback := &Configuration{ServiceURI: p.fallback, PingFrequency: DefaultPingFrequency}
	if p.afd == nil {
		p.log.Debug("discovery has no signaling-afd service, connecting to the discovered signaling service")
		return fallback, nil
	}
	if p.fallback == nil {
		return p.afd.Configuration(ctx, client, src)
	}
	// The token is fetched first, so only the configuration request is bounded to leave the fallback time.
	token, err := src.ServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("request service token: %w", err)
	}
	wait := maxConfigurationWait
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)/2)
	}
	afdCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	cfg, err := p.afd.Configuration(afdCtx, client, fixedTokenSource{token})
	if err == nil {
		return cfg, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	p.log.Warn("signaling configuration unavailable, connecting to the discovered signaling service", slog.Any("error", err))
	return fallback, nil
}

// fixedTokenSource is a service.TokenSource that returns one token.
type fixedTokenSource struct{ token *service.Token }

// ServiceToken implements [service.TokenSource].
func (s fixedTokenSource) ServiceToken(context.Context) (*service.Token, error) { return s.token, nil }

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
		ServiceURI    string          `json:"signalingUri"`
		PingFrequency json.RawMessage `json:"pingFrequency"`
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
	if cfg.ServiceURI.Host == "" {
		return fmt.Errorf("service/signaling: Configuration.ServiceURI %q has no host", data.ServiceURI)
	}
	// An interval that is missing or does not parse falls back to the default instead of failing the dial.
	cfg.PingFrequency = DefaultPingFrequency
	var frequency string
	if json.Unmarshal(data.PingFrequency, &frequency) == nil {
		if d, ok := parseTimeSpan(frequency); ok && d >= time.Second {
			cfg.PingFrequency = d
		}
	}
	return nil
}

// timeSpan matches a non-negative interval in .NET's TimeSpan format, [d.]hh:mm:ss[.fffffff].
var timeSpan = regexp.MustCompile(`^(?:(\d{1,5})\.)?([01]?\d|2[0-3]):([0-5]?\d):([0-5]?\d)(\.\d{1,7})?$`)

// parseTimeSpan parses an interval in .NET's TimeSpan format, as the signaling service writes pingFrequency.
func parseTimeSpan(s string) (time.Duration, bool) {
	m := timeSpan.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	days, _ := strconv.Atoi(cmp.Or(m[1], "0"))
	h, _ := strconv.Atoi(m[2])
	mins, _ := strconv.Atoi(m[3])
	secs, _ := strconv.ParseFloat(m[4]+m[5], 64)
	return time.Duration(days)*24*time.Hour + time.Duration(h)*time.Hour + time.Duration(mins)*time.Minute +
		time.Duration(secs*float64(time.Second)), true
}
