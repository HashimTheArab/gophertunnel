package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// Result wraps the basic structure of response body sent by most franchise-related services.
// Make sure to specify the T generic type to whatever you want in the Data.
type Result[T any] struct {
	// Data is the payload of the result, if successful.
	Data T `json:"result"`
}

// UserAgent is always set as a 'User-Agent' header to the request, and indicates that the
// request is made by libHttpClient, which is a primary HTTP client bundled in XSAPI/GDK.
const UserAgent = "libhttpclient/1.0.0.0"

// ServiceEnvironment represents an environment for a service that hosts an endpoint
// on the [ServiceEnvironment.ServiceURI].
type ServiceEnvironment struct {
	ServiceURI *url.URL `json:"serviceUri"`
}

// UnmarshalJSON implements [json.Unmarshaler.UnmarshalJSON].
// Since [url.URL] does not implement [json.Unmarshaler] or [encoding.TextUnmarshaler],
// we decode URL fields as strings first, then manually parse them into URLs.
// See: https://github.com/golang/go/issues/52638
func (e *ServiceEnvironment) UnmarshalJSON(b []byte) error {
	type Alias ServiceEnvironment
	data := struct {
		*Alias
		ServiceURI string `json:"serviceUri"`
		Issuer     string `json:"issuer"`
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	if data.ServiceURI == "" {
		return errors.New("service/internal: ServiceEnvironment.ServiceURI is empty")
	}
	var err error
	e.ServiceURI, err = url.Parse(data.ServiceURI)
	if err != nil {
		return fmt.Errorf("parse ServiceURI: %w", err)
	}
	return nil
}
