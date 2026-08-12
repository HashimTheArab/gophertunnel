// Package gallery provides access to the Minecraft Gallery service.
package gallery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// Environment represents an environment for the Gallery service.
type Environment struct {
	// ServiceURI is the base endpoint URL for the Gallery service.
	ServiceURI *url.URL `json:"serviceUri"`

	// HTTPClient is used to make Gallery requests. If nil, http.DefaultClient is used.
	HTTPClient *http.Client `json:"-"`
}

// DefaultEnvironment is the production Gallery service environment. It may become outdated if
// Mojang changes the service endpoint.
var DefaultEnvironment = &Environment{ServiceURI: &url.URL{
	Scheme: "https",
	Host:   "persona.franchise.minecraft-services.net",
}}

// NewClient returns a new Client using DefaultEnvironment.
func NewClient(src service.TokenSource) (*Client, error) {
	return DefaultEnvironment.New(src)
}

// New returns a new Client using src for authorization.
func (e *Environment) New(src service.TokenSource) (*Client, error) {
	if e == nil {
		return nil, errors.New("service/gallery: environment is nil")
	}
	if e.ServiceURI == nil || !e.ServiceURI.IsAbs() || e.ServiceURI.Host == "" {
		return nil, errors.New("service/gallery: environment has invalid service URI")
	}
	return &Client{src: src, client: e.httpClient(), env: e}, nil
}

func (e *Environment) httpClient() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	return http.DefaultClient
}

// Client provides access to the Minecraft Gallery service, which stores a player's showcased
// screenshots.
type Client struct {
	src    service.TokenSource
	client *http.Client
	env    *Environment
}

// Image contains metadata for an image stored in the Gallery service.
type Image struct {
	ID           string    `json:"id"`
	Featured     bool      `json:"isFeatured"`
	LastModified time.Time `json:"lastModified"`
	TakenAt      time.Time `json:"takenTime"`
	URL          string    `json:"url"`

	client   *Client
	fetchURL string
}

// UploadOptions controls the metadata associated with an uploaded image.
type UploadOptions struct {
	// Featured reports whether the image should be showcased.
	Featured bool
	// TakenAt is the time at which the image was captured. A zero value omits the corresponding
	// request header.
	TakenAt time.Time
}

// Images returns the images showcased by the player identified by xuid.
func (c *Client) Images(ctx context.Context, xuid string) ([]Image, error) {
	if _, err := strconv.ParseUint(xuid, 10, 64); err != nil || strings.Trim(xuid, "0123456789") != "" {
		return nil, fmt.Errorf("service/gallery: invalid XUID %q", xuid)
	}
	requestURL := c.env.ServiceURI.JoinPath("/api/v1.0/gallery/xuid", url.PathEscape(xuid)).String()
	req, err := c.request(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, internal.Err(resp)
	}
	var response struct {
		Result *struct {
			Images []Image `json:"showcasedImages"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("service/gallery: decode images: %w", err)
	}
	if response.Result == nil {
		return nil, errors.New("service/gallery: invalid images result")
	}
	for i := range response.Result.Images {
		if err := c.trustImage(&response.Result.Images[i]); err != nil {
			return nil, err
		}
	}
	return response.Result.Images, nil
}

// Upload uploads image data to the Gallery service.
func (c *Client) Upload(ctx context.Context, image io.Reader, options UploadOptions) (Image, error) {
	if image == nil {
		return Image{}, errors.New("service/gallery: image is nil")
	}
	requestURL := c.env.ServiceURI.JoinPath("/api/v1.0/gallery").String()
	req, err := c.request(ctx, http.MethodPost, requestURL, image)
	if err != nil {
		return Image{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Ms-Showcased-Featured", strconv.FormatBool(options.Featured))
	if !options.TakenAt.IsZero() {
		req.Header.Set("X-Ms-Showcased-Timetaken", options.TakenAt.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Image{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return Image{}, internal.Err(resp)
	}
	var response internal.Result[*Image]
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Image{}, fmt.Errorf("service/gallery: decode upload result: %w", err)
	}
	if response.Data == nil {
		return Image{}, errors.New("service/gallery: invalid upload result")
	}
	if err := c.trustImage(response.Data); err != nil {
		return Image{}, err
	}
	return *response.Data, nil
}

// Fetch downloads image data. Image must be an unchanged value returned by this Client's Images
// or Upload method. The caller must close the returned reader. Redirects are rejected so that the
// Minecraft service token is never forwarded beyond the URL supplied by the Gallery service.
func (c *Client) Fetch(ctx context.Context, image Image) (io.ReadCloser, error) {
	if image.client != c || image.fetchURL == "" || image.URL != image.fetchURL {
		return nil, errors.New("service/gallery: image was not returned by this client or its URL was changed")
	}
	req, err := c.request(ctx, http.MethodGet, image.fetchURL, nil)
	if err != nil {
		return nil, err
	}
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, internal.Err(resp)
	}
	return resp.Body, nil
}

// Delete deletes the image identified by imageID.
func (c *Client) Delete(ctx context.Context, imageID string) error {
	if imageID == "" || imageID == "." || imageID == ".." {
		return errors.New("service/gallery: invalid image ID")
	}
	requestURL := c.env.ServiceURI.JoinPath("/api/v1.0/gallery", url.PathEscape(imageID)).String()
	req, err := c.request(ctx, http.MethodDelete, requestURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return internal.Err(resp)
	}
	return nil
}

func (c *Client) trustImage(image *Image) error {
	if image.URL == "" {
		return nil
	}
	imageURL, err := url.Parse(image.URL)
	if err != nil || !imageURL.IsAbs() || imageURL.Host == "" || imageURL.User != nil {
		return fmt.Errorf("service/gallery: invalid image URL %q", image.URL)
	}
	if imageURL.Scheme != "https" && !(c.env.ServiceURI.Scheme == "http" && imageURL.Scheme == "http") {
		return fmt.Errorf("service/gallery: unsupported image URL scheme %q", imageURL.Scheme)
	}
	image.client = c
	image.fetchURL = image.URL
	return nil
}

func (c *Client) request(ctx context.Context, method, requestURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("service/gallery: make request: %w", err)
	}
	if c.src == nil {
		return nil, errors.New("service/gallery: token source is nil")
	}
	token, err := c.src.ServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("service/gallery: request service token: %w", err)
	}
	if token == nil {
		return nil, errors.New("service/gallery: token source returned nil token")
	}
	token.SetAuthHeader(req)
	req.Header.Set("User-Agent", internal.UserAgent)
	return req, nil
}
