// Package persona reads profile images from the Minecraft persona service.
package persona

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// Environment is the discovered persona service endpoint.
type Environment struct {
	internal.ServiceEnvironment
	// HTTPClient sends the requests; nil uses http.DefaultClient.
	HTTPClient *http.Client `json:"-"`
}

// ServiceName implements [service.Environment] and returns "persona".
func (*Environment) ServiceName() string { return "persona" }

// New returns a Client authorized by src.
func (e *Environment) New(src service.TokenSource) *Client {
	return &Client{env: e, src: src}
}

// Client reads persona profile images.
type Client struct {
	env *Environment
	src service.TokenSource
}

// ImageKind names a rendered profile image.
type ImageKind string

const (
	ImageHead   ImageKind = "head"
	ImageAvatar ImageKind = "avatar"
)

// Image is a rendered profile image as the service sends it.
type Image struct {
	Data        []byte
	ContentType string
	ETag        string
}

// ProfileImage returns the rendered image of kind for the player with xuid; the answer is image
// bytes, and anything that is not an image is an error.
func (c *Client) ProfileImage(ctx context.Context, xuid string, kind ImageKind) (Image, error) {
	if xuid == "" || strings.ContainsAny(xuid, "/?#") {
		return Image{}, errors.New("service/persona: invalid xuid")
	}
	target := c.env.ServiceURI.JoinPath("/api/v1.0/profile/xuid", url.PathEscape(xuid), "image", string(kind))
	data, resp, err := request.Raw(ctx, c.env.HTTPClient, c.src, http.MethodGet, target, nil, request.Options{
		Header: http.Header{"Accept": {"image/*"}},
	})
	if err != nil {
		return Image{}, err
	}
	contentType := http.DetectContentType(data)
	if !strings.HasPrefix(contentType, "image/") {
		return Image{}, errors.New("service/persona: response is not an image")
	}
	return Image{Data: data, ContentType: contentType, ETag: resp.Header.Get("ETag")}, nil
}
