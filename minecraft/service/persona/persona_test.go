package persona

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

type fixedTokens struct{}

func (fixedTokens) ServiceToken(context.Context) (*service.Token, error) {
	return &service.Token{AuthorizationHeader: "MCToken synthetic", ValidUntil: time.Now().Add(time.Hour)}, nil
}

var png = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

// The head image is fetched by XUID and must be image bytes; JSON or text is an error.
func TestProfileImageReturnsImageBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1.0/profile/xuid/2535/image/head":
			w.Header().Set("ETag", `"v1"`)
			_, _ = w.Write(png)
		default:
			_, _ = w.Write([]byte(`{"result":{"url":"https://x"}}`))
		}
	}))
	defer server.Close()
	env := new(Environment)
	if err := json.Unmarshal([]byte(`{"serviceUri":"`+server.URL+`"}`), env); err != nil {
		t.Fatal(err)
	}
	env.HTTPClient = server.Client()
	image, err := env.New(fixedTokens{}).ProfileImage(context.Background(), "2535", ImageHead)
	if err != nil || image.ETag != `"v1"` || image.ContentType != "image/png" {
		t.Fatalf("image = %+v err = %v", image, err)
	}
	if _, err := env.New(fixedTokens{}).ProfileImage(context.Background(), "9", ImageAvatar); err == nil {
		t.Fatal("a JSON body was accepted as an image")
	}
	if _, err := env.New(fixedTokens{}).ProfileImage(context.Background(), "../x", ImageHead); err == nil {
		t.Fatal("a path-changing xuid was accepted")
	}
}
