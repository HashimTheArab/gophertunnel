package service

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/df-mc/go-playfab/v2"
	"github.com/df-mc/go-playfab/v2/title"
	"github.com/df-mc/go-xsapi/v2/xal/nsal"
	"github.com/df-mc/go-xsapi/v2/xal/xasu"
	"github.com/df-mc/go-xsapi/v2/xal/xsts"
)

func TestNewTokenSourceRejectsNilXboxSigner(t *testing.T) {
	_, err := NewTokenSource(context.Background(), nil, TokenSourceConfig{})
	if err == nil || !strings.Contains(err.Error(), "Xbox signer") {
		t.Fatalf("NewTokenSource() error = %v, want an Xbox signer error", err)
	}
}

// Every environment field must have an explicit copy or reset policy, including newly added fields.
func TestAuthorizationEnvironmentNewTokenSourceCopiesConfiguration(t *testing.T) {
	transport := newTokenSourceTransport{}
	client := &http.Client{Transport: &transport}
	originalClient := &http.Client{Timeout: time.Second}
	env := &AuthorizationEnvironment{
		ServiceURI:         &url.URL{Scheme: "https", Host: "auth.test"},
		Issuer:             &url.URL{Scheme: "https", Host: "issuer.test"},
		PlayFabTitleID:     title.Title("20CA2"),
		EduPlayFabTitleID:  title.Title("EDU"),
		HTTPClient:         originalClient,
		KeyRefreshInterval: 5 * time.Minute,
		SessionID:          "session",
		verifier:           &oidc.IDTokenVerifier{},
	}
	want := make(map[string]any)
	value := reflect.ValueOf(env).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		switch field.Name {
		case "verifier", "verifierMu":
			// Cached verifier state and its lock belong to the original environment.
			continue
		}
		if !field.IsExported() || value.Field(i).IsZero() {
			t.Fatalf("AuthorizationEnvironment.%s needs a nonzero fixture and a copy/reset policy", field.Name)
		}
		want[field.Name] = value.Field(i).Interface()
	}
	want["HTTPClient"] = client
	env.verifierMu.Lock()
	defer env.verifierMu.Unlock()
	src, err := env.NewTokenSource(context.Background(), tokenSourceXboxSigner{}, TokenSourceConfig{HTTPClient: client})
	if err != nil {
		t.Fatalf("AuthorizationEnvironment.NewTokenSource() error = %v", err)
	}
	defer src.Close()

	underlying := src.TokenSource.(*tokenSource)
	if underlying.env == env {
		t.Fatal("token source reused the caller's environment")
	}
	copied := reflect.ValueOf(underlying.env).Elem()
	for field, expected := range want {
		if got := copied.FieldByName(field).Interface(); !reflect.DeepEqual(got, expected) {
			t.Errorf("copied %s = %#v, want %#v", field, got, expected)
		}
	}
	if env.HTTPClient != originalClient {
		t.Fatal("token source changed the caller's HTTP client")
	}
	if underlying.env.verifier != nil {
		t.Fatal("token source copied the cached verifier")
	}
	if !underlying.env.verifierMu.TryLock() {
		t.Fatal("token source copied the held verifier lock")
	}
	underlying.env.verifierMu.Unlock()
}

func TestNewTokenSourceBuildsStandardWorkflow(t *testing.T) {
	discoveryCacheMu.Lock()
	oldURL, oldCache := discoveryURL, discoveryCache
	discoveryURL, discoveryCache = &url.URL{Scheme: "https", Host: "discovery.test"}, make(map[string]*Discovery)
	discoveryCacheMu.Unlock()
	t.Cleanup(func() {
		discoveryCacheMu.Lock()
		discoveryURL, discoveryCache = oldURL, oldCache
		discoveryCacheMu.Unlock()
	})

	transport := newTokenSourceTransport{}
	client := &http.Client{Transport: &transport}
	src, err := NewTokenSource(context.Background(), tokenSourceXboxSigner{}, TokenSourceConfig{
		HTTPClient: client,
		PlayFab:    playfab.ClientConfig{CreateAccount: true},
	})
	if err != nil {
		t.Fatalf("NewTokenSource() error = %v", err)
	}
	if src.TokenSource == nil {
		t.Fatal("NewTokenSource() returned a nil underlying TokenSource")
	}
	if !transport.discoveryRequested {
		t.Fatal("NewTokenSource() did not discover the authorization environment")
	}
	if !transport.playFabRequested {
		t.Fatal("NewTokenSource() did not log in to PlayFab")
	}
	if !transport.createAccount {
		t.Fatal("NewTokenSource() did not forward PlayFab CreateAccount")
	}
	if err := src.Close(); err != nil {
		t.Fatalf("ManagedTokenSource.Close() error = %v", err)
	}
}

type tokenSourceXboxSigner struct{}

func (tokenSourceXboxSigner) TokenAndSignature(context.Context, *url.URL) (*xsts.Token, nsal.SignaturePolicy, error) {
	return &xsts.Token{
		Token:    "xsts-token",
		NotAfter: time.Now().Add(time.Hour),
		DisplayClaims: xsts.DisplayClaims{UserInfo: []xsts.UserInfo{{
			UserInfo: xasu.UserInfo{UserHash: "user-hash"},
		}}},
	}, nsal.SignaturePolicy{}, nil
}

type newTokenSourceTransport struct {
	discoveryRequested bool
	playFabRequested   bool
	createAccount      bool
}

func (t *newTokenSourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body string
	switch req.URL.Host {
	case "discovery.test":
		t.discoveryRequested = true
		body = `{"result":{"serviceEnvironments":{"auth":{"prod":{"serviceUri":"https://auth.test","issuer":"https://issuer.test","playFabTitleId":"20CA2"}}}}}`
	case "20ca2.playfabapi.com":
		t.playFabRequested = true
		requestBody, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		t.createAccount = strings.Contains(string(requestBody), `"CreateAccount":true`)
		body = `{"code":200,"status":"OK","data":{"EntityToken":{"Entity":{"Id":"entity-id","Type":"title_player_account"},"EntityToken":"entity-token","TokenExpiration":"2099-01-01T00:00:00Z"},"PlayFabId":"playfab-id","SessionTicket":"session-ticket"}}`
	default:
		return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: io.EOF}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}
