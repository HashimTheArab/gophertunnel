package layout

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

type fixedTokens struct{}

func (fixedTokens) ServiceToken(context.Context) (*service.Token, error) {
	return &service.Token{AuthorizationHeader: "MCToken synthetic", ValidUntil: time.Now().Add(time.Hour)}, nil
}

// Synthesized in the live ServerTab shape, not a captured payload.
const serverTabFixture = `{"result":{"layoutStructure":{"title":{"value":""},
"refreshPolicy":{"timeToLiveInSeconds":3600,"events":[],"minRefreshDelayInSeconds":5},
"body":{"fabs":[
{"$type":"ExperienceFab","id":"hero","variant":"feature-play","title":{"value":"Best fit"},
 "refreshPolicy":{"timeToLiveInSeconds":86400,"minRefreshDelayInSeconds":5},
 "experience":{"experienceId":"b7f5596c-e811-49ec-b318-80ff3c435d1d","mode":"Public","title":{"value":"OneBlock"},
  "creatorName":"Maker","creatorId":"c1","linksTo":{"id":"detail-1","type":"layout"},
  "description":{"value":"Skyblock."},"logoImage":{"full":{"url":"https://cdn.example.test/logo.png"}},
  "activities":[{"title":{"value":"Play"},"subtitle":{"value":""},"description":{"value":"Go"},"image":{"half":{"url":"https://cdn.example.test/a.png"}}}],
  "listing":{"displayImage":{"full":{"url":"https://cdn.example.test/f.png"},"quarter":{"url":"https://cdn.example.test/q.png"}},"motd":{"value":"Hello"}}}},
{"$type":"ExperienceListFab","id":"all","variant":"grid","title":{"value":"All servers"},
 "pagedExperiences":{"experiences":[{"experienceId":"81ac183c-1d09-44a2-b0b5-78abaf8c9877","title":{"value":"Hunt"},"creatorName":"E"},
  {"experienceId":"b7f5596c-e811-49ec-b318-80ff3c435d1d","title":{"value":"OneBlock"}}]}},
{"$type":"UnknownFab","id":"future"}]}}}}`

// A layout is posted by id and decodes its refresh policy, experience fabs and list fabs.
func TestLayoutDecodesTheServerTab(t *testing.T) {
	var method, path, body string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		if r.Header.Get("Authorization") != "MCToken synthetic" {
			t.Error("layout request without the service token")
		}
		_, _ = io.WriteString(w, serverTabFixture)
	}))
	defer server.Close()
	env := new(Environment)
	if err := json.Unmarshal([]byte(`{"serviceUri":"`+server.URL+`"}`), env); err != nil {
		t.Fatal(err)
	}
	env.HTTPClient = server.Client()
	layout, err := env.New(fixedTokens{}).Layout(context.Background(), ServerTab)
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/api/v1.0/layout/ServerTab" || body != "{}" {
		t.Fatalf("request = %s %s %s", method, path, body)
	}
	if layout.RefreshPolicy.TimeToLive() != time.Hour || len(layout.Body.Fabs) != 3 {
		t.Fatalf("layout = %+v", layout)
	}
	hero := layout.Body.Fabs[0]
	if hero.Type != FabExperience || hero.Experience == nil || hero.Experience.Description.Value != "Skyblock." ||
		hero.Experience.Activities[0].Image.URL() != "https://cdn.example.test/a.png" || hero.Experience.Listing.MOTD.Value != "Hello" {
		t.Fatalf("hero = %+v", hero)
	}
	if unknown := layout.Body.Fabs[2]; unknown.Type != "UnknownFab" || len(unknown.Raw) == 0 {
		t.Fatalf("unknown fab = %+v", unknown)
	}
	experiences := layout.Experiences()
	if len(experiences) != 2 || experiences[0].ID != uuid.MustParse("b7f5596c-e811-49ec-b318-80ff3c435d1d") ||
		experiences[1].Title.Value != "Hunt" || experiences[0].Listing.DisplayImage.URL() != "https://cdn.example.test/f.png" {
		t.Fatalf("experiences = %+v", experiences)
	}
}
