package userstats

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/auth"
)

func TestProfileBatchesAndKeepsUnavailableValues(t *testing.T) {
	calls := 0
	client := NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var body struct {
			Groups []RequestedStatistics `json:"requestedscids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Groups) != len(profileServiceConfigIDs) || body.Groups[4].ServiceConfigID != auth.ServiceConfigID || len(body.Groups[0].Names) != 4 {
			t.Fatal("wrong profile selection")
		}
		raw, _ := json.Marshal(map[string]any{"users": []any{map[string]any{"xuid": "1", "scids": []any{map[string]any{
			"scid": auth.ServiceConfigID, "stats": []any{
				map[string]any{"statname": MinutesPlayed, "type": "Double", "value": "12.5"},
				map[string]any{"statname": BlocksBroken, "type": "Integer", "value": 0},
				map[string]any{"statname": MobsDefeated, "type": "Double", "value": "NaN"},
				map[string]any{"statname": DistanceTravelled, "type": "Double", "value": "-1"},
			},
		}}}}})
		return response(http.StatusOK, string(raw)), nil
	})})
	stats, err := client.Profile(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || *stats.MinutesPlayed != "12.5" || *stats.BlocksBroken != "0" || stats.MobsDefeated != nil || stats.DistanceTravelled != nil {
		t.Fatalf("profile=%+v calls=%d", stats, calls)
	}
}

func TestStatisticNonNegativeNumber(t *testing.T) {
	for _, raw := range []string{`null`, `true`, `{}`, `[]`, `"NaN"`, `"Inf"`, `"-Inf"`, `-2`, `"1e500"`} {
		if _, ok := (Statistic{Value: json.RawMessage(raw)}).NonNegativeNumber(); ok {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`0`, `"0"`, `12.5`, `"12.5"`, `" 12.5 "`} {
		if _, ok := (Statistic{Value: json.RawMessage(raw)}).NonNegativeNumber(); !ok {
			t.Errorf("rejected %s", raw)
		}
	}
}

func TestProfileSumsConfigurationsAndIgnoresOtherUsers(t *testing.T) {
	client := NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body struct {
			Groups []RequestedStatistics `json:"requestedscids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		groups := make([]ServiceStatistics, 0, len(profileServiceConfigIDs))
		for i, scid := range profileServiceConfigIDs {
			if body.Groups[i].ServiceConfigID != scid {
				t.Fatal("platform request order changed")
			}
			for index, name := range []string{MinutesPlayed, BlocksBroken, MobsDefeated, DistanceTravelled} {
				if body.Groups[i].Names[index] != name {
					t.Fatal("statistic request order changed")
				}
			}
			groups = append(groups, ServiceStatistics{ServiceConfigID: scid, Statistics: []Statistic{{Name: MinutesPlayed, Value: json.RawMessage(`"1.5"`)}}})
		}
		raw, _ := json.Marshal(struct {
			Users []UserStatistics `json:"users"`
		}{[]UserStatistics{{XUID: "2", ServiceConfigurations: groups}, {XUID: "1", ServiceConfigurations: groups}}})
		return response(http.StatusOK, string(raw)), nil
	})})
	stats, err := client.Profile(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	if stats.MinutesPlayed == nil || *stats.MinutesPlayed != "10.5" || stats.BlocksBroken != nil {
		t.Fatalf("profile=%+v", stats)
	}
}

func TestProfileMissingUser(t *testing.T) {
	client := NewClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"users":[{"xuid":"2","scids":[]}]}`), nil
	})})
	if _, err := client.Profile(context.Background(), "1"); err == nil {
		t.Fatal("accepted another user's statistics")
	}
}
