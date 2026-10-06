package userstats

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth"
)

const (
	// MinutesPlayed is the accumulated play time, in minutes.
	MinutesPlayed = "MinutesPlayed"
	// BlocksBroken is the total number of blocks broken.
	BlocksBroken = "BlockBrokenTotal"
	// MobsDefeated counts defeated monsters.
	MobsDefeated = "MobKilled.IsMonster.1"
	// DistanceTravelled is the accumulated travel distance.
	DistanceTravelled = "DistanceTravelled"
)

// ProfileStatistics preserves unavailable values separately from a real zero.
type ProfileStatistics struct {
	MinutesPlayed     *string
	BlocksBroken      *string
	MobsDefeated      *string
	DistanceTravelled *string
}

// The retail profile combines statistics across Bedrock's platform service configurations.
var profileServiceConfigIDs = [...]uuid.UUID{
	uuid.MustParse("00000000-0000-0000-0000-000073e3c5ef"),
	uuid.MustParse("00000000-0000-0000-0000-000067b57dac"),
	uuid.MustParse("00000000-0000-0000-0000-00006bf082d7"),
	uuid.MustParse("00000000-0000-0000-0000-00006cfa0c1e"),
	auth.ServiceConfigID,
	uuid.MustParse("00000000-0000-0000-0000-00007a079e33"),
	uuid.MustParse("00000000-0000-0000-0000-000079dbee96"),
}

// Profile reads the four retail Bedrock profile statistics across all platform configurations.
// Values are summed as doubles, with unavailable statistics kept separate from a real zero.
func (c *Client) Profile(ctx context.Context, xuid string) (*ProfileStatistics, error) {
	names := []string{MinutesPlayed, BlocksBroken, MobsDefeated, DistanceTravelled}
	requested := make([]RequestedStatistics, 0, len(profileServiceConfigIDs))
	for _, scid := range profileServiceConfigIDs {
		requested = append(requested, RequestedStatistics{ServiceConfigID: scid, Names: names})
	}
	users, err := c.Batch(ctx, []string{xuid}, requested)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.XUID != xuid {
			continue
		}
		var totals [4]float64
		var available [4]bool
		for _, group := range user.ServiceConfigurations {
			if !slices.Contains(profileServiceConfigIDs[:], group.ServiceConfigID) {
				continue
			}
			for _, statistic := range group.Statistics {
				index := slices.Index(names, statistic.Name)
				value, ok := statistic.NonNegativeNumber()
				if index < 0 || !ok {
					continue
				}
				number, _ := strconv.ParseFloat(value, 64)
				total := totals[index] + number
				if math.IsInf(total, 0) {
					continue
				}
				totals[index], available[index] = total, true
			}
		}
		result := &ProfileStatistics{}
		fields := []**string{&result.MinutesPlayed, &result.BlocksBroken, &result.MobsDefeated, &result.DistanceTravelled}
		for index, field := range fields {
			if available[index] {
				value := strconv.FormatFloat(totals[index], 'f', -1, 64)
				*field = &value
			}
		}
		return result, nil
	}
	return nil, errors.New("service/userstats: response user mismatch")
}

// NonNegativeNumber returns finite, nonnegative numeric text, accepting string and number values.
func (s Statistic) NonNegativeNumber() (string, bool) {
	value := strings.TrimSpace(string(s.Value))
	if strings.HasPrefix(value, "\"") {
		if json.Unmarshal(s.Value, &value) != nil {
			return "", false
		}
		value = strings.TrimSpace(value)
	}
	number, err := strconv.ParseFloat(value, 64)
	return value, err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) && number >= 0
}
