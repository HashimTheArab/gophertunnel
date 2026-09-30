package protocol

import (
	"bytes"
	"fmt"
	"maps"
	"math"

	"github.com/sandertv/gophertunnel/minecraft/nbt"
)

const maxTradeOffers = 1024

// TradeItem is an item advertised in an UpdateTrade offer. It uses a named
// item NBT compound, rather than an ItemStack's runtime item ID. Zero values
// represent an absent ingredient or an unavailable placeholder offer.
type TradeItem struct {
	Name     string
	Metadata int16
	Count    byte

	compound map[string]any
}

// NBT returns the named item compound for this item, including any server
// supplied item tags or block state. Nested values are read-only. The top-level
// map is detached so changing its keys cannot change the advertised item.
func (i TradeItem) NBT() map[string]any {
	return maps.Clone(i.compound)
}

// TradeOffer is one recipe advertised by UpdateTrade. NetworkID identifies
// the recipe in a CraftRecipeStackRequestAction; it is not a list index.
// Counts are retained as advertised: servers may already include demand,
// reputation, or special-price adjustments in BuyA and BuyB. Reapplying those
// adjustments from BaseCountA/BaseCountB would charge a different price.
type TradeOffer struct {
	NetworkID        uint32
	Tier             int32
	Uses             int32
	MaxUses          int32
	BuyA             TradeItem
	BuyB             TradeItem
	Sell             TradeItem
	BaseCountA       int32
	BaseCountB       int32
	Demand           int32
	PriceMultiplierA float32
	PriceMultiplierB float32
}

// DecodeTradeOffers decodes the network NBT offer compound in UpdateTrade.
// Unknown offer and item fields are permitted; item NBT is retained intact.
// Malformed fields fail the complete decode, rather than silently changing
// the price or the identity of an ingredient.
func DecodeTradeOffers(data []byte) ([]TradeOffer, error) {
	buffer := bytes.NewBuffer(data)
	var root map[string]any
	if err := nbt.NewDecoderWithEncoding(buffer, nbt.NetworkLittleEndian).Decode(&root); err != nil {
		return nil, fmt.Errorf("decode trade offers: %w", err)
	}
	if buffer.Len() != 0 {
		return nil, fmt.Errorf("decode trade offers: trailing NBT data")
	}
	value, present := root["Recipes"]
	if !present {
		return nil, fmt.Errorf("decode trade offers: missing Recipes")
	}
	list, ok := value.([]any)
	if !ok || len(list) > maxTradeOffers {
		return nil, fmt.Errorf("decode trade offers: invalid Recipes")
	}
	offers := make([]TradeOffer, len(list))
	for index, value := range list {
		compound, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("decode trade offer %d: expected compound", index)
		}
		offer, err := decodeTradeOffer(compound)
		if err != nil {
			return nil, fmt.Errorf("decode trade offer %d: %w", index, err)
		}
		offers[index] = offer
	}
	return offers, nil
}

func decodeTradeOffer(compound map[string]any) (TradeOffer, error) {
	var offer TradeOffer
	var networkID int32
	ints := []struct {
		key string
		out *int32
	}{
		{"netId", &networkID}, {"tier", &offer.Tier},
		{"uses", &offer.Uses}, {"maxUses", &offer.MaxUses},
		{"buyCountA", &offer.BaseCountA}, {"buyCountB", &offer.BaseCountB},
		{"demand", &offer.Demand},
	}
	for _, field := range ints {
		if value, present := compound[field.key]; present {
			var ok bool
			*field.out, ok = value.(int32)
			if !ok {
				return offer, fmt.Errorf("%s: expected int", field.key)
			}
		}
	}
	if networkID < 0 || offer.Tier < 0 || offer.Uses < 0 || offer.MaxUses < 0 ||
		offer.BaseCountA < 0 || offer.BaseCountB < 0 {
		return offer, fmt.Errorf("negative recipe identity, tier, uses, or base count")
	}
	offer.NetworkID = uint32(networkID)
	for _, field := range []struct {
		key string
		out *float32
	}{
		{"priceMultiplierA", &offer.PriceMultiplierA},
		{"priceMultiplierB", &offer.PriceMultiplierB},
	} {
		if value, present := compound[field.key]; present {
			var ok bool
			*field.out, ok = value.(float32)
			if !ok || math.IsNaN(float64(*field.out)) || math.IsInf(float64(*field.out), 0) {
				return offer, fmt.Errorf("%s: expected finite float", field.key)
			}
		}
	}
	for _, field := range []struct {
		key string
		out *TradeItem
	}{
		{"buyA", &offer.BuyA}, {"buyB", &offer.BuyB}, {"sell", &offer.Sell},
	} {
		if value, present := compound[field.key]; present {
			var err error
			*field.out, err = decodeTradeItem(value)
			if err != nil {
				return offer, fmt.Errorf("%s: %w", field.key, err)
			}
		}
	}
	return offer, nil
}

func decodeTradeItem(value any) (TradeItem, error) {
	compound, ok := value.(map[string]any)
	if !ok {
		return TradeItem{}, fmt.Errorf("expected item compound")
	}
	if len(compound) == 0 {
		return TradeItem{}, nil
	}
	name, ok := compound["Name"].(string)
	if !ok || name == "" {
		return TradeItem{}, fmt.Errorf("invalid Name")
	}
	count, ok := compound["Count"].(byte)
	if !ok {
		return TradeItem{}, fmt.Errorf("Count: expected byte")
	}
	metadata, ok := compound["Damage"].(int16)
	if !ok {
		return TradeItem{}, fmt.Errorf("Damage: expected short")
	}
	if tag, present := compound["tag"]; present {
		if _, ok := tag.(map[string]any); !ok {
			return TradeItem{}, fmt.Errorf("tag: expected compound")
		}
	}
	return TradeItem{Name: name, Metadata: metadata, Count: count, compound: compound}, nil
}
