package protocol

import (
	"bytes"
	"errors"
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
		return nil, errors.New("decode trade offers: trailing NBT data")
	}
	var list []any
	if err := tradeRequired(root, "Recipes", &list); err != nil {
		return nil, fmt.Errorf("decode trade offers: %w", err)
	}
	if len(list) > maxTradeOffers {
		return nil, fmt.Errorf("decode trade offers: %d recipes exceed limit %d", len(list), maxTradeOffers)
	}
	offers := make([]TradeOffer, len(list))
	for index, value := range list {
		compound, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("decode trade offer %d: expected compound", index)
		}
		if err := offers[index].decode(compound); err != nil {
			return nil, fmt.Errorf("decode trade offer %d: %w", index, err)
		}
	}
	return offers, nil
}

func (offer *TradeOffer) decode(compound map[string]any) error {
	var networkID int32
	err := errors.Join(
		tradeCounter(compound, "netId", &networkID),
		tradeCounter(compound, "tier", &offer.Tier),
		tradeCounter(compound, "uses", &offer.Uses),
		tradeCounter(compound, "maxUses", &offer.MaxUses),
		tradeCounter(compound, "buyCountA", &offer.BaseCountA),
		tradeCounter(compound, "buyCountB", &offer.BaseCountB),
		tradeOptional(compound, "demand", &offer.Demand),
		tradeMultiplier(compound, "priceMultiplierA", &offer.PriceMultiplierA),
		tradeMultiplier(compound, "priceMultiplierB", &offer.PriceMultiplierB),
		offer.BuyA.decode(compound, "buyA"),
		offer.BuyB.decode(compound, "buyB"),
		offer.Sell.decode(compound, "sell"),
	)
	offer.NetworkID = uint32(networkID)
	return err
}

// decode reads the optional item compound under key. An absent or empty
// compound leaves the item zero.
func (i *TradeItem) decode(offer map[string]any, key string) error {
	var compound, tag map[string]any
	if err := tradeOptional(offer, key, &compound); err != nil || len(compound) == 0 {
		return err
	}
	err := errors.Join(
		tradeRequired(compound, "Name", &i.Name),
		tradeRequired(compound, "Count", &i.Count),
		tradeRequired(compound, "Damage", &i.Metadata),
		tradeOptional(compound, "tag", &tag),
	)
	if err == nil && i.Name == "" {
		err = errors.New("empty Name")
	}
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	i.compound = compound
	return nil
}

// tradeRequired stores compound[key] in out, failing if it is absent or not
// of the NBT type T.
func tradeRequired[T any](compound map[string]any, key string, out *T) error {
	value, ok := compound[key].(T)
	if !ok {
		return fmt.Errorf("%s: expected %T", key, value)
	}
	*out = value
	return nil
}

// tradeOptional is tradeRequired for fields that default to zero when absent.
func tradeOptional[T any](compound map[string]any, key string, out *T) error {
	if _, present := compound[key]; !present {
		return nil
	}
	return tradeRequired(compound, key, out)
}

// tradeCounter reads an optional recipe ID, tier, use count or base count,
// none of which may be negative.
func tradeCounter(compound map[string]any, key string, out *int32) error {
	if err := tradeOptional(compound, key, out); err != nil || *out >= 0 {
		return err
	}
	return fmt.Errorf("%s: negative value %d", key, *out)
}

func tradeMultiplier(compound map[string]any, key string, out *float32) error {
	if err := tradeOptional(compound, key, out); err != nil ||
		!math.IsNaN(float64(*out)) && !math.IsInf(float64(*out), 0) {
		return err
	}
	return fmt.Errorf("%s: expected finite float", key)
}
