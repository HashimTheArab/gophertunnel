package protocol

import (
	"bytes"
	"math"
	"reflect"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/nbt"
)

func TestTrade_DecodeAdvertisedOffers(t *testing.T) {
	t.Parallel()
	buyA := tradeTestItem("minecraft:emerald", 14)
	buyB := tradeTestItem("minecraft:book", 1)
	sell := tradeTestItem("minecraft:enchanted_book", 1)
	sell["Damage"] = int16(6)
	sell["tag"] = map[string]any{"ench": []any{map[string]any{"id": int16(26), "lvl": int16(1)}}}
	sell["server_item_field"] = int64(17)
	root := map[string]any{"Recipes": []any{map[string]any{
		"netId": int32(42), "tier": int32(2), "uses": int32(3), "maxUses": int32(12),
		"buyA": buyA, "buyB": buyB, "sell": sell,
		"buyCountA": int32(10), "buyCountB": int32(1), "demand": int32(4),
		"priceMultiplierA": float32(0.2), "priceMultiplierB": float32(0.1),
		"future_offer_field": "preserved on the packet",
	}}}
	wire, err := nbt.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(wire)
	offers, err := DecodeTradeOffers(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 1 {
		t.Fatalf("offers = %d, want 1", len(offers))
	}
	// Every public offer field must be explicitly covered: extending the typed
	// view without extending its decoder or this fixture cannot silently pass.
	want := map[string]any{
		"NetworkID": uint32(42), "Tier": int32(2), "Uses": int32(3), "MaxUses": int32(12),
		"BuyA":       TradeItem{Name: "minecraft:emerald", Count: 14, compound: buyA},
		"BuyB":       TradeItem{Name: "minecraft:book", Count: 1, compound: buyB},
		"Sell":       TradeItem{Name: "minecraft:enchanted_book", Metadata: 6, Count: 1, compound: sell},
		"BaseCountA": int32(10), "BaseCountB": int32(1), "Demand": int32(4),
		"PriceMultiplierA": float32(0.2), "PriceMultiplierB": float32(0.1),
	}
	typed := reflect.ValueOf(offers[0])
	for index := 0; index < typed.NumField(); index++ {
		name := typed.Type().Field(index).Name
		expected, present := want[name]
		if !present {
			t.Fatalf("TradeOffer field %s has no decoder fixture", name)
		}
		if got := typed.Field(index).Interface(); !reflect.DeepEqual(got, expected) {
			t.Errorf("%s = %#v, want %#v", name, got, expected)
		}
	}
	if !reflect.DeepEqual(offers[0].Sell.NBT(), sell) {
		t.Fatal("named item compound lost its tags or unknown fields")
	}
	if !bytes.Equal(before, wire) {
		t.Fatal("offer decode modified the serialised packet")
	}
	itemNBT := offers[0].Sell.NBT()
	itemNBT["Count"] = byte(9)
	if offers[0].Sell.NBT()["Count"] != byte(1) {
		t.Fatal("returned top-level item compound aliases the advertised item")
	}
}

func TestTrade_EmptyIngredientsAndHiddenOffers(t *testing.T) {
	t.Parallel()
	root := map[string]any{"Recipes": []any{
		map[string]any{"netId": int32(7), "sell": tradeTestItem("minecraft:bread", 2),
			"buyA": tradeTestItem("minecraft:emerald", 1), "buyB": map[string]any{}, "maxUses": int32(10)},
		map[string]any{"tier": int32(5), "maxUses": int32(0)},
	}}
	wire, err := nbt.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	offers, err := DecodeTradeOffers(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 2 || offers[0].BuyB.Count != 0 || offers[1].NetworkID != 0 || offers[1].Sell.Count != 0 {
		t.Fatalf("unexpected offers: %#v", offers)
	}
}

func TestTrade_RejectMalformedOffers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		root map[string]any
	}{
		{"missing list", map[string]any{}},
		{"wrong list type", map[string]any{"Recipes": "trades"}},
		{"wrong offer type", map[string]any{"Recipes": []any{int32(1)}}},
		{"wrong identity type", tradeTestRoot(map[string]any{"netId": "1"})},
		{"negative uses", tradeTestRoot(map[string]any{"uses": int32(-1)})},
		{"negative base count", tradeTestRoot(map[string]any{"buyCountA": int32(-1)})},
		{"nan multiplier", tradeTestRoot(map[string]any{"priceMultiplierA": float32(math.NaN())})},
		{"wrong item type", tradeTestRoot(map[string]any{"buyA": "emerald"})},
		{"missing item name", tradeTestRoot(map[string]any{"buyA": map[string]any{"Count": byte(1), "Damage": int16(0)}})},
		{"wrong item count type", tradeTestRoot(map[string]any{"buyA": map[string]any{"Name": "minecraft:emerald", "Count": int32(1), "Damage": int16(0)}})},
		{"wrong item metadata type", tradeTestRoot(map[string]any{"buyA": map[string]any{"Name": "minecraft:emerald", "Count": byte(1), "Damage": int32(0)}})},
		{"wrong item tag type", tradeTestRoot(map[string]any{"buyA": map[string]any{"Name": "minecraft:emerald", "Count": byte(1), "Damage": int16(0), "tag": "data"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := nbt.Marshal(tc.root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeTradeOffers(wire); err == nil {
				t.Fatal("malformed offers accepted")
			}
		})
	}
}

func TestTrade_RejectMalformedNBT(t *testing.T) {
	t.Parallel()
	valid, err := nbt.Marshal(map[string]any{"Recipes": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, {0}, valid[:len(valid)-1], append(bytes.Clone(valid), 0)} {
		if _, err := DecodeTradeOffers(data); err == nil {
			t.Fatalf("malformed NBT %x accepted", data)
		}
	}
}

func TestTrade_BoundedRecipeCount(t *testing.T) {
	t.Parallel()
	list := make([]any, maxTradeOffers+1)
	for index := range list {
		list[index] = map[string]any{}
	}
	wire, err := nbt.Marshal(map[string]any{"Recipes": list})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTradeOffers(wire); err == nil {
		t.Fatal("unbounded recipe list accepted")
	}
}

func tradeTestItem(name string, count byte) map[string]any {
	return map[string]any{"Name": name, "Count": count, "Damage": int16(0)}
}

func tradeTestRoot(offer map[string]any) map[string]any {
	return map[string]any{"Recipes": []any{offer}}
}
