package minecraft

import (
	"fmt"
	"reflect"
	"testing"
)

// TestStartGameGameDataRoundTrip fails when a GameData field is added without extending
// both StartGameFromGameData and GameDataFromStartGame, so the pair cannot drift apart.
func TestStartGameGameDataRoundTrip(t *testing.T) {
	// These arrive outside StartGame and are deliberately not part of the mapping:
	// Items (ItemRegistry), Dimensions (DimensionData), ChunkRadius (ChunkRadiusUpdated).
	outsideStartGame := map[string]bool{"Items": true, "Dimensions": true, "ChunkRadius": true}

	var data GameData
	value := reflect.ValueOf(&data).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if outsideStartGame[field.Name] {
			continue
		}
		fill(t, value.Field(i), field.Name)
	}

	got := GameDataFromStartGame(StartGameFromGameData(data))
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if outsideStartGame[field.Name] {
			continue
		}
		if !reflect.DeepEqual(value.Field(i).Interface(), reflect.ValueOf(got).Field(i).Interface()) {
			t.Errorf("GameData.%s did not survive the StartGame round trip: map it in both StartGameFromGameData and GameDataFromStartGame", field.Name)
		}
	}
}

// fill sets v to a non-zero value so a dropped field cannot pass as an untouched one.
func fill(t *testing.T, v reflect.Value, name string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.String:
		v.SetString("x-" + name)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		m.SetMapIndex(reflect.Zero(v.Type().Key()), reflect.Zero(v.Type().Elem()))
		v.Set(m)
	case reflect.Array:
		if v.Len() > 0 {
			fill(t, v.Index(0), name)
		}
	case reflect.Struct:
		if v.NumField() > 0 {
			fill(t, v.Field(0), fmt.Sprintf("%s.0", name))
		}
	default:
		t.Fatalf("GameData.%s has kind %v the round-trip filler does not cover; extend fill", name, v.Kind())
	}
}
