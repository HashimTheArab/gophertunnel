package packet

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestPlayerAuthInput_NormalizeYaw(t *testing.T) {
	for _, tc := range []struct{ in, want float32 }{
		{0, 0}, {-90, -90}, {179.5, 179.5}, {-180, -180}, {180, -180}, {270, -90}, {344, -16}, {360, 0}, {-181, 179}, {720, 0}, {-540, -180},
		{1e20, -88}, {-1e20, 88}, {math.MaxFloat32, 0}, {-math.MaxFloat32, 0},
	} {
		pk := PlayerAuthInput{Yaw: tc.in, HeadYaw: tc.in, InteractYaw: tc.in, Pitch: 25, InteractPitch: -30}
		changed := pk.NormalizeYaw()
		if pk.Yaw != tc.want || pk.HeadYaw != tc.want || pk.InteractYaw != tc.want || changed != (tc.in != tc.want) {
			t.Fatalf("input=%v: got yaw=%v/%v/%v changed=%t, want %v", tc.in, pk.Yaw, pk.HeadYaw, pk.InteractYaw, changed, tc.want)
		}
		if pk.Pitch != 25 || pk.InteractPitch != -30 || pk.NormalizeYaw() {
			t.Fatal("normalization changed pitch or was not idempotent")
		}
	}
	for _, v := range []float32{float32(math.NaN()), float32(math.Inf(1)), float32(math.Inf(-1))} {
		pk := PlayerAuthInput{Yaw: v, HeadYaw: v, InteractYaw: v}
		if pk.NormalizeYaw() || math.Float32bits(pk.Yaw) != math.Float32bits(v) {
			t.Fatal("non-finite yaw was altered")
		}
	}
}

// TestPlayerAuthInput_NormalizeYawCoversEveryYaw guards new yaw fields.
func TestPlayerAuthInput_NormalizeYawCoversEveryYaw(t *testing.T) {
	pk := PlayerAuthInput{}
	value := reflect.ValueOf(&pk).Elem()
	for i := 0; i < value.NumField(); i++ {
		if strings.HasSuffix(value.Type().Field(i).Name, "Yaw") {
			value.Field(i).SetFloat(270)
		}
	}
	pk.NormalizeYaw()
	for i := 0; i < value.NumField(); i++ {
		if strings.HasSuffix(value.Type().Field(i).Name, "Yaw") && value.Field(i).Float() != -90 {
			t.Errorf("%s was not normalized", value.Type().Field(i).Name)
		}
	}
}
