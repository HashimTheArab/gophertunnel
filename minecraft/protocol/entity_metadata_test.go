package protocol

import "testing"

func TestEntityMetadataPlayerSleeping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata EntityMetadata
		want     bool
	}{
		{name: "missing", metadata: nil},
		{name: "player flags", metadata: EntityMetadata{EntityDataKeyPlayerFlags: byte(1 << 1)}, want: true},
		{name: "flags two", metadata: EntityMetadata{EntityDataKeyFlagsTwo: int64(1 << (EntityDataFlagSleeping & 63))}, want: true},
		{name: "unrelated flags", metadata: NewEntityMetadata()},
		{name: "wrong types", metadata: EntityMetadata{EntityDataKeyPlayerFlags: int32(2), EntityDataKeyFlagsTwo: byte(1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.metadata.PlayerSleeping(); got != test.want {
				t.Fatalf("PlayerSleeping() = %t, want %t", got, test.want)
			}
		})
	}
}
