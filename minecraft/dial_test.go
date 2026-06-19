package minecraft

import "testing"

func TestReadChainIdentityDataRejectsShortChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "empty", data: `{"chain":[]}`},
		{name: "one entry", data: `{"chain":["root"]}`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := readChainIdentityData([]byte(tt.data)); err == nil {
				t.Fatal("expected short chain error")
			}
		})
	}
}
