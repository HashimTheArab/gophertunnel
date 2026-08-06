package protocol

import (
	"bytes"
	"testing"
)

func TestPresenceInfo_WireFormat(t *testing.T) {
	tests := []struct {
		name string
		info PresenceInfo
		want []byte
	}{
		{
			name: "default presence",
			want: []byte{0},
		},
		{
			name: "rich presence override",
			info: PresenceInfo{RichPresenceID: Option("dimension_clash")},
			want: append([]byte{1, 15}, []byte("dimension_clash")...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			tt.info.Marshal(NewWriter(buf, 0))
			if got := buf.Bytes(); !bytes.Equal(got, tt.want) {
				t.Fatalf("encoded PresenceInfo = %x, want %x", got, tt.want)
			}

			var got PresenceInfo
			got.Marshal(NewReader(bytes.NewBuffer(tt.want), 0, true))
			gotID, gotOK := got.RichPresenceID.Value()
			wantID, wantOK := tt.info.RichPresenceID.Value()
			if gotOK != wantOK || gotID != wantID {
				t.Fatalf("decoded rich presence = (%q, %t), want (%q, %t)", gotID, gotOK, wantID, wantOK)
			}
		})
	}
}

func TestServerJoinInformation_PresenceWireFormat(t *testing.T) {
	tests := []struct {
		name string
		info ServerJoinInformation
		want []byte
	}{
		{
			name: "no presence information",
			want: []byte{0, 0, 0},
		},
		{
			name: "default presence information",
			info: ServerJoinInformation{PresenceInfo: Option(PresenceInfo{})},
			want: []byte{0, 0, 1, 0},
		},
		{
			name: "rich presence override",
			info: ServerJoinInformation{PresenceInfo: Option(PresenceInfo{RichPresenceID: Option("rp")})},
			want: []byte{0, 0, 1, 1, 2, 'r', 'p'},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			tt.info.Marshal(NewWriter(buf, 0))
			if got := buf.Bytes(); !bytes.Equal(got, tt.want) {
				t.Fatalf("encoded ServerJoinInformation = %x, want %x", got, tt.want)
			}
		})
	}
}
