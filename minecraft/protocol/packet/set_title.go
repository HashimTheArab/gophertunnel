// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SetTitle is sent by the server to make a title, subtitle or action bar shown to a player. It has
// several fields that allow setting the duration of the titles.
type SetTitle struct {
	TitleType   protocol.TitleType
	TitleText   string
	FadeInTime  int32
	StayTime    int32
	FadeOutTime int32
	// Xuid is the XBOX Live user ID of the player, which will remain consistent as long as the player
	// is logged in with the XBOX Live account. It is empty if the user is not logged into its XBL
	// account.
	XUID string
	// PlatformOnlineID is either a uint64 or an empty string.
	PlatformOnlineID     string
	FilteredTitleMessage string
}

// Marshal reads or writes SetTitle using its canonical wire layout.
func (x *SetTitle) Marshal(io protocol.IO) {
	x.TitleType.Marshal(io)
	io.String(&x.TitleText)
	io.Varint32(&x.FadeInTime)
	io.Varint32(&x.StayTime)
	io.Varint32(&x.FadeOutTime)
	io.String(&x.XUID)
	io.String(&x.PlatformOnlineID)
	io.String(&x.FilteredTitleMessage)
}

// ID returns the protocol ID for SetTitle.
func (*SetTitle) ID() uint32 { return IDSetTitle }

const (
	TitleActionClear               protocol.TitleType = 0
	TitleActionReset               protocol.TitleType = 1
	TitleActionSetTitle            protocol.TitleType = 2
	TitleActionSetSubtitle         protocol.TitleType = 3
	TitleActionSetActionBar        protocol.TitleType = 4
	TitleActionSetDurations        protocol.TitleType = 5
	TitleActionTitleTextObject     protocol.TitleType = 6
	TitleActionSubtitleTextObject  protocol.TitleType = 7
	TitleActionActionbarTextObject protocol.TitleType = 8
)
