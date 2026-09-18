package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

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

// SetTitle is sent by the server to make a title, subtitle or action bar shown to a player. It has several
// fields that allow setting the duration of the titles.
type SetTitle struct {
	ActionType      protocol.TitleType
	Text            string
	FadeInDuration  int32
	RemainDuration  int32
	FadeOutDuration int32
	// Xuid is the XBOX Live user ID of the player, which will remain consistent as long as the player is logged
	// in with the XBOX Live account. It is empty if the user is not logged into its XBL account.
	XUID string
	// PlatformOnlineID is either a uint64 or an empty string.
	PlatformOnlineID string
	FilteredMessage  string
}

// Marshal reads or writes SetTitle using its canonical wire layout.
func (x *SetTitle) Marshal(io protocol.IO) {
	x.ActionType.Marshal(io)
	io.String(&x.Text)
	io.Varint32(&x.FadeInDuration)
	io.Varint32(&x.RemainDuration)
	io.Varint32(&x.FadeOutDuration)
	io.String(&x.XUID)
	io.String(&x.PlatformOnlineID)
	io.String(&x.FilteredMessage)
}

// ID returns the protocol ID for SetTitle.
func (*SetTitle) ID() uint32 { return IDSetTitle }
