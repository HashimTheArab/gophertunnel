// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package protocol

type TextData interface {
	Marshaler
	tagTextData() uint8
}

// MarshalTextData reads or writes the TextData union using its canonical wire layout.
func MarshalTextData(io IO, x *TextData) {
	Union(io, x, io.Uint8, TextData.tagTextData, func(tag uint8) TextData {
		switch tag {
		case 0:
			return new(MessageOnly)
		case 1:
			return new(AuthorAndMessage)
		case 2:
			return new(MessageAndParams)
		case 3:
			return new(TextDataPopup)
		case 4:
			return new(TextDataJukeboxPopup)
		case 5:
			return new(TextDataTip)
		case 6:
			return new(TextDataSystemMessage)
		case 7:
			return new(TextDataWhisper)
		case 8:
			return new(TextDataAnnouncement)
		case 9:
			return new(TextDataTextObjectWhisper)
		case 10:
			return new(TextDataTextObject)
		case 11:
			return new(TextDataTextObjectAnnouncement)
		}
		return nil
	})
}
