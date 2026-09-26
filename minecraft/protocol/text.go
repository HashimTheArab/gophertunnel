package protocol

type TextData interface {
	Marshaler
	tagTextData() uint32
}

// MarshalTextData reads or writes the TextData union using its canonical wire layout.
func MarshalTextData(io IO, x *TextData) {
	Union(io, x, io.Varuint32, TextData.tagTextData, func(tag uint32) TextData {
		switch tag {
		case 0:
			return new(MessageOnly)
		case 1:
			return new(AuthorAndMessage)
		case 2:
			return new(MessageAndParams)
		}
		return nil
	})
}

type TextPacketType uint8

// Marshal reads or writes TextPacketType through its uint8 wire encoding.
func (x *TextPacketType) Marshal(io IO) { io.Uint8((*uint8)(x)) }
