package protocol

type PackInstanceID struct {
	UUID        string
	Version     string
	SubPackName string
}

// Marshal reads or writes PackInstanceID using its canonical wire layout.
func (x *PackInstanceID) Marshal(io IO) {
	io.String(&x.UUID)
	io.String(&x.Version)
	io.String(&x.SubPackName)
}

type RequestAbilityType uint8

const (
	PackSettingTypeFloat  RequestAbilityType = 0
	PackSettingTypeBool   RequestAbilityType = 1
	PackSettingTypeString RequestAbilityType = 2
)

// Marshal reads or writes RequestAbilityType through its uint8 wire encoding.
func (x *RequestAbilityType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ResourcePackClientResponseData interface {
	Marshaler
	tagResourcePackClientResponseData() uint32
}

// MarshalResourcePackClientResponseData reads or writes the ResourcePackClientResponseData union using its canonical wire layout.
func MarshalResourcePackClientResponseData(io IO, x *ResourcePackClientResponseData) {
	Union(io, x, io.Varuint32, ResourcePackClientResponseData.tagResourcePackClientResponseData, func(tag uint32) ResourcePackClientResponseData {
		switch tag {
		case 0:
			return new(Cancel)
		case 1:
			return new(Downloading)
		case 2:
			return new(DownloadingFinished)
		case 3:
			return new(ResourcePackStackFinished)
		}
		return nil
	})
}

type ResourcePackStackFinished struct {
	ResponseType string
}

func (*ResourcePackStackFinished) tagResourcePackClientResponseData() uint32 { return 3 }

// Marshal reads or writes ResourcePackStackFinished using its canonical wire layout.
func (x *ResourcePackStackFinished) Marshal(io IO) {
	io.String(&x.ResponseType)
}
