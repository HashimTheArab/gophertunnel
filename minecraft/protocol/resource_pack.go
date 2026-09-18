package protocol

// PackInstanceID represents a resource pack sent on the stack of the client. When sent, the client will apply
// them in the order of the stack sent.
type PackInstanceID struct {
	// UUID is the UUID of the resource pack. Each resource pack downloaded must have a different UUID in order
	// for the client to be able to handle them properly.
	UUID string
	// Version is the version of the resource pack. The client will cache resource packs sent by the server as
	// long as they carry the same version. Sending a resource pack with a different version than previously will
	// force the client to re-download it.
	Version string
	// SubPackName ...
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
