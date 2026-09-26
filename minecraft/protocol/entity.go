package protocol

type EntityCommandTarget struct {
	TargetEntityRuntimeID uint64
}

func (*EntityCommandTarget) tagCommandBlockUpdateData() uint32 { return 0 }

// Marshal reads or writes EntityCommandTarget using its canonical wire layout.
func (x *EntityCommandTarget) Marshal(io IO) {
	io.ActorRuntimeID(&x.TargetEntityRuntimeID)
}

type EntityNetID struct {
	RawID uint32
}

// Marshal reads or writes EntityNetID using its canonical wire layout.
func (x *EntityNetID) Marshal(io IO) {
	io.Varuint32(&x.RawID)
}
