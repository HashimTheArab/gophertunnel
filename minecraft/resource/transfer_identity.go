package resource

import "github.com/google/uuid"

type transferIdentity struct {
	uuid    uuid.UUID
	version string
}

// WithTransferIdentity returns an independent pack view identified by the completed transfer's
// advertisement. Manifest metadata, archive bytes and checksum remain unchanged. Bind only after
// assembling the download requested under this identity; never infer a binding from pack order.
func (pack Pack) WithTransferIdentity(id uuid.UUID, version string) *Pack {
	pack.transferIdentity = &transferIdentity{uuid: id, version: version}
	return &pack
}
