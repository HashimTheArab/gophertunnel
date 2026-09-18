package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ModalFormResponse is sent by the client in response to a ModalFormRequest, after the player has
// submitted the form sent. It contains the options/properties selected by the player, or a JSON
// encoded 'null' if the form was closed by clicking the X at the top right corner of the form.
type ModalFormResponse struct {
	// FormID is the form ID of the form the client has responded to. It is the same as the ID sent in
	// the ModalFormRequest, and may be used to identify which form was submitted.
	FormID uint32
	// JSONResponse is a JSON encoded value representing the response of the player. For a modal form,
	// the response is either true or false, for a menu form, the response is an integer specifying the
	// index of the button clicked, and for a custom form, the response is an array containing a value
	// for each element.
	ResponseData protocol.Optional[string]
	// FormCancelReason represents the reason why the form was cancelled. It is one of the constants
	// above.
	CancelReason protocol.Optional[protocol.ModalFormCancelReason]
}

// Marshal reads or writes ModalFormResponse using its canonical wire layout.
func (x *ModalFormResponse) Marshal(io protocol.IO) {
	io.Varuint32(&x.FormID)
	protocol.OptionalFunc(io, &x.ResponseData, io.String)
	protocol.OptionalMarshaler(io, &x.CancelReason)
}

// ID returns the protocol ID for ModalFormResponse.
func (*ModalFormResponse) ID() uint32 { return IDModalFormResponse }

const (
	ModalFormCancelReasonUserClosed protocol.ModalFormCancelReason = 0
	ModalFormCancelReasonUserBusy   protocol.ModalFormCancelReason = 1
)
