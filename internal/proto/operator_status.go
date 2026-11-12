package proto

import "errors"

// OperatorStatusRequest reads only a fixed non-secret projection, never a path
// or arbitrary command supplied by a socket peer.
type OperatorStatusRequest struct {
	Op string `json:"op"`
	View string `json:"view"`
}
func (*OperatorStatusRequest) IsRequest() {}
func (r OperatorStatusRequest) Validate() error {
	if r.Op != "operator_status" || (r.View != "review" && r.View != "fleet" && r.View != "hosts") {
		return errors.New("invalid operator status request")
	}
	return nil
}
type OperatorStatusEvent struct {
	Op string `json:"op"`
	Text string `json:"text"`
}
