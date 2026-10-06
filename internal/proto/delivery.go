package proto

import (
	"encoding/json"
	"errors"
)

// DeliveryKind is an approval-visible stdin semantic, not a requested fallback.
type DeliveryKind string

const (
	SealedMemfd  DeliveryKind = "sealed_memfd"
	SocketStream DeliveryKind = "socket_stream"
)

// Empty is the historical sealed regular-file contract.
func (k DeliveryKind) Valid() bool { return k == "" || k == SealedMemfd || k == SocketStream }
func (k DeliveryKind) Effective() DeliveryKind {
	if k == "" {
		return SealedMemfd
	}
	return k
}
func (k *DeliveryKind) UnmarshalJSON(data []byte) error {
	var value string
	if string(data) == "null" {
		return errors.New("null captured delivery kind")
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	kind := DeliveryKind(value)
	if kind == "" || !kind.Valid() {
		return errors.New("unknown captured delivery kind")
	}
	*k = kind
	return nil
}
