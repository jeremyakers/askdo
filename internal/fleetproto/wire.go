package fleetproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/jeremyakers/askdo/internal/proto"
)

var (
	ErrProtocol  = errors.New("invalid fleet protocol")
	ErrSignature = errors.New("invalid fleet signature")
	ErrBinding   = errors.New("fleet frozen binding mismatch")
	ErrExpired   = errors.New("fleet proof expired")
)

// Parse rejects duplicate/unknown/case-alias keys, absent required fields,
// nulls, invalid unions and bounds. Unsigned parsing never confers authority.
func Parse[T Payload](data []byte) (T, error) {
	var value T
	if err := strict(data, &value, MaxPayloadBytes); err != nil {
		return value, err
	}
	if err := Validate(value); err != nil {
		var zero T
		return zero, err
	}
	return value, nil
}

func Sign[T Payload](key ed25519.PrivateKey, value T) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	if err := Validate(value); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode", ErrProtocol)
	}
	// Apply the same structural requirements as the remote boundary.
	if _, err := Parse[T](payload); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, append([]byte(SigningDomain), payload...))
	return json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)})
}

// Verify authenticates the original decoded payload bytes BEFORE payload JSON
// parsing. Returned payload is suitable for exact-byte audit persistence.
func Verify[T Payload](key ed25519.PublicKey, wire []byte) (T, []byte, error) {
	var zero T
	var env Envelope
	if err := strict(wire, &env, MaxEnvelopeBytes); err != nil {
		return zero, nil, err
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes || base64.StdEncoding.EncodeToString(payload) != env.Payload {
		return zero, nil, ErrProtocol
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signature || len(key) != ed25519.PublicKeySize {
		return zero, nil, ErrSignature
	}
	if !ed25519.Verify(key, append([]byte(SigningDomain), payload...), sig) {
		return zero, nil, ErrSignature
	}
	value, err := Parse[T](payload)
	if err != nil {
		return zero, nil, err
	}
	return value, payload, nil
}

func strict(data []byte, dst any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return ErrProtocol
	}
	if err := proto.StrictUnmarshal(data, dst); err != nil {
		return fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	if err := shape(data, reflect.TypeOf(dst).Elem(), 0); err != nil {
		return fmt.Errorf("%w: required JSON shape", ErrProtocol)
	}
	return nil
}

// The standard JSON decoder accepts case-insensitive names and zeroes missing
// fields. This closed typed shape pass supplies the stricter network semantics,
// including required numeric zero values (root UID, upstream index).
func shape(data []byte, typ reflect.Type, depth int) error {
	if depth > 64 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ErrProtocol
	}
	if typ == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	if typ.Kind() == reflect.Pointer {
		return shape(data, typ.Elem(), depth+1)
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
			return ErrProtocol
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			if name == "" || name == "-" {
				return ErrProtocol
			}
			raw, exists := fields[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !exists {
				if optional {
					continue
				}
				return ErrProtocol
			}
			if err := shape(raw, f.Type, depth+1); err != nil {
				return err
			}
			delete(fields, name)
		}
		if len(fields) != 0 {
			return ErrProtocol
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return ErrProtocol
		}
		for _, item := range items {
			if err := shape(item, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func digest(data []byte) Hash { sum := sha256.Sum256(data); return Hash(hex.EncodeToString(sum[:])) }

// HashSubmissionBytes validates before hashing the exact network submission.
func HashSubmissionBytes(data []byte) (Hash, error) {
	if _, err := Parse[TicketSubmission](data); err != nil {
		return "", err
	}
	return digest(data), nil
}
func HashProfile(p ProfileMetadata) (Hash, error) {
	p.Revision = ""
	if err := profile(p, false); err != nil {
		return "", err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("%w: metadata", ErrProtocol)
	}
	return digest(data), nil
}
func HashRoute(r RouteSnapshot) (Hash, error) {
	r.Revision = ""
	if err := route(r, false); err != nil {
		return "", err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("%w: metadata", ErrProtocol)
	}
	return digest(data), nil
}

// HashProfiles binds the complete ordered selection, including an explicit empty
// selection for human-only review. Individual revisions remain self-verifying.
func HashProfiles(profiles []ProfileMetadata) (Hash, error) {
	if profiles == nil || len(profiles) > MaxProfiles {
		return "", ErrProtocol
	}
	ids := map[ID]bool{}
	for _, p := range profiles {
		if ids[p.ProfileID] {
			return "", ErrProtocol
		}
		ids[p.ProfileID] = true
		if err := Validate(p); err != nil {
			return "", err
		}
	}
	data, err := json.Marshal(profiles)
	if err != nil {
		return "", ErrProtocol
	}
	return digest(data), nil
}
func HashDisplay(d Display) (Hash, error) {
	if err := display(d); err != nil {
		return "", err
	}
	data, err := json.Marshal(d)
	if err != nil || len(data) > 65536 {
		return "", ErrProtocol
	}
	return digest(data), nil
}

// HashReceipt is over deterministic typed receipt bytes, not its envelope.
func HashReceipt(r Receipt) (Hash, error) {
	if err := Validate(r); err != nil {
		return "", err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return "", ErrProtocol
	}
	return digest(data), nil
}
