package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	// ErrDuplicateJSONKey reports an object containing a repeated key.
	ErrDuplicateJSONKey = errors.New("duplicate JSON object key")
	// ErrNULInJSONString reports a decoded string containing NUL.
	ErrNULInJSONString = errors.New("NUL in JSON string")
	// ErrInvalidJSONUTF8 reports a byte stream that is not valid UTF-8.
	ErrInvalidJSONUTF8 = errors.New("JSON is not valid UTF-8")
)

// Request is implemented by wire types that ask a component to do something:
// a client's request to the broker, a host's request to the gateway, a worker's
// tool or model request and the arguments of each, a helper's claim and the
// instructions it receives. Decoding a Request refuses a field the type does
// not define, because silently dropping it could change what is done.
//
// Every other wire type reports or describes something: a result, event,
// catalog, receipt, capability, status or configuration projection. Decoders
// ignore the fields of a report they do not know, so a newer peer can add to
// what it reports without an older reader refusing the whole message. Mark a
// type with an IsRequest method only if it asks a component to act, and do not
// embed a Request in a report: embedding promotes the marker.
type Request interface{ IsRequest() }

// RejectsUnknownFields reports whether a strict decode into dst refuses fields
// that dst's type does not define, because dst is a Request. Decoders outside
// this package that check shape themselves (fleetproto) ask the same question.
func RejectsUnknownFields(dst any) bool {
	_, request := dst.(Request)
	return request
}

// StrictUnmarshal decodes one JSON value while rejecting duplicate object keys,
// NUL-containing strings, invalid UTF-8 and trailing values. Fields dst does not
// define are ignored, unless dst is a Request, which refuses them: a newer peer
// may add fields to what it reports, and an older reader must keep working
// rather than refuse it.
func StrictUnmarshal(data []byte, dst any) error {
	return strictUnmarshal(data, dst, false, false)
}

// StrictRequestUnmarshal is StrictUnmarshal that always rejects unknown fields,
// whatever dst is. Use it for administrator configuration, which tells askdo
// what to do but is not one typed Request that could be marked.
func StrictRequestUnmarshal(data []byte, dst any) error {
	return strictUnmarshal(data, dst, false, true)
}

// StrictUnmarshalAllowNUL decodes like StrictUnmarshal, except that valid JSON
// string escapes decoding to NUL bytes are accepted. It exists for
// model-generated content (review report fields, progress details) where
// escaped control characters are legitimate data; protocol metadata such as
// paths and identifiers must keep using StrictUnmarshal.
func StrictUnmarshalAllowNUL(data []byte, dst any) error {
	return strictUnmarshal(data, dst, true, false)
}

func strictUnmarshal(data []byte, dst any, allowNUL, rejectUnknown bool) error {
	if !utf8.Valid(data) {
		return ErrInvalidJSONUTF8
	}
	if err := scanStrictJSON(data, allowNUL); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if rejectUnknown || RejectsUnknownFields(dst) {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("multiple JSON values")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

type jsonScope struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

func scanStrictJSON(data []byte, allowNUL bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stack []jsonScope
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if text, ok := token.(string); ok {
			if !allowNUL && bytes.IndexByte([]byte(text), 0) >= 0 {
				return ErrNULInJSONString
			}
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				top := &stack[len(stack)-1]
				if _, exists := top.keys[text]; exists {
					return fmt.Errorf("%w: %q", ErrDuplicateJSONKey, text)
				}
				top.keys[text] = struct{}{}
				top.expectKey = false
				continue
			}
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, jsonScope{object: true, expectKey: true, keys: make(map[string]struct{})})
			case '[':
				stack = append(stack, jsonScope{})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("unexpected JSON delimiter")
				}
				stack = stack[:len(stack)-1]
			}
		}
		if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = true
		}
	}
	if len(stack) != 0 {
		return errors.New("unterminated JSON value")
	}
	return nil
}
