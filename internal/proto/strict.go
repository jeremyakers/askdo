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

// StrictUnmarshal decodes one JSON value while rejecting unknown fields,
// duplicate object keys, NUL-containing strings, and invalid UTF-8.
func StrictUnmarshal(data []byte, dst any) error {
	return strictUnmarshal(data, dst, false)
}

// StrictUnmarshalAllowNUL decodes exactly like StrictUnmarshal — unknown
// fields, duplicate object keys, and invalid UTF-8 are still rejected — except
// that valid JSON string escapes decoding to NUL bytes are accepted. It exists
// for model-generated content (review report fields, progress details) where
// escaped control characters are legitimate data; protocol metadata such as
// paths and identifiers must keep using StrictUnmarshal.
func StrictUnmarshalAllowNUL(data []byte, dst any) error {
	return strictUnmarshal(data, dst, true)
}

func strictUnmarshal(data []byte, dst any, allowNUL bool) error {
	if !utf8.Valid(data) {
		return ErrInvalidJSONUTF8
	}
	if err := scanStrictJSON(data, allowNUL); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
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
