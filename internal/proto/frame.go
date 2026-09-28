// Package proto defines the framed protocols shared by askdo processes.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

// MaxFrameLength is the fixed hard ceiling for all protocol frames.
const MaxFrameLength uint32 = 64 << 20

var (
	// ErrFrameTooLarge reports a frame whose declared length exceeds its limit.
	ErrFrameTooLarge = errors.New("protocol frame exceeds maximum length")
	// ErrInvalidFrameBody reports a non-UTF-8 frame body.
	ErrInvalidFrameBody = errors.New("protocol frame body is not valid UTF-8")
	// ErrInvalidFrameJSON reports a frame body that is not JSON.
	ErrInvalidFrameJSON = errors.New("protocol frame body is not valid JSON")
)

// ReadDeadlineSetter is implemented by network connections that support read
// deadlines.
type ReadDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

// SetReceiveDeadline sets a deadline for a subsequent frame receive. Passing
// time.Time{} clears a previously configured deadline.
func SetReceiveDeadline(conn ReadDeadlineSetter, deadline time.Time) error {
	return conn.SetReadDeadline(deadline)
}

// WriteFrame writes body as a length-prefixed UTF-8 protocol frame.
func WriteFrame(w io.Writer, body []byte) error {
	if uint64(len(body)) > uint64(MaxFrameLength) {
		return ErrFrameTooLarge
	}
	if !utf8.Valid(body) {
		return ErrInvalidFrameBody
	}
	if !json.Valid(body) {
		return ErrInvalidFrameJSON
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if err := writeAll(w, body); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed UTF-8 protocol frame. The advertised
// length is checked before allocating its body.
func ReadFrame(r io.Reader, maxLength uint32) ([]byte, error) {
	if maxLength > MaxFrameLength {
		maxLength = MaxFrameLength
	}
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxLength {
		return nil, ErrFrameTooLarge
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	if !utf8.Valid(body) {
		return nil, ErrInvalidFrameBody
	}
	if !json.Valid(body) {
		return nil, ErrInvalidFrameJSON
	}
	return body, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
