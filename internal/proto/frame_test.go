package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		max   uint32
		want  error
	}{
		{"oversized", append([]byte{0, 0, 0, 3}, []byte(`{}`)...), 2, ErrFrameTooLarge},
		{"truncated", []byte{0, 0, 0, 5, '{'}, 10, nil},
		{"garbage", []byte{0, 0, 0, 3, 'x', 'y', 'z'}, 10, ErrInvalidFrameJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(test.input), test.max)
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("error=%v, want %v", err, test.want)
				}
			} else if err == nil {
				t.Fatal("expected error")
			}
		})
	}
	boundary := bytes.Repeat([]byte(" "), 32)
	boundary[0] = '['
	boundary[len(boundary)-1] = ']'
	var wire bytes.Buffer
	if err := WriteFrame(&wire, boundary); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&wire, uint32(len(boundary)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, boundary) {
		t.Fatal("exact-boundary payload changed")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameLength+1)
	if _, err := ReadFrame(bytes.NewReader(header[:]), MaxFrameLength); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error=%v", err)
	}
}
