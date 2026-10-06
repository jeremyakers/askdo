package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapturedDeliveryKindWire(t *testing.T) {
	old := `{"path":"stdin","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}`
	var input CapturedInput
	if err := json.Unmarshal([]byte(old), &input); err != nil || input.DeliveryKind.Effective() != SealedMemfd {
		t.Fatal(input, err)
	}
	got, _ := json.Marshal(input)
	if string(got) != old {
		t.Fatalf("modern omitted kind changed JSON: %s", got)
	}
	for _, value := range []string{`null`, `""`, `"pipe"`, `1`} {
		if err := json.Unmarshal([]byte(strings.TrimSuffix(old, "}")+`,"delivery_kind":`+value+`}`), &input); err == nil {
			t.Fatal(value)
		}
	}
	for _, kind := range []DeliveryKind{SealedMemfd, SocketStream} {
		input.DeliveryKind = kind
		body, _ := json.Marshal(input)
		var result CapturedInput
		if err := json.Unmarshal(body, &result); err != nil || result != input {
			t.Fatal(result, err)
		}
	}
}
