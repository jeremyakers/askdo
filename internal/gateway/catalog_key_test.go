package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestSigningKeyFormatsAndBotTokenIdentity(t *testing.T) {
	old := validateRootFile
	validateRootFile = func(path string, secret bool) error { return nil }
	defer func() { validateRootFile = old }()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing")
	for _, raw := range [][]byte{key.Seed(), key} {
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadSigningKey(path)
		if err != nil || !got.Equal(key) {
			t.Fatal("signing key mismatch", err)
		}
	}
	broken := append([]byte(nil), key...)
	broken[len(broken)-1] ^= 1
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(broken)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(path); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
	for _, token := range []string{"12345:abcdefghijklmnopqrstuvwxyz_ABC-123", "012345:abcdefghijklmnopqrstuvwxyz", "-123:abcdefghijklmnopqrstuvwxyz", "12345:bad", "12345:abcdefghijklmnopqrst?secret"} {
		if err := os.WriteFile(path, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		ids, err := loadBotIDs([]BotConfig{{Name: "bot", TokenFile: path}})
		if token == "12345:abcdefghijklmnopqrstuvwxyz_ABC-123" {
			if err != nil || ids["bot"] != 12345 {
				t.Fatal(ids, err)
			}
		} else if err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}

func TestContinuationCannotChangeToolsHistoryOrToolIDs(t *testing.T) {
	request := modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}
	response := modelwire.ModelResponse{ToolCalls: []modelwire.ToolCall{{ID: "exact", Name: "inspect", Arguments: []byte(`{}`)}}}
	session := &modelSession{request: request, response: response}
	next := request
	next.Messages = append(append([]modelwire.Message(nil), request.Messages...), modelwire.Message{Role: "assistant", ToolCalls: response.ToolCalls}, modelwire.Message{Role: "tool", ToolCallID: "exact", Content: "result"})
	if !continues(session, next) {
		t.Fatal("valid history rejected")
	}
	bad := next
	bad.Tools = append([]modelwire.ToolDefinition(nil), next.Tools...)
	bad.Tools[0].Name = "other"
	if continues(session, bad) {
		t.Fatal("tools changed")
	}
	bad = next
	bad.Messages = append([]modelwire.Message(nil), next.Messages...)
	bad.Messages[0].Content = "replacement evidence"
	if continues(session, bad) {
		t.Fatal("history changed")
	}
	bad = next
	bad.Messages = append([]modelwire.Message(nil), next.Messages...)
	bad.Messages[len(bad.Messages)-1].ToolCallID = "wrong"
	if continues(session, bad) {
		t.Fatal("tool ID changed")
	}
}
