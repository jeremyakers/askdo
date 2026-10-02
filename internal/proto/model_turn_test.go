package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestModelTurnStrictVariants(t *testing.T) {
	result := ModelTurnResult{Type: "model_turn_result", RequestSeq: 1, Response: &modelwire.ModelResponse{Content: "ok"}}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeWorkerMessage(body, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"type":"model_turn_result","request_seq":0,"response":{}}`,
		`{"type":"model_turn_result","request_seq":1}`,
		`{"type":"model_turn_result","request_seq":1,"response":{},"failure":{"code":"auth"}}`,
		`{"type":"model_turn_result","request_seq":1,"failure":{"code":"secret"}}`,
		`{"type":"model_turn_result","request_seq":1,"failure":{"code":"auth","detail":"secret"}}`,
		`{"type":"model_turn_result","request_seq":1,"request_seq":1,"response":{}}`,
		`{"type":"model_turn_result","request_seq":"1","response":{}}`,
		`{"type":"model_turn_result","request_seq":1,"response":null,"failure":{"code":"auth"}}`,
		`{"type":"model_turn_result","request_seq":1,"response":{"content":null}}`,
		`{"type":"model_turn_result","request_seq":1,"response":{"tool_calls":[{"id":"a","name":"read_path"}]}}`,
	} {
		if _, err := DecodeWorkerMessage([]byte(raw), BrokerToWorker); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err = DecodeWorkerMessage(body, WorkerToBroker); err == nil {
		t.Fatal("wrong direction accepted")
	}
}

func TestFleetBootstrapWireRejectsSecretsAndPreservesUpstream(t *testing.T) {
	boot := Bootstrap{Type: "bootstrap", FleetMode: true, Host: "host", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "1000", Operation: WorkerOperation{Mode: "argv", CWD: "/home/agent", Argv: []string{"/usr/bin/id"}}, ReviewDeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli(), ConfigProjection: ConfigProjection{Models: []ProjectedModel{{Name: "actual-codex", API: "openai_codex", BaseURL: "https://upstream.invalid/v1", Model: "actual-model", DataBoundary: "external", RequestTimeoutMS: 1000}}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 8, MaxOutputTokens: 100}}}
	body, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeWorkerMessage(body, BrokerToWorker)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := message.(*Bootstrap)
	if !ok || decoded.ConfigProjection.Models[0] != boot.ConfigProjection.Models[0] {
		t.Fatalf("message=%#v", message)
	}
	type plain Bootstrap // Marshal raw hostile input without fleet-safe omission.
	for _, secret := range []string{"key", "access", "account", "telegram"} {
		t.Run(secret, func(t *testing.T) {
			malicious := boot
			malicious.ConfigProjection.Models = append([]ProjectedModel{}, boot.ConfigProjection.Models...)
			switch secret {
			case "key":
				malicious.ConfigProjection.Models[0].APIKeyFile = "secret"
			case "access":
				malicious.ConfigProjection.Models[0].AccessToken = "secret"
			case "account":
				malicious.ConfigProjection.Models[0].AccountID = "secret"
			case "telegram":
				malicious.ConfigProjection.Telegram.TokenFile = "secret"
			}
			if err := ValidateWorkerMessage(malicious, BrokerToWorker); err == nil {
				t.Fatal("validator accepted secret")
			}
			body, err := json.Marshal(plain(malicious))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeWorkerMessage(body, BrokerToWorker); err == nil {
				t.Fatal("wire accepted secret")
			}
			if _, err := json.Marshal(malicious); err == nil {
				t.Fatal("fleet Marshal emitted secret")
			}
		})
	}
}

func TestModelTurnRequestRequiredFieldsAndBounds(t *testing.T) {
	request := ModelTurnRequest{Type: "model_turn_request", RequestSeq: 1, ChoiceName: "actual", Request: modelwire.ModelRequest{Model: "actual-model", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "read_path", Description: "read", Schema: json.RawMessage(`{"type":"object"}`)}}, MaxOutputTokens: 100}}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWorkerMessage(body, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"type", "request_seq", "choice_name", "request"} {
		original := fields[field]
		delete(fields, field)
		malformed, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeWorkerMessage(malformed, WorkerToBroker); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
		fields[field] = original
	}
	for _, tokens := range []int{0, -1, 200001} {
		request.Request.MaxOutputTokens = tokens
		if err := ValidateWorkerMessage(request, WorkerToBroker); err == nil {
			t.Fatalf("tokens=%d accepted", tokens)
		}
	}
}

func TestFleetBootstrapOmitsTelegramAndRejectsSecrets(t *testing.T) {
	boot := Bootstrap{FleetMode: true, ConfigProjection: ConfigProjection{Models: []ProjectedModel{}, Telegram: WorkerTelegram{}}}
	body, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "telegram") {
		t.Fatalf("Telegram serialized: %s", body)
	}
	for _, model := range []ProjectedModel{{APIKeyFile: "secret"}, {AccessToken: "secret"}, {AccountID: "secret"}} {
		boot.ConfigProjection.Models = []ProjectedModel{model}
		if err := ValidateFleetBootstrap(boot); err == nil {
			t.Fatal("secret accepted")
		}
	}
	boot.ConfigProjection.Models = nil
	boot.ConfigProjection.Telegram.TokenFile = "secret"
	if err := ValidateFleetBootstrap(boot); err == nil {
		t.Fatal("Telegram secret accepted")
	}
}
