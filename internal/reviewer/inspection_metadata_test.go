package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestScopeAlwaysOffered(t *testing.T) {
	names := map[string]bool{}
	for _, def := range Definitions() {
		names[def.Name] = true
	}
	if !names["inspection_scope"] || names["hash_path"] || names["service_status"] || names["sudo_policy"] {
		t.Fatalf("unexpected tools: %v", names)
	}
}

type metadataBroker struct {
	calls  int
	result proto.InspectResult
	err    error
}

func (b *metadataBroker) Inspect(_ context.Context, request proto.InspectRequest) (proto.InspectResult, error) {
	b.calls++
	if _, err := proto.DecodeInspectRequestPayload(request); err != nil {
		return proto.InspectResult{}, err
	}
	b.result.RequestSeq = request.RequestSeq
	return b.result, b.err
}

func TestCapabilityRegistryAndIndependentDisabledGate(t *testing.T) {
	defs := DefinitionsForCapabilities(proto.InspectionCapabilities{HashPathEnabled: true, ServiceStatusEnabled: true, SudoPolicyEnabled: true}, true)
	names := map[string]bool{}
	for _, def := range defs {
		names[def.Name] = true
	}
	if len(names) != 12 || !names["hash_path"] || !names["service_status"] || !names["sudo_policy"] || !names["inspection_scope"] || !names["webfetch"] {
		t.Fatalf("tools: %v", names)
	}
	for _, name := range []string{"hash_path", "service_status", "sudo_policy"} {
		broker := &metadataBroker{}
		e := NewToolExecutor(toolBootstrap(), broker)
		result, terminal, err := e.Execute(context.Background(), ToolCall{ID: "1", Name: name, Arguments: json.RawMessage(`{}`)})
		if err != nil || terminal || broker.calls != 0 || !strings.Contains(result.Content, `"reason_code":"disabled"`) {
			t.Fatalf("disabled %s: %+v %v %v calls=%d", name, result, terminal, err, broker.calls)
		}
	}
}

func TestMetadataProxySanitizesFailuresAndCanComplete(t *testing.T) {
	for _, tc := range []struct {
		result proto.InspectResult
		err    error
		want   string
	}{
		{result: proto.InspectResult{Type: "inspect_result", Status: "inspection_denied", ReasonCode: "outside_scope"}, want: `{"reason_code":"outside_scope","status":"inspection_denied"}`},
		{err: errors.New("private root credential diagnostic"), want: `{"status":"unresolved","reason_code":"inspection_failed"}`},
		{result: proto.InspectResult{Type: "inspect_result", Status: "unresolved", ReasonCode: "private secret"}, want: `{"status":"unresolved","reason_code":"inspection_failed"}`},
	} {
		broker := &metadataBroker{result: tc.result, err: tc.err}
		bootstrap := toolBootstrap()
		bootstrap.ConfigProjection.Limits.InspectionCaps.HashPathEnabled = true
		e := NewToolExecutor(bootstrap, broker)
		result, terminal, err := e.Execute(context.Background(), ToolCall{ID: "1", Name: "hash_path", Arguments: json.RawMessage(`{"path":"/usr/bin/sudo"}`)})
		if err != nil || terminal || result.Content != tc.want || broker.calls != 1 {
			t.Fatalf("result %+v terminal %v err %v", result, terminal, err)
		}
		result, terminal, err = e.Execute(context.Background(), ToolCall{ID: "2", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"unknown","summary":"Evidence unavailable","effects":[],"warnings":[],"missing_context":[],"reversibility":"Unknown","intent_match":"unverified"}`)})
		if err != nil || !terminal || result.IsError {
			t.Fatalf("completion %+v terminal %v err %v", result, terminal, err)
		}
	}
}

func TestMetadataProxyTypedSuccessAndMalformedNoIO(t *testing.T) {
	value := proto.SudoPolicyResult{UID: 1000, Rules: []proto.SudoRule{}, ObservedAtUnixMS: 1, Complete: true}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	broker := &metadataBroker{result: proto.InspectResult{Type: "inspect_result", Status: "ok", Payload: raw}}
	bootstrap := toolBootstrap()
	bootstrap.ConfigProjection.Limits.InspectionCaps.SudoPolicyEnabled = true
	e := NewToolExecutor(bootstrap, broker)
	for _, args := range []string{`{}`, `{"uid":null}`, `{"uid":1000,"command":"id"}`} {
		result, terminal, err := e.Execute(context.Background(), ToolCall{ID: "1", Name: "sudo_policy", Arguments: json.RawMessage(args)})
		if err != nil || terminal || !result.IsError || broker.calls != 0 {
			t.Fatalf("bad args executed: %+v %v", result, err)
		}
	}
	result, terminal, err := e.Execute(context.Background(), ToolCall{ID: "2", Name: "sudo_policy", Arguments: json.RawMessage(`{"uid":1000}`)})
	if err != nil || terminal || result.IsError || result.Content != string(raw) || broker.calls != 1 {
		t.Fatalf("typed result %+v %v", result, err)
	}
}
