package proto

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestReviewRiskScoreWireValidation(t *testing.T) {
	for _, risk := range []string{"1", "2", "3", "4", "5", "unknown", "low", "medium", "high", "0", "6", "01", "", "<b>1</b>"} {
		t.Run(risk, func(t *testing.T) {
			message := ReviewComplete{Type: "review_complete", Report: validReport(), ModelHistory: []ModelHistoryEntry{}}
			message.Report.Risk = risk
			wantValid := risk == "1" || risk == "2" || risk == "3" || risk == "4" || risk == "5" || risk == "unknown"
			if err := ValidateReviewComplete(message); (err == nil) != wantValid {
				t.Fatalf("risk %q: valid=%t, err=%v", risk, wantValid, err)
			}
		})
	}
}

func TestAutoApprovalPlanAndNotificationWire(t *testing.T) {
	digest := strings.Repeat("a", 64)
	f := Frozen{Type: "frozen", ManifestDigest: digest, Report: validReport(), WithheldRefs: []string{}, AutoApproval: &AutoApprovalPlan{Score: 1, MaxRisk: 2, EffectiveThreshold: 3}}
	f.Report.Risk = "1"
	check := func(message any, dir Direction) error {
		body, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeWorkerMessage(body, dir)
		return err
	}
	if err := check(f, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	if err := check(f, WorkerToBroker); err == nil {
		t.Fatal("frozen accepted backwards")
	}
	for _, tc := range []struct {
		risk string
		plan AutoApprovalPlan
	}{
		{"unknown", AutoApprovalPlan{1, 2, 3}}, {"2", AutoApprovalPlan{1, 2, 3}},
		{"5", AutoApprovalPlan{5, 4, 5}}, {"4", AutoApprovalPlan{4, 2, 3}},
		{"1", AutoApprovalPlan{1, 0, 2}}, {"1", AutoApprovalPlan{1, 2, 5}},
		{"1", AutoApprovalPlan{1, 2, 1}}, {"1", AutoApprovalPlan{1, 4, 6}},
	} {
		f.Report.Risk, *f.AutoApproval = tc.risk, tc.plan
		if err := check(f, BrokerToWorker); err == nil {
			t.Errorf("accepted risk %q plan %+v", tc.risk, tc.plan)
		}
	}
	n := AutoNotificationSent{Type: "auto_notification_sent", Digest: digest, MessageIDs: []int64{11, 12}, NoticeID: 13, TimeUnixMS: 1}
	if err := check(n, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	if err := check(n, BrokerToWorker); err == nil {
		t.Fatal("notification accepted backwards")
	}
	for _, bad := range []AutoNotificationSent{
		{Type: "notification_sent", Digest: digest, MessageIDs: []int64{1}, NoticeID: 2, TimeUnixMS: 1},
		{Type: n.Type, Digest: "bad", MessageIDs: []int64{1}, NoticeID: 2, TimeUnixMS: 1},
		{Type: n.Type, Digest: digest, MessageIDs: nil, NoticeID: 2, TimeUnixMS: 1},
		{Type: n.Type, Digest: digest, MessageIDs: []int64{}, NoticeID: 2, TimeUnixMS: 1},
		{Type: n.Type, Digest: digest, MessageIDs: []int64{0}, NoticeID: 2, TimeUnixMS: 1},
		{Type: n.Type, Digest: digest, MessageIDs: make([]int64, 33), NoticeID: 2, TimeUnixMS: 1},
		{Type: n.Type, Digest: digest, MessageIDs: []int64{1}, NoticeID: 0, TimeUnixMS: 1},
		{Type: n.Type, Digest: digest, MessageIDs: []int64{1}, NoticeID: 2, TimeUnixMS: 0},
	} {
		if err := check(bad, WorkerToBroker); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestWorkerDirectionality(t *testing.T) {
	cancel := Cancel{Type: "cancel", Reason: "shutdown"}
	if err := ValidateWorkerMessage(cancel, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkerMessage(cancel, WorkerToBroker); err == nil {
		t.Fatal("broker message accepted worker-to-broker")
	}
	progress := Progress{Type: "progress", Stage: "reviewing", Detail: "started"}
	if err := ValidateWorkerMessage(progress, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkerMessage(progress, BrokerToWorker); err == nil {
		t.Fatal("worker message accepted broker-to-worker")
	}
}

func TestAvailabilityWireStrictAndDirectional(t *testing.T) {
	history := []AvailabilityFailure{{Name: "first", Code: AvailabilityQuota}, {Name: "second", Code: AvailabilityMalformedWire}}
	for _, tc := range []struct {
		message   any
		direction Direction
	}{
		{ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: history}, WorkerToBroker},
		{ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), Reason: "No AI review", History: history}, BrokerToWorker},
	} {
		body, err := json.Marshal(tc.message)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeWorkerMessage(body, tc.direction); err != nil {
			t.Fatalf("%T: %v", tc.message, err)
		}
		other := BrokerToWorker
		if tc.direction == BrokerToWorker {
			other = WorkerToBroker
		}
		if _, err := DecodeWorkerMessage(body, other); err == nil {
			t.Fatalf("%T accepted wrong direction", tc.message)
		}
	}
	for _, history := range [][]AvailabilityFailure{nil, {}, {{Name: "m", Code: "refused"}}, {{Name: "m", Code: AvailabilityQuota}, {Name: strings.Repeat("n", 129), Code: AvailabilityTimeout}}} {
		if err := ValidateWorkerMessage(ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: history}, WorkerToBroker); err == nil {
			t.Fatalf("accepted history %+v", history)
		}
	}
	if _, err := DecodeWorkerMessage([]byte(`{"type":"review_unavailable","code":"all_providers_unavailable","history":[{"name":"x","code":"quota_rate","extra":"approved"}]}`), WorkerToBroker); err == nil {
		t.Fatal("accepted freeform history field")
	}
}

func TestApprovalOnlyFrozenAcceptsEmptyPolicyHistory(t *testing.T) {
	message := ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), Reason: "Approval-only policy", History: []AvailabilityFailure{}}
	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeWorkerMessage(body, BrokerToWorker)
	if err != nil {
		t.Fatalf("policy response did not round trip: %v", err)
	}
	if got, ok := decoded.(*ApprovalOnlyFrozen); !ok || got.History == nil || len(got.History) != 0 {
		t.Fatalf("decoded = %#v", decoded)
	}

	message.History = nil
	if err := ValidateWorkerMessage(message, BrokerToWorker); err == nil {
		t.Fatal("nil approval-only history accepted")
	}
	message.History = []AvailabilityFailure{{Name: "provider", Code: "model_said_approve"}}
	if err := ValidateWorkerMessage(message, BrokerToWorker); err == nil {
		t.Fatal("malformed history accepted")
	}

	providerOutcome := ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: []AvailabilityFailure{{Name: "provider", Code: AvailabilityTransport}}}
	if err := ValidateWorkerMessage(providerOutcome, WorkerToBroker); err != nil {
		t.Fatalf("typed provider-unavailable outcome rejected: %v", err)
	}
}

func TestApprovalOnlyBootstrapPolicyAndPreflightValidation(t *testing.T) {
	b := Bootstrap{Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef", Operation: WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/"}, ReviewDeadlineUnixMS: 1, ConfigProjection: ConfigProjection{Models: []ProjectedModel{}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Telegram: WorkerTelegram{TokenFile: "/key", ApprovalTTLMS: 1}}}
	b.ApprovalOnly = true
	if err := ValidateWorkerMessage(b, BrokerToWorker); err != nil {
		t.Fatalf("owner-policy human-only bootstrap rejected: %v", err)
	}
	body, _ := json.Marshal(b)
	if _, err := DecodeWorkerMessage(body, BrokerToWorker); err != nil {
		t.Fatalf("policy bootstrap round trip: %v", err)
	}
	b.ApprovalOnly = false
	b.PreflightFailures = []AvailabilityFailure{{Name: "codex", Code: AvailabilityCodexReLogin}}
	b.ConfigProjection.Models = []ProjectedModel{{Name: "remaining", API: "openai_chat", BaseURL: "https://example.org", Model: "m", RequestTimeoutMS: 1}}
	if err := ValidateWorkerMessage(b, BrokerToWorker); err != nil {
		t.Fatalf("typed fallback bootstrap rejected: %v", err)
	}
	b.ApprovalOnly = true
	b.ConfigProjection.Models = []ProjectedModel{{Name: "other", API: "openai_chat", BaseURL: "https://example.org", Model: "m", RequestTimeoutMS: 1}}
	if err := ValidateWorkerMessage(b, BrokerToWorker); err == nil {
		t.Fatal("approval-only allowed usable model")
	}
	b.ConfigProjection.Models = []ProjectedModel{}
	b.PreflightFailures = []AvailabilityFailure{{Name: "codex", Code: "model_said_approve"}}
	if err := ValidateWorkerMessage(b, BrokerToWorker); err == nil {
		t.Fatal("malformed availability history accepted")
	}
}

func TestBootstrapExecutionEnvironmentAllowsOnlyActualNonSecretVariables(t *testing.T) {
	b := Bootstrap{
		Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef",
		Operation:            WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/work"},
		ReviewDeadlineUnixMS: 1, ApprovalOnly: true,
		ConfigProjection:     ConfigProjection{Models: []ProjectedModel{}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Telegram: WorkerTelegram{TokenFile: "/key", ApprovalTTLMS: 1}},
		ExecutionEnvironment: []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "PWD=/work"},
	}
	if err := ValidateWorkerMessage(b, BrokerToWorker); err != nil {
		t.Fatalf("safe execution environment rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"private bundle path", []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "ASKDO_BUNDLE=/private/spool"}},
		{"wrong cwd", []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "PWD=/other"}},
		{"duplicate", []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "PATH=/usr/bin:/bin"}},
		{"incomplete", []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b.ExecutionEnvironment = tc.env
			if err := ValidateWorkerMessage(b, BrokerToWorker); err == nil {
				t.Fatalf("unsafe/inaccurate environment accepted: %v", tc.env)
			}
		})
	}
}

func TestInspectRequestAndResultBounds(t *testing.T) {
	payload, _ := json.Marshal(ReadPathRequest{Base: "host", Path: "/file", Offset: 0, MaxBytes: MaxDirectReadBytes})
	request := InspectRequest{Type: "inspect_request", RequestSeq: 7, Op: "read_path", Payload: payload}
	if err := ValidateWorkerMessage(request, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	resultPayload, _ := json.Marshal(ReadPathResult{Content: "line", Offset: 0, NextOffset: 4, EOF: true})
	result := InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: resultPayload}
	if err := ValidateInspectResultFor(request, result); err != nil {
		t.Fatal(err)
	}
	request.RequestSeq++
	if err := ValidateInspectResultFor(request, result); err == nil {
		t.Fatal("mismatched request sequence accepted")
	}
	payload, _ = json.Marshal(ReadPathRequest{Base: "host", Path: "/file", Offset: 0, MaxBytes: MaxDirectReadBytes + 1})
	if err := ValidateWorkerMessage(InspectRequest{Type: "inspect_request", Op: "read_path", Payload: payload}, WorkerToBroker); err == nil {
		t.Fatal("oversized direct read accepted")
	}
}

func TestInspectionWireRejectsParserSite(t *testing.T) {
	for _, tc := range []struct{ op, payload string }{
		{"read_path", `{"path":"/tmp/script","base":"host","offset":0,"max_bytes":32,"source_site":"old"}`},
		{"search_path", `{"path":"/tmp","base":"host","pattern":"script","cursor":"","source_site":"old"}`},
	} {
		req := InspectRequest{Type: "inspect_request", Op: tc.op, Payload: json.RawMessage(tc.payload)}
		if err := ValidateWorkerMessage(req, WorkerToBroker); err == nil {
			t.Errorf("%s accepted retired source_site wire field", tc.op)
		}
	}
}

func TestReviewWireRejectsCoverage(t *testing.T) {
	review := ReviewComplete{Type: "review_complete", Report: validReport(), ModelHistory: []ModelHistoryEntry{{Name: "m", Outcome: "ok"}}}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	raw["coverage"] = json.RawMessage(`{"supplied":[]}`)
	body, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWorkerMessage(body, WorkerToBroker); err == nil {
		t.Fatal("retired coverage wire field accepted")
	}
}

func TestDirectInspectWireRejectsImportanceAndCaptureFields(t *testing.T) {
	for _, raw := range []string{
		`{"type":"inspect_request","request_seq":0,"op":"read_path","required":true,"payload":{"base":"host","path":"/file","offset":0,"max_bytes":32}}`,
		`{"type":"inspect_request","request_seq":0,"op":"read_path","payload":{"base":"host","path":"/file","offset":0,"max_bytes":32,"file_id":"old"}}`,
		`{"type":"inspect_request","request_seq":0,"op":"list_path","payload":{"base":"bundle","path":".","cursor":"","required":true}}`,
		`{"type":"review_failed","code":"required_inspection_denied"}`,
	} {
		if _, err := DecodeWorkerMessage([]byte(raw), WorkerToBroker); err == nil {
			t.Errorf("retired wire shape accepted: %s", raw)
		}
	}
}

func TestWorkerMessageEnumsAndBounds(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, message := range []any{Frozen{Type: "frozen", ManifestDigest: digest, Report: validReport(), WithheldRefs: []string{}}, ReviewRejected{Type: "review_rejected", Code: "invalid_report", Reason: "x"}, NotificationSent{Type: "notification_sent", MessageIDs: []int64{}, Digest: digest}, Decision{Type: "decision", Digest: digest, Action: "approve"}} {
		if err := ValidateWorkerMessage(message, directionFor(message)); err != nil {
			t.Fatalf("%T: %v", message, err)
		}
	}
	if err := ValidateWorkerMessage(Decision{Type: "decision", Digest: digest, Action: "other"}, WorkerToBroker); err == nil {
		t.Fatal("bad decision action accepted")
	}
	if err := ValidateWorkerMessage(ReviewRejected{Type: "review_rejected", Code: "other", Reason: "x"}, BrokerToWorker); err == nil {
		t.Fatal("bad rejected code accepted")
	}
	if err := ValidateWorkerMessage(ReviewRejected{Type: "review_rejected", Code: "coverage_insufficient", Reason: "x"}, BrokerToWorker); err == nil {
		t.Fatal("obsolete coverage rejection accepted")
	}
	if err := ValidateWorkerMessage(NotificationSent{Type: "notification_sent", Digest: digest}, WorkerToBroker); err == nil {
		t.Fatal("nil message_ids accepted")
	}
	if err := ValidateWorkerMessage(Frozen{Type: "frozen", ManifestDigest: digest, Report: ReviewReport{Risk: "1", Summary: "x", Reversibility: "x", IntentMatch: "consistent"}}, BrokerToWorker); err == nil {
		t.Fatal("nil report arrays accepted")
	}
}

func TestDecodeWorkerMessageRequiresNestedFields(t *testing.T) {
	tests := []string{
		`{"type":"notification_sent","digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","card_id":1,"expiry_unix_ms":1}`,
		`{"type":"notification_sent","message_ids":null,"digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","card_id":1,"expiry_unix_ms":1}`,
		`{"type":"review_complete","report":{"risk":"1","summary":"x","reversibility":"x","intent_match":"consistent"},"coverage":{"supplied":[],"dependencies":[],"denied":[],"unresolved_checks":[]},"model_history":[]}`,
		`{"type":"bootstrap","host":"host","target_uid":1,"request_id":"0123456789abcdef0123456789abcdef","operation":{"mode":"argv","argv":["/bin/true"],"reason":"x","captures":[]},"config_projection":{"models":[],"limits":{"max_model_calls_per_attempt":1,"max_output_tokens":1},"telegram":{"token_file":"/key","operator_user_id":1,"chat_id":1,"approval_ttl_ms":1}},"deadline_unix_ms":0,"review_deadline_unix_ms":1}`,
	}
	for _, input := range tests {
		if _, err := DecodeWorkerMessage([]byte(input), WorkerToBroker); err == nil {
			t.Fatalf("invalid message accepted: %s", input)
		}
	}
}

func TestBundleBootstrapAllowsNoArgumentsAfterWireRoundTrip(t *testing.T) {
	bootstrap := Bootstrap{
		Type:                 "bootstrap",
		Host:                 "host",
		TargetUID:            1,
		RequestID:            "0123456789abcdef0123456789abcdef",
		Operation:            WorkerOperation{Mode: "bundle", Entry: "run.sh", Args: []string{}, CWD: "/home/agent", BundleDir: "/spool/job/bundle", Reason: "x"},
		DeadlineUnixMS:       0,
		ReviewDeadlineUnixMS: 1,
		ConfigProjection: ConfigProjection{
			Models:   []ProjectedModel{{Name: "model", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", RequestTimeoutMS: 1}},
			Limits:   WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1},
			Telegram: WorkerTelegram{TokenFile: "/key", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 1},
		},
	}
	body, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWorkerMessage(body, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
}

// TestBootstrapLimitsOmitInspectedBounds pins the worker projection boundary:
// inspected-file/byte bounds are broker-only staging/search limits enforced
// from the admin config, so the bootstrap limits JSON must never carry them;
// a wire projection that does is rejected by the strict decoder.
func TestBootstrapLimitsOmitInspectedBounds(t *testing.T) {
	bootstrap := Bootstrap{
		Type:                 "bootstrap",
		Host:                 "host",
		RequestID:            "0123456789abcdef0123456789abcdef",
		Operation:            WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/"},
		ReviewDeadlineUnixMS: 1,
		ConfigProjection: ConfigProjection{
			Models:   []ProjectedModel{{Name: "model", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", RequestTimeoutMS: 1}},
			Limits:   WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1},
			Telegram: WorkerTelegram{TokenFile: "/key", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 1},
		},
	}
	body, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	projection, ok := decoded["config_projection"].(map[string]any)
	if !ok {
		t.Fatalf("config_projection missing from wire JSON: %s", body)
	}
	limits, ok := projection["limits"].(map[string]any)
	if !ok {
		t.Fatalf("limits missing from wire JSON: %s", body)
	}
	for _, key := range []string{"max_inspected_files", "max_inspected_bytes"} {
		if _, present := limits[key]; present {
			t.Fatalf("broker-only bound %s leaked into worker projection: %s", key, body)
		}
	}
	if _, err := DecodeWorkerMessage(body, BrokerToWorker); err != nil {
		t.Fatalf("projection without inspected bounds rejected: %v", err)
	}
	legacy := strings.Replace(string(body), `"max_output_tokens":1`, `"max_output_tokens":1,"max_inspected_files":1,"max_inspected_bytes":1`, 1)
	if legacy == string(body) {
		t.Fatalf("wire JSON shape changed, legacy injection needs updating: %s", body)
	}
	if _, err := DecodeWorkerMessage([]byte(legacy), BrokerToWorker); err == nil {
		t.Fatal("wire projection with obsolete inspected bounds accepted")
	}
}

// TestDecodeWorkerMessageNULPolicy pins the NUL boundary: review_complete and
// progress carry model-generated content where escaped control characters are
// legitimate data; structural messages keep strict NUL rejection.
func TestDecodeWorkerMessageNULPolicy(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	accepted := []struct {
		name, input string
		direction   Direction
	}{
		{"review_complete report", `{"type":"review_complete","report":{"risk":"1","summary":"binary \u0000\u0001\u001f bytes","effects":["runs id\u0000"],"warnings":[{"message":"m\u0000","evidence":"readelf \u0000 output"}],"missing_context":[],"reversibility":"unknown\u0000","intent_match":"consistent"},"model_history":[{"name":"m","outcome":"api_error","error":"echoed \u0000 bytes"}]}`, WorkerToBroker},
		{"progress detail", `{"type":"progress","stage":"reviewing","detail":"scanning \u0000 bytes"}`, WorkerToBroker},
		// frozen embeds the validated report verbatim, so its report fields
		// are the same model content; the digest stays NUL-rejecting via
		// digestPattern validation.
		{"frozen report", `{"type":"frozen","manifest_digest":"` + digest + `","report":{"risk":"1","summary":"binary \u0000 bytes","effects":[],"warnings":[],"missing_context":[],"reversibility":"x","intent_match":"consistent"},"withheld_refs":[],"withheld_count":0}`, BrokerToWorker},
	}
	for _, test := range accepted {
		t.Run("accept/"+test.name, func(t *testing.T) {
			if _, err := DecodeWorkerMessage([]byte(test.input), test.direction); err != nil {
				t.Fatalf("content message rejected: %v", err)
			}
		})
	}
	rejected := []struct {
		name, input string
	}{
		{"inspect_request path", `{"type":"inspect_request","request_seq":1,"op":"read_path","payload":{"path":"/usr/bin/id\u0000.evil","base":"host","offset":0,"max_bytes":32}}`},
		{"inspect_request search pattern", `{"type":"inspect_request","request_seq":1,"op":"search_path","payload":{"base":"host","path":"/tmp","pattern":"\u0000","cursor":""}}`},
		{"bootstrap reason", `{"type":"bootstrap","host":"host","target_uid":1,"request_id":"0123456789abcdef0123456789abcdef","operation":{"mode":"argv","argv":["/bin/true"],"reason":"x\u0000","captures":[]},"config_projection":{"models":[{"name":"m","api":"openai_chat","base_url":"http://127.0.0.1","model":"fake","request_timeout_ms":1}],"limits":{"max_model_calls_per_attempt":1,"max_output_tokens":1},"telegram":{"token_file":"/key","operator_user_id":1,"chat_id":1,"approval_ttl_ms":1}},"deadline_unix_ms":0,"review_deadline_unix_ms":1}`},
		{"frozen digest", `{"type":"frozen","manifest_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\u0000","report":{"risk":"1","summary":"x","effects":[],"warnings":[],"missing_context":[],"reversibility":"x","intent_match":"consistent"}}`},
		{"notification_sent digest", `{"type":"notification_sent","message_ids":[1],"card_id":1,"digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\u0000","expiry_unix_ms":1}`},
	}
	for _, test := range rejected {
		t.Run("reject/"+test.name, func(t *testing.T) {
			if _, err := DecodeWorkerMessage([]byte(test.input), WorkerToBroker); err == nil {
				t.Fatal("structural message accepted")
			}
		})
	}
	// The NUL rejections above must come from the decoder's NUL policy, not
	// incidental field validation.
	if _, err := DecodeWorkerMessage([]byte(rejected[0].input), WorkerToBroker); !errors.Is(err, ErrNULInJSONString) {
		t.Fatalf("inspect_request NUL error=%v", err)
	}
	// A NUL inside frozen's structural digest is rejected by validation even
	// though the message's report content is NUL-tolerant.
	if _, err := DecodeWorkerMessage([]byte(rejected[3].input), BrokerToWorker); err == nil || errors.Is(err, ErrNULInJSONString) {
		t.Fatalf("frozen digest NUL error=%v, want validation (not scan) rejection", err)
	}
}

// TestWorkerMessagesMarshalEmptyArraysNotNull pins the producer contract:
// every required array field in an Appendix A worker message marshals as []
// when empty, never null. Each entry is a message exactly as its producer
// constructs it for the empty case; the marshaled JSON is decoded and walked
// recursively and any null value fails the test. Every message must also
// survive the strict decoder in its permitted direction (which for
// notification_sent includes an empty message_ids array).
func TestWorkerMessagesMarshalEmptyArraysNotNull(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	payload := func(value any) json.RawMessage {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	bootstrap := Bootstrap{
		Type:      "bootstrap",
		Host:      "host",
		RequestID: "0123456789abcdef0123456789abcdef",
		Operation: WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/home/agent", Reason: "x"},
		ConfigProjection: ConfigProjection{
			Models:   []ProjectedModel{{Name: "model", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", RequestTimeoutMS: 1}},
			Limits:   WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1},
			Telegram: WorkerTelegram{TokenFile: "/key", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 1},
		},
		ReviewDeadlineUnixMS: 1,
	}
	messages := []struct {
		name      string
		message   any
		direction Direction
	}{
		{"bootstrap no capture records", bootstrap, BrokerToWorker},
		{"inspect_result zero search matches", InspectResult{Type: "inspect_result", RequestSeq: 1, Status: "ok", Payload: payload(SearchPathResult{Matches: []DirectSearchMatch{}, NextCursor: ""})}, BrokerToWorker},
		{"inspect_result empty directory", InspectResult{Type: "inspect_result", RequestSeq: 2, Status: "ok", Payload: payload(ListPathResult{Entries: []DirectoryEntry{}, NextCursor: ""})}, BrokerToWorker},
		{"frozen empty report arrays", Frozen{Type: "frozen", ManifestDigest: digest, Report: validReport(), WithheldRefs: []string{}}, BrokerToWorker},
		{"review_complete no inspection", ReviewComplete{Type: "review_complete", Report: validReport(), ModelHistory: []ModelHistoryEntry{{Name: "m", Outcome: "ok"}}}, WorkerToBroker},
		{"notification_sent empty message_ids", NotificationSent{Type: "notification_sent", MessageIDs: NonNilSlice([]int64(nil)), CardID: 1, Digest: digest, ExpiryUnixMS: 1}, WorkerToBroker},
	}
	for _, test := range messages {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.message)
			if err != nil {
				t.Fatal(err)
			}
			var decoded any
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			assertNoNullJSON(t, "$", decoded)
			if _, err := DecodeWorkerMessage(body, test.direction); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
		})
	}
}

func assertNoNullJSON(t *testing.T, path string, value any) {
	t.Helper()
	switch v := value.(type) {
	case nil:
		t.Fatalf("%s is null", path)
	case map[string]any:
		for key, child := range v {
			assertNoNullJSON(t, path+"."+key, child)
		}
	case []any:
		for i, child := range v {
			assertNoNullJSON(t, fmt.Sprintf("%s[%d]", path, i), child)
		}
	}
}

// TestProjectedModelCodexAmendment pins the Wave 8 Appendix A freeze
// exception: openai_codex is a valid api enum value and carries the
// broker-projected access_token/account_id (required at runtime for that
// api, bounded, and forbidden on every other api so OAuth material can never
// leak into a key-file provider's projection).
func TestProjectedModelCodexAmendment(t *testing.T) {
	projection := func(models ...ProjectedModel) ConfigProjection {
		return ConfigProjection{
			Models:   models,
			Limits:   WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1},
			Telegram: WorkerTelegram{TokenFile: "/key", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 1},
		}
	}
	codex := ProjectedModel{Name: "codex", API: "openai_codex", BaseURL: "https://chatgpt.com/backend-api/codex", Model: "gpt-5", RequestTimeoutMS: 1, AccessToken: "access", AccountID: "acct-1"}
	keyed := ProjectedModel{Name: "keyed", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", APIKeyFile: "/keys/openai", RequestTimeoutMS: 1}
	if err := validateProjection(projection(codex, keyed)); err != nil {
		t.Fatalf("valid mixed projection rejected: %v", err)
	}
	cases := []struct {
		name  string
		model ProjectedModel
	}{
		{"codex missing access_token", ProjectedModel{Name: "c", API: "openai_codex", BaseURL: "https://x", Model: "m", RequestTimeoutMS: 1, AccountID: "acct-1"}},
		{"codex missing account_id", ProjectedModel{Name: "c", API: "openai_codex", BaseURL: "https://x", Model: "m", RequestTimeoutMS: 1, AccessToken: "access"}},
		{"codex oversized access_token", ProjectedModel{Name: "c", API: "openai_codex", BaseURL: "https://x", Model: "m", RequestTimeoutMS: 1, AccessToken: strings.Repeat("a", 4097), AccountID: "acct-1"}},
		{"codex oversized account_id", ProjectedModel{Name: "c", API: "openai_codex", BaseURL: "https://x", Model: "m", RequestTimeoutMS: 1, AccessToken: "access", AccountID: strings.Repeat("a", 257)}},
		{"key provider with access_token", ProjectedModel{Name: "k", API: "openai_chat", BaseURL: "https://x", Model: "m", RequestTimeoutMS: 1, AccessToken: "access"}},
		{"key provider with account_id", ProjectedModel{Name: "k", API: "anthropic_messages", BaseURL: "https://x", Model: "m", RequestTimeoutMS: 1, AccountID: "acct-1"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := validateProjection(projection(test.model)); err == nil {
				t.Fatal("invalid projected model accepted")
			}
		})
	}
	// Wire round-trip: the codex fields serialize and survive strict decode;
	// omitted on key providers (omitempty), so nothing changes on the wire
	// for pre-Wave-8 models.
	bootstrap := Bootstrap{
		Type:                 "bootstrap",
		Host:                 "host",
		TargetUID:            1,
		RequestID:            "0123456789abcdef0123456789abcdef",
		Operation:            WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/home/agent", Reason: "x"},
		DeadlineUnixMS:       0,
		ReviewDeadlineUnixMS: 1,
		ConfigProjection:     projection(codex, keyed),
	}
	body, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"access_token":"access"`) || !strings.Contains(string(body), `"account_id":"acct-1"`) {
		t.Fatalf("codex projection fields missing from wire: %s", body)
	}
	if strings.Count(string(body), "access_token") != 1 {
		t.Fatalf("access_token leaked onto a non-codex model: %s", body)
	}
	decoded, err := DecodeWorkerMessage(body, BrokerToWorker)
	if err != nil {
		t.Fatalf("codex bootstrap rejected by strict decode: %v", err)
	}
	got := decoded.(*Bootstrap).ConfigProjection.Models[0]
	if got.AccessToken != "access" || got.AccountID != "acct-1" {
		t.Fatalf("round-trip lost codex fields: %+v", got)
	}
	// A codex model without the runtime-required fields fails strict decode.
	broken := strings.Replace(string(body), `"access_token":"access",`, ``, 1)
	if _, err := DecodeWorkerMessage([]byte(broken), BrokerToWorker); err == nil {
		t.Fatal("codex model without access_token survived strict decode")
	}
}

func directionFor(message any) Direction {
	switch message.(type) {
	case Frozen, ReviewRejected:
		return BrokerToWorker
	default:
		return WorkerToBroker
	}
}
func validReport() ReviewReport {
	return ReviewReport{Risk: "1", Summary: "x", Effects: []string{}, Warnings: []ReviewWarning{}, MissingContext: []string{}, Reversibility: "x", IntentMatch: "consistent"}
}

func TestDirectResultRejectsLegacyFileID(t *testing.T) {
	request := InspectRequest{Type: "inspect_request", RequestSeq: 3, Op: "read_path", Payload: json.RawMessage(`{"base":"host","path":"/file","offset":0,"max_bytes":32}`)}
	result := InspectResult{Type: "inspect_result", RequestSeq: 3, Status: "ok", Payload: json.RawMessage(`{"content":"text","offset":0,"next_offset":4,"eof":true,"file_id":"old"}`)}
	if err := ValidateInspectResultFor(request, result); err == nil {
		t.Fatal("legacy file_id in direct response accepted")
	}
}
