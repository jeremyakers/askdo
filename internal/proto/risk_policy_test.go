package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func riskPolicyBootstrap(policy *RiskPolicy) Bootstrap {
	return Bootstrap{
		Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef",
		Operation:            WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/"},
		ReviewDeadlineUnixMS: 1,
		RiskPolicy:           policy,
		ConfigProjection: ConfigProjection{
			Models:   []ProjectedModel{{Name: "model", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", RequestTimeoutMS: 1}},
			Limits:   WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1},
			Telegram: WorkerTelegram{TokenFile: "/key", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 1},
		},
	}
}

// The administrator rubric is an optional, root-projected bootstrap field. A
// bootstrap without it keeps the historical wire bytes; one with it carries
// the exact text, including whitespace and non-ASCII, through the strict
// worker decoder.
func TestBootstrapRiskPolicyIsOptionalAndRoundTripsExactText(t *testing.T) {
	absent, err := json.Marshal(riskPolicyBootstrap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(absent), "risk_policy") {
		t.Fatalf("absent rubric leaked into the historical wire shape: %s", absent)
	}
	decoded, err := DecodeWorkerMessage(absent, BrokerToWorker)
	if err != nil || decoded.(*Bootstrap).RiskPolicy != nil {
		t.Fatalf("old bootstrap shape rejected or gained a rubric: %v", err)
	}

	for _, text := range []string{"", "  rubric\r\n\ttrailing spaces  \n\n", "naïve ✓ <b>&</b> \"quoted\" \\ back\n"} {
		body, err := json.Marshal(riskPolicyBootstrap(&RiskPolicy{Text: text}))
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeWorkerMessage(body, BrokerToWorker)
		if err != nil {
			t.Fatalf("rubric %q rejected: %v", text, err)
		}
		if policy := got.(*Bootstrap).RiskPolicy; policy == nil || policy.Text != text {
			t.Fatalf("rubric changed in transit: %+v want %q", policy, text)
		}
	}
}

// The fleet bootstrap has its own marshaller that rewrites config_projection;
// the host's rubric must still travel in it, and still be optional there.
func TestFleetBootstrapCarriesRiskPolicyAndKeepsItOptional(t *testing.T) {
	fleet := func(policy *RiskPolicy) Bootstrap {
		return Bootstrap{Type: "bootstrap", FleetMode: true, Host: "host", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "1000", Operation: WorkerOperation{Mode: "argv", CWD: "/home/agent", Argv: []string{"/usr/bin/id"}}, ReviewDeadlineUnixMS: 1, RiskPolicy: policy, ConfigProjection: ConfigProjection{Models: []ProjectedModel{{Name: "local", API: "openai_chat", BaseURL: "https://gateway.invalid/v1", Model: "fixture", DataBoundary: "local", RequestTimeoutMS: 1000}}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 8, MaxOutputTokens: 100}}}
	}
	absent, err := json.Marshal(fleet(nil))
	if err != nil || strings.Contains(string(absent), "risk_policy") {
		t.Fatalf("absent rubric changed the fleet wire shape: %s %v", absent, err)
	}
	body, err := json.Marshal(fleet(&RiskPolicy{Text: "HOST canary\n"}))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeWorkerMessage(body, BrokerToWorker)
	if err != nil {
		t.Fatal(err)
	}
	if policy := decoded.(*Bootstrap).RiskPolicy; policy == nil || policy.Text != "HOST canary\n" {
		t.Fatalf("fleet rubric=%+v", policy)
	}
}

func TestBootstrapRiskPolicyRejectsMalformedShapesAndUnsafeText(t *testing.T) {
	body, err := json.Marshal(riskPolicyBootstrap(&RiskPolicy{Text: "rubric"}))
	if err != nil {
		t.Fatal(err)
	}
	valid := string(body)
	for name, mutate := range map[string]func(string) string{
		"null": func(s string) string {
			return strings.Replace(s, `"risk_policy":{"text":"rubric"}`, `"risk_policy":null`, 1)
		},
		"string": func(s string) string {
			return strings.Replace(s, `"risk_policy":{"text":"rubric"}`, `"risk_policy":"rubric"`, 1)
		},
		"missing text": func(s string) string {
			return strings.Replace(s, `"risk_policy":{"text":"rubric"}`, `"risk_policy":{}`, 1)
		},
		"null text": func(s string) string { return strings.Replace(s, `"text":"rubric"`, `"text":null`, 1) },
		"worker hash": func(s string) string {
			return strings.Replace(s, `"text":"rubric"`, `"text":"rubric","sha256":"`+strings.Repeat("a", 64)+`"`, 1)
		},
		"escaped NUL": func(s string) string { return strings.Replace(s, `"text":"rubric"`, `"text":"ru\u0000bric"`, 1) },
		"duplicate key": func(s string) string {
			return strings.Replace(s, `"text":"rubric"`, `"text":"rubric","text":"other"`, 1)
		},
	} {
		mutated := mutate(valid)
		if mutated == valid {
			t.Fatalf("%s: wire shape changed, mutation needs updating: %s", name, valid)
		}
		if _, err := DecodeWorkerMessage([]byte(mutated), BrokerToWorker); err == nil {
			t.Fatalf("%s: malformed rubric accepted", name)
		}
	}
	// The broker validates before it frames a bootstrap, so unsafe text never
	// reaches a worker that would fail to decode it.
	for name, text := range map[string]string{"NUL": "ru\x00bric", "invalid UTF-8": "ru\xffbric"} {
		boot := riskPolicyBootstrap(&RiskPolicy{Text: text})
		if err := ValidateWorkerMessage(boot, BrokerToWorker); err == nil {
			t.Fatalf("%s: broker-side validation accepted the rubric", name)
		}
	}
}
