package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDecodeForMutation verifies the strict-decode-without-whole-validate
// entry point: defaults are applied and presence is recorded, malformed and
// unknown fields are rejected, but values that whole-file Validate would
// reject (placeholder telegram IDs) decode fine.
func TestDecodeForMutation(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	raw := []byte(`{
		"config_version": 4,
		"inspection": {"read_roots": [], "trusted_executable_roots": []},
		"review": {"models": []},
		"limits": {},
		"telegram": {"token_file": "/etc/askdo/credentials/telegram.token", "operator_user_id": 0, "chat_id": 0}
	}`)
	cfg, err := DecodeForMutation(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Telegram.OperatorUserID != 0 || cfg.Telegram.ChatID != 0 {
		t.Fatal("placeholder telegram IDs must decode without whole-file validation")
	}
	if time.Duration(cfg.Review.RequestTimeout) != defaultRequestTimeout {
		t.Fatalf("default request timeout not applied: %v", cfg.Review.RequestTimeout)
	}
	if time.Duration(cfg.Telegram.ApprovalTTL) != defaultApprovalTTL {
		t.Fatalf("default approval TTL not applied: %v", cfg.Telegram.ApprovalTTL)
	}
	if cfg.Limits.MaxInspectedFiles != 256 {
		t.Fatalf("default limits not applied: %d", cfg.Limits.MaxInspectedFiles)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("decoded placeholder config must still fail whole-file Validate")
	}
}

func TestDecodeForMutationRejects(t *testing.T) {
	base := `{
		"config_version": 4,
		"inspection": {"read_roots": [], "trusted_executable_roots": []},
		"review": {"models": []},
		"limits": {},
		"telegram": {"token_file": "/x", "operator_user_id": 1, "chat_id": 1}
	}`
	cases := []struct {
		name string
		raw  string
	}{
		{"unknown-top", strings.Replace(base, `"limits": {}`, `"limits": {}, "bogus": 1`, 1)},
		{"unknown-model-field", strings.Replace(base, `"models": []`, `"models": [{"name": "a", "api": "openai_chat", "base_url": "https://x.invalid", "model": "m", "bogus": 1}]`, 1)},
		{"malformed", `{"config_version":`},
		{"missing-object", `{"config_version": 4}`},
		{"missing-version", `{"inspection": {"read_roots": [], "trusted_executable_roots": []}, "review": {"models": []}, "limits": {}, "telegram": {"token_file": "/x", "operator_user_id": 1, "chat_id": 1}}`},
		{"old-version", strings.Replace(base, `"config_version": 4`, `"config_version": 3`, 1)},
		{"unsupported-version", strings.Replace(base, `"config_version": 4`, `"config_version": 5`, 1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeForMutation([]byte(test.raw)); err == nil {
				t.Fatal("expected decode error")
			}
		})
	}
}

func TestValidateTelegramSection(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	valid := TelegramConfig{
		TokenFile:      "/etc/askdo/credentials/telegram.token",
		OperatorUserID: 123,
		ChatID:         -456,
		ApprovalTTL:    Duration(10 * time.Minute),
	}
	if err := ValidateTelegramSection(valid); err != nil {
		t.Fatalf("valid telegram section rejected: %v", err)
	}
	for _, ttl := range []time.Duration{30 * time.Second, 2 * time.Hour, 24 * time.Hour, 48 * time.Hour, 1<<63 - 1} {
		section := valid
		section.ApprovalTTL = Duration(ttl)
		if err := ValidateTelegramSection(section); err != nil {
			t.Errorf("approval_ttl %v rejected: %v", ttl, err)
		}
	}
	cases := []struct {
		name   string
		mutate func(*TelegramConfig)
	}{
		{"token-relative", func(g *TelegramConfig) { g.TokenFile = "relative" }},
		{"user-id-zero", func(g *TelegramConfig) { g.OperatorUserID = 0 }},
		{"user-id-negative", func(g *TelegramConfig) { g.OperatorUserID = -1 }},
		{"chat-zero", func(g *TelegramConfig) { g.ChatID = 0 }},
		{"ttl-low", func(g *TelegramConfig) { g.ApprovalTTL = Duration(29 * time.Second) }},
		{"ttl-zero", func(g *TelegramConfig) { g.ApprovalTTL = 0 }},
		{"ttl-negative", func(g *TelegramConfig) { g.ApprovalTTL = Duration(-time.Second) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			section := valid
			test.mutate(&section)
			if err := ValidateTelegramSection(section); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateReviewSection(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	valid := validConfig().Review
	if err := ValidateReviewSection(valid); err != nil {
		t.Fatalf("valid review section rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*ReviewConfig)
	}{
		{"models-empty", func(r *ReviewConfig) { r.Models = nil }},
		{"sibling-invalid", func(r *ReviewConfig) {
			r.Models = append(r.Models, ModelConfig{Name: "bad", API: "bogus", BaseURL: "https://x.invalid", Model: "m", DataBoundary: "external", RequestTimeout: r.RequestTimeout})
		}},
		{"request-timeout", func(r *ReviewConfig) { r.RequestTimeout = 0 }},
		{"total-timeout", func(r *ReviewConfig) { r.TotalTimeout = 0 }},
		{"calls", func(r *ReviewConfig) { r.MaxModelCallsPerAttempt = 0 }},
		{"tokens", func(r *ReviewConfig) { r.MaxOutputTokens = 0 }},
		{"model-timeout", func(r *ReviewConfig) { r.Models[0].RequestTimeout = 0 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			section := validConfig().Review
			test.mutate(&section)
			if err := ValidateReviewSection(section); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// A wizard mutating an unrelated section must round-trip explicit
// review.auto_approve_grants unchanged, and an omitted field must stay
// omitted (never pinned as an explicit empty array).
func TestDecodeForMutationAutoApproveGrants(t *testing.T) {
	raw := []byte(`{
		"config_version": 4,
		"inspection": {"read_roots": [], "trusted_executable_roots": []},
		"review": {"models": [], "auto_approve_grants": [{"user": "sample-agent", "max_risk": 1}]},
		"limits": {},
		"telegram": {"token_file": "/x", "operator_user_id": 1, "chat_id": 1}
	}`)
	cfg, err := DecodeForMutation(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cfg.Review.AutoApproveGrants) != 1 || cfg.Review.AutoApproveGrants[0].User != "sample-agent" || cfg.Review.AutoApproveGrants[0].MaxRisk != 1 {
		t.Fatalf("grants lost on decode: %+v", cfg.Review.AutoApproveGrants)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"auto_approve_grants":[{"user":"sample-agent","max_risk":1}]`) {
		t.Fatalf("grants lost on wizard save: %s", data)
	}
	reloaded, err := DecodeForMutation(data)
	if err != nil {
		t.Fatalf("re-decode of marshaled config: %v", err)
	}
	if len(reloaded.Review.AutoApproveGrants) != 1 || reloaded.Review.AutoApproveGrants[0].MaxRisk != 1 {
		t.Fatalf("round trip lost grants: %+v", reloaded.Review.AutoApproveGrants)
	}

	omitted := []byte(`{
		"config_version": 4,
		"inspection": {"read_roots": [], "trusted_executable_roots": []},
		"review": {"models": []},
		"limits": {},
		"telegram": {"token_file": "/x", "operator_user_id": 1, "chat_id": 1}
	}`)
	cfg, err = DecodeForMutation(omitted)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"auto_approve_grants"`) {
		t.Fatalf("omitted auto_approve_grants pinned on save: %s", data)
	}
}

func TestDurationMarshalRoundTrip(t *testing.T) {
	raw := []byte(`{
		"config_version": 4,
		"inspection": {"read_roots": [], "trusted_executable_roots": []},
		"review": {"models": [], "request_timeout": "90s"},
		"limits": {},
		"telegram": {"token_file": "/x", "operator_user_id": 1, "chat_id": 1, "approval_ttl": "5m"}
	}`)
	cfg, err := DecodeForMutation(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Durations must marshal as quoted Go duration strings (canonicalized by
	// time.Duration.String), never as raw nanosecond numbers.
	if !strings.Contains(string(data), `"request_timeout":"1m30s"`) || !strings.Contains(string(data), `"approval_ttl":"5m0s"`) {
		t.Fatalf("durations did not marshal as Go duration strings: %s", data)
	}
	reloaded, err := DecodeForMutation(data)
	if err != nil {
		t.Fatalf("re-decode of marshaled config: %v", err)
	}
	if time.Duration(reloaded.Review.RequestTimeout) != 90*time.Second {
		t.Fatalf("round trip lost request_timeout: %v", reloaded.Review.RequestTimeout)
	}
}
