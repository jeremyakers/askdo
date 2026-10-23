package reviewer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestReviewSecurityRiskScores(t *testing.T) {
	for _, risk := range []string{"1", "2", "3", "4", "5", "unknown", "low", "medium", "high", "0", "6", "01", "", "<b>1</b>"} {
		t.Run(risk, func(t *testing.T) {
			input := strings.Replace(validReview, `"risk":"4"`, `"risk":"`+risk+`"`, 1)
			report, err := ValidateReportArgs([]byte(input))
			wantValid := risk == "1" || risk == "2" || risk == "3" || risk == "4" || risk == "5" || risk == "unknown"
			if (err == nil) != wantValid || (wantValid && report.Risk != risk) {
				t.Fatalf("risk %q: report=%+v err=%v", risk, report, err)
			}
		})
	}
}

const validReview = `{"risk":"4","summary":"Will change state.","effects":["Changes a file."],"warnings":[{"message":"May fail.","evidence":"f1:1"}],"missing_context":[],"reversibility":"No verified rollback.","intent_match":"unverified"}`

func TestReviewSuggestions_whenOptionalOrInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, suggestions string
		valid             bool
	}{
		{"absent", "", true},
		{"empty", `[]`, true},
		{"null array", `null`, false},
		{"submitter", `[{"issue":"Unknown backup","action":"Supply backup evidence","actor":"submitter"}]`, true},
		{"administrator", `[{"issue":"Inspection denied","action":"Review inspection scope","actor":"administrator"}]`, true},
		{"bad actor", `[{"issue":"Unknown backup","action":"Supply evidence","actor":"root"}]`, false},
		{"missing issue", `[{"action":"Supply evidence","actor":"submitter"}]`, false},
		{"missing action", `[{"issue":"Unknown backup","actor":"submitter"}]`, false},
		{"null issue", `[{"issue":null,"action":"Inspect","actor":"submitter"}]`, false},
		{"long issue", `[{"issue":"` + strings.Repeat("x", 513) + `","action":"Inspect","actor":"submitter"}]`, false},
		{"long action", `[{"issue":"Unknown","action":"` + strings.Repeat("x", 513) + `","actor":"submitter"}]`, false},
		{"too many", `[` + strings.TrimSuffix(strings.Repeat(`{"issue":"Unknown","action":"Inspect","actor":"submitter"},`, 17), ",") + `]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a legacy report with an optional suggestion extension.
			input := validReview
			if tc.suggestions != "" {
				input = strings.TrimSuffix(input, "}") + `,"suggestions":` + tc.suggestions + `}`
			}
			// When the submit_review boundary parses the report.
			report, err := ValidateReportArgs([]byte(input))
			// Then only bounded suggestions with a known actor are accepted.
			if (err == nil) != tc.valid {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestValidateReportArgs(t *testing.T) {
	if report, err := ValidateReportArgs([]byte(validReview)); err != nil || report.Risk != "4" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	tests := map[string]string{
		"bad risk":        strings.Replace(validReview, `"risk":"4"`, `"risk":"critical"`, 1),
		"bad intent":      strings.Replace(validReview, `"unverified"`, `"yes"`, 1),
		"unknown":         strings.Replace(validReview, `"summary":`, `"approved":true,"summary":`, 1),
		"callback":        strings.Replace(validReview, `"summary":`, `"callback_data":"a:bad","summary":`, 1),
		"provider":        strings.Replace(validReview, `"summary":`, `"provider_identity":"fake","summary":`, 1),
		"duplicate":       strings.Replace(validReview, `"risk":"4"`, `"risk":"1","risk":"4"`, 1),
		"missing summary": strings.Replace(validReview, `"summary":"Will change state.",`, ``, 1),
		"long summary":    strings.Replace(validReview, "Will change state.", strings.Repeat("x", 2049), 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateReportArgs([]byte(input)); !errors.Is(err, ErrMalformedReview) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestValidateReportAllEnumsAndBounds(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"risk": "1", "summary": "s", "effects": []string{}, "warnings": []map[string]string{}, "missing_context": []string{}, "reversibility": "r", "intent_match": "consistent"}
	}
	validate := func(report map[string]any) error {
		data, err := json.Marshal(report)
		if err != nil {
			return err
		}
		_, err = ValidateReportArgs(data)
		return err
	}
	for _, risk := range []string{"1", "2", "3", "4", "5", "unknown"} {
		report := base()
		report["risk"] = risk
		if err := validate(report); err != nil {
			t.Fatalf("risk %s: %v", risk, err)
		}
	}
	for _, intent := range []string{"consistent", "inconsistent", "unverified"} {
		report := base()
		report["intent_match"] = intent
		if err := validate(report); err != nil {
			t.Fatalf("intent %s: %v", intent, err)
		}
	}
	cases := map[string]func(map[string]any){
		"summary":        func(r map[string]any) { r["summary"] = strings.Repeat("x", 2049) },
		"effects count":  func(r map[string]any) { r["effects"] = make([]string, 33) },
		"effect length":  func(r map[string]any) { r["effects"] = []string{strings.Repeat("x", 513)} },
		"warnings count": func(r map[string]any) { r["warnings"] = make([]map[string]string, 33) },
		"warning message": func(r map[string]any) {
			r["warnings"] = []map[string]string{{"message": strings.Repeat("x", 513), "evidence": "e"}}
		},
		"warning evidence": func(r map[string]any) {
			r["warnings"] = []map[string]string{{"message": "m", "evidence": strings.Repeat("x", 513)}}
		},
		"missing count":  func(r map[string]any) { r["missing_context"] = make([]string, 17) },
		"missing length": func(r map[string]any) { r["missing_context"] = []string{strings.Repeat("x", 513)} },
		"reversibility":  func(r map[string]any) { r["reversibility"] = strings.Repeat("x", 1025) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			report := base()
			mutate(report)
			if err := validate(report); !errors.Is(err, ErrMalformedReview) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
