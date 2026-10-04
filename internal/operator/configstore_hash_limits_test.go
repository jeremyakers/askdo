package operator

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
)

func TestConfigStoreUnrelatedSavePreservesOmittedHashLimits(t *testing.T) {
	stubConfigCredentialChecks(t)
	stubOwnership(t)
	for _, section := range []Section{SectionReview, SectionTelegram} {
		t.Run(map[Section]string{SectionReview: "review", SectionTelegram: "telegram"}[section], func(t *testing.T) {
			original := fixtureConfig(t, t.TempDir(), false, false)
			path := writeFixture(t, original)
			store, err := LoadForMutation(path)
			if err != nil {
				t.Fatal(err)
			}
			if store.Config().Limits.MaxHashFileBytes != 32<<20 || store.Config().Limits.MaxHashedBytesPerReview != 64<<20 {
				t.Fatalf("runtime defaults lost: %+v", store.Config().Limits)
			}
			var expected map[string]any
			if err := json.Unmarshal(original, &expected); err != nil {
				t.Fatal(err)
			}
			if section == SectionReview {
				store.Config().Review.Mode = "approval_only"
			} else {
				store.Config().Telegram.ApprovalTTL = config.Duration(5 * time.Minute)
			}
			if err := store.Save(section); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err := json.Unmarshal(saved, &actual); err != nil {
				t.Fatal(err)
			}
			var document struct {
				Limits json.RawMessage `json:"limits"`
			}
			if err := json.Unmarshal(saved, &document); err != nil {
				t.Fatal(err)
			}
			// This independently describes the legacy decoder's accepted limits.
			var legacyLimits struct {
				MaxInspectedFiles    int   `json:"max_inspected_files"`
				MaxInspectedBytes    int64 `json:"max_inspected_bytes"`
				MaxLogBytesPerStream int64 `json:"max_log_bytes_per_stream"`
			}
			decoder := json.NewDecoder(bytes.NewReader(document.Limits))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&legacyLimits); err != nil {
				t.Fatalf("unrelated save broke legacy limits decoding: %v", err)
			}
			for _, name := range []string{"inspection", "limits"} {
				if !reflect.DeepEqual(actual[name], expected[name]) {
					t.Fatalf("unrelated %s changed: %#v", name, actual[name])
				}
			}
			expectedReview := expected["review"].(map[string]any)
			expectedReview["mode"] = "required"
			if section == SectionReview {
				expectedReview["mode"] = "approval_only"
			} else {
				expected["telegram"].(map[string]any)["approval_ttl"] = "5m0s"
			}
			// Duration rendering is the existing mutation behavior, not this fix.
			expectedReview["request_timeout"] = "2m0s"
			expectedReview["total_timeout"] = "20m0s"
			expectedReview["models"].([]any)[0].(map[string]any)["request_timeout"] = "2m0s"
			if section == SectionReview {
				expected["telegram"].(map[string]any)["approval_ttl"] = "10m0s"
			}
			if !reflect.DeepEqual(actual["review"], expectedReview) || !reflect.DeepEqual(actual["telegram"], expected["telegram"]) {
				t.Fatalf("section mutation or preservation failed: review=%#v telegram=%#v", actual["review"], actual["telegram"])
			}
			reloaded, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.Limits != store.Config().Limits {
				t.Fatalf("runtime reload changed budgets: %+v", reloaded.Limits)
			}
		})
	}
}
