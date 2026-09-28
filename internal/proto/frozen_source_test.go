package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFrozenWithheldFactsWire(t *testing.T) {
	message := Frozen{Type: "frozen", ManifestDigest: strings.Repeat("a", 64), Report: ReviewReport{Risk: "unknown", Summary: "read what was available", Effects: []string{}, Warnings: []ReviewWarning{}, MissingContext: []string{}, Reversibility: "unknown", IntentMatch: "unverified"}, WithheldRefs: []string{".env"}, WithheldCount: 1}
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeWorkerMessage(raw, BrokerToWorker)
	if err != nil || decoded.(*Frozen).WithheldRefs[0] != ".env" {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	for _, invalid := range []Frozen{
		{Type: "frozen", ManifestDigest: message.ManifestDigest, Report: message.Report, WithheldCount: 1},
		{Type: "frozen", ManifestDigest: message.ManifestDigest, Report: message.Report, WithheldRefs: []string{".env", ".env"}, WithheldCount: 2},
		{Type: "frozen", ManifestDigest: message.ManifestDigest, Report: message.Report, WithheldRefs: []string{".env"}, WithheldCount: 0},
	} {
		if err := ValidateWorkerMessage(invalid, BrokerToWorker); err == nil {
			t.Fatalf("accepted invalid facts: %+v", invalid)
		}
	}
}

func TestReviewCompleteNeedsNoDirectReads(t *testing.T) {
	message := ReviewComplete{Type: "review_complete", Report: validReport(), ModelHistory: []ModelHistoryEntry{{Name: "model", Outcome: "ok"}}}
	// Review validation checks the report schema and model history only; no
	// inspected-file count or other broker-only limit constrains it.
	if err := ValidateReviewComplete(message); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	data, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"coverage"`) || strings.Contains(string(data), `"file_id"`) || strings.Contains(string(data), `"captures"`) {
		t.Fatalf("obsolete fields leaked into review: %s", data)
	}
}
