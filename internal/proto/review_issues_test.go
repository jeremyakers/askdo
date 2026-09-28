package proto

import "testing"

func TestFrozenWithheldBoundsAndDirection(t *testing.T) {
	report := ReviewReport{Risk: "unknown", Effects: []string{}, Warnings: []ReviewWarning{}, MissingContext: []string{}, IntentMatch: "unverified"}
	frozen := Frozen{Type: "frozen", ManifestDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Report: report, WithheldCount: 1, WithheldRefs: []string{"secret.env"}}
	if err := ValidateWorkerMessage(frozen, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkerMessage(frozen, WorkerToBroker); err == nil {
		t.Fatal("worker forged frozen message")
	}
	frozen.WithheldCount = -1
	if err := ValidateWorkerMessage(frozen, BrokerToWorker); err == nil {
		t.Fatal("negative count accepted")
	}
	frozen.WithheldCount = 1
	frozen.WithheldRefs = []string{"unobserved", "another"}
	if err := ValidateWorkerMessage(frozen, BrokerToWorker); err == nil {
		t.Fatal("more refs than count accepted")
	}
}
