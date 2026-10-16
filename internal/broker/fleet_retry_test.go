package broker

import (
	"testing"

	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestFleetRetryStillConsumesRootCallSlots(t *testing.T) {
	// Given the real root-owned choice/sequence boundary, when a transient turn
	// is retried, then the same attempt advances its physical call counter.
	j, request := fleetTurnFixture()
	request.RetryTransient = true
	first, err := j.fleetTurn(request)
	if err != nil || !first.RetryTransient {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	failure := fleetproto.ModelResult{Binding: first.Binding, Failure: &fleetproto.Failure{Code: fleetproto.ErrCodeUpstreamTransport}, Retry: &modelwire.Retry{AfterMS: 250}}
	response, err := j.fleetTurnResult(request, failure, &fleetclient.Error{Code: fleetproto.ErrCodeUpstreamTransport})
	if err != nil || response.Failure == nil || response.Failure.Retry == nil || len(j.fleet.failures) != 0 || j.fleet.retryFailure == nil {
		t.Fatalf("temporary result advanced choice: %+v %v", response, err)
	}
	request.RequestSeq++
	second, err := j.fleetTurn(request)
	if err != nil || second.RetryTransient || second.Binding.Attempt != first.Binding.Attempt || second.Binding.Turn != first.Binding.Turn+1 || second.Binding.Deadline != first.Binding.Deadline {
		t.Fatalf("retry=%+v err=%v", second, err)
	}
	if _, err := j.fleetTurnResult(request, fleetproto.ModelResult{Binding: second.Binding, Response: &modelwire.ModelResponse{}}, nil); err != nil {
		t.Fatal(err)
	}
	if j.fleet.retryFailure != nil || len(j.fleet.failures) != 0 || !j.fleet.responded {
		t.Fatal("successful retry polluted fallback history")
	}
	request.RequestSeq++
	if _, err := j.fleetTurn(request); err == nil {
		t.Fatal("root call budget reset by retry")
	}
}

func TestFleetPendingRetryCanFinishAvailabilityHistory(t *testing.T) {
	// Given a retryable failure that cannot fit the worker's remaining deadline,
	// when the worker reports unavailability, then root retains the typed cause
	// rather than rejecting honest history or forcing another provider call.
	j, _ := fleetTurnFixture()
	j.fleet.retryFailure = &proto.AvailabilityFailure{Name: "local", Code: proto.AvailabilityTransport}
	history := []proto.AvailabilityFailure{*j.fleet.retryFailure}
	if !j.validUnavailableHistory(history) {
		t.Fatal("pending transient became invalid review history")
	}
	if len(j.fleet.failures) != 1 || j.fleet.failures[0] != history[0] {
		t.Fatal("root availability history lost")
	}
}

func TestFleetPendingRetryAdvancesOnlyInFrozenOrder(t *testing.T) {
	// Given root's previous typed transient outcome, when the loop elects its
	// next frozen choice, then that outcome is finalized once, not model-shopped
	// without an actual availability failure and not charged as another call.
	j, request := fleetTurnFixture()
	first, err := j.fleetTurn(request)
	if err != nil {
		t.Fatal(err)
	}
	j.fleet.retryFailure = &proto.AvailabilityFailure{Name: "local", Code: proto.AvailabilityTimeout}
	p := j.fleet.selection.Profiles[0]
	p.ProfileID = "second"
	p.Revision, _ = fleetproto.HashProfile(p)
	j.fleet.selection.Profiles = append(j.fleet.selection.Profiles, p)
	j.models = append(j.models, proto.ProjectedModel{Name: "second", Model: "fixture"})
	request.RequestSeq++
	request.ChoiceName = "second"
	next, err := j.fleetTurn(request)
	if err != nil || next.Binding.Attempt != first.Binding.Attempt+1 || next.Binding.Turn != 1 || len(j.fleet.failures) != 1 {
		t.Fatalf("next=%+v err=%v", next, err)
	}
}

func TestFleetUnknownTimeoutOnlyRecoversIdenticalChargedSuccessor(t *testing.T) {
	// Given root's own timer lost a signed outcome, when recovery is requested,
	// then it is neither provider fallback nor a new attempt/call-budget reset.
	j, request := fleetTurnFixture()
	request.RetryTransient = true
	first, err := j.fleetTurn(request)
	if err != nil {
		t.Fatal(err)
	}
	j.fleet.retryFailure = &proto.AvailabilityFailure{Name: "local", Code: proto.AvailabilityTransport}
	outcome := j.fleetRequestTimeout(request, first)
	if outcome.Failure == nil || outcome.Failure.Code != proto.ModelRequestTimeout || outcome.Failure.Retry == nil || j.fleet.retryFailure != nil || len(j.fleet.failures) != 0 {
		t.Fatalf("timeout upgraded to provider failure: %+v", outcome)
	}
	if j.validUnavailableHistory([]proto.AvailabilityFailure{{Name: "local", Code: proto.AvailabilityTimeout}}) || j.fleetReviewHistory(&proto.ReviewComplete{ModelHistory: []proto.ModelHistoryEntry{{Name: "local", Outcome: "ok"}}}) {
		t.Fatal("unknown outcome authorized review/NO AI")
	}
	request.RequestSeq++
	altered := request
	altered.Request.Messages = []modelwire.Message{{Role: "user", Content: "altered evidence"}}
	if _, err := j.fleetTurn(altered); err == nil {
		t.Fatal("unknown recovery changed evidence")
	}
	alternative := request
	alternative.ChoiceName = "other"
	if _, err := j.fleetTurn(alternative); err == nil {
		t.Fatal("unknown recovery shopped models")
	}
	second, err := j.fleetTurn(request)
	if err != nil || !second.RecoverPrevious || second.RetryTransient || second.Binding.Attempt != first.Binding.Attempt || second.Binding.Turn != 2 {
		t.Fatalf("successor=%+v err=%v", second, err)
	}
	last := j.fleetRequestTimeout(request, second)
	if last.Failure.Code != proto.ModelRequestTimeout || last.Failure.Retry != nil {
		t.Fatal("unknown exhaustion offered more calls")
	}
	request.RequestSeq++
	if _, err := j.fleetTurn(request); err == nil {
		t.Fatal("unknown exhaustion reset call budget")
	}
	if j.validUnavailableHistory([]proto.AvailabilityFailure{{Name: "local", Code: proto.AvailabilityTimeout}}) {
		t.Fatal("unverified timeout permitted human NO AI")
	}
}
