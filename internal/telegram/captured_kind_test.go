package telegram

import (
	"github.com/jeremyakers/askdo/internal/proto"
	"strings"
	"testing"
)

func TestCapturedInputDeliveryLabel(t *testing.T) {
	if got := capturedDeliveryLabel(proto.SocketStream); !strings.Contains(got, "non-seekable") || !strings.Contains(got, "socket_stream") {
		t.Fatal(got)
	}
	if got := capturedDeliveryLabel(""); !strings.Contains(got, "sealed_memfd") {
		t.Fatal(got)
	}
}

func TestCapturedKindReachesReviewedAndUnreviewedRendering(t *testing.T) {
	for _, kind := range []proto.DeliveryKind{"", proto.SealedMemfd, proto.SocketStream} {
		in := testCardInput()
		in.CapturedStdinBytes = 17
		in.CapturedStdinKind = kind
		parts, err := RenderDetails(DetailsInput{CardInput: in})
		if err != nil {
			t.Fatal(err)
		}
		label := capturedDeliveryLabel(kind)
		if !strings.Contains(strings.Join(parts, ""), label) {
			t.Fatal("reviewed kind missing")
		}
		u := ApprovalOnlyInput{Host: in.Host, JobID: in.JobID, Operation: in.Operation, Expiry: in.Expiry, CapturedStdinBytes: 17, CapturedStdinKind: kind}
		parts, err = RenderApprovalOnlyDetails(u)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(parts, ""), label) {
			t.Fatal("unreviewed kind missing")
		}
	}
}

func TestCapturedKindVisibleOnActionableCards(t *testing.T) {
	// The delivery kind is documented as visible before approval, so it must be
	// on the one message an operator sees, not only behind Details.
	for _, tc := range []struct {
		kind proto.DeliveryKind
		want string
	}{
		{"", "captured script input (17 bytes, sealed_memfd)"},
		{proto.SealedMemfd, "captured script input (17 bytes, sealed_memfd)"},
		{proto.SocketStream, "captured script input (17 bytes, socket_stream)"},
	} {
		// Given: captured input of a known delivery kind.
		in := testCardInput()
		in.CapturedStdinBytes = 17
		in.CapturedStdinKind = tc.kind
		u := ApprovalOnlyInput{Host: in.Host, JobID: in.JobID, Operation: in.Operation, Expiry: in.Expiry, CapturedStdinBytes: 17, CapturedStdinKind: tc.kind}
		// When: the reviewed and NO AI REVIEW cards render.
		reviewed, _, err := RenderReviewedCard(in, testNonce)
		if err != nil {
			t.Fatal(err)
		}
		unreviewed, _, err := RenderApprovalOnlyCard(u, testNonce)
		if err != nil {
			t.Fatal(err)
		}
		// Then: both name the kind on the card itself.
		for name, card := range map[string]string{"reviewed": reviewed, "unreviewed": unreviewed} {
			if !strings.Contains(card, tc.want) {
				t.Errorf("%s card for kind %q lacks %q:\n%s", name, tc.kind, tc.want, card)
			}
		}
	}
}

func TestUnknownCapturedKindNeverRenderedAsModern(t *testing.T) {
	in := testCardInput()
	in.CapturedStdinBytes = 17
	in.CapturedStdinKind = "pipe"
	if _, err := RenderSummaryParts(in); err == nil {
		t.Fatal("unknown kind mislabeled modern")
	}
	u := ApprovalOnlyInput{Host: in.Host, JobID: in.JobID, Operation: in.Operation, Expiry: in.Expiry, CapturedStdinBytes: 17, CapturedStdinKind: "pipe"}
	if _, err := RenderApprovalOnlySummaryParts(u); err == nil {
		t.Fatal("unknown kind mislabeled modern")
	}
}
