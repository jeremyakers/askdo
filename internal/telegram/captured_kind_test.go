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
		parts, err := RenderSummaryParts(in)
		if err != nil {
			t.Fatal(err)
		}
		label := capturedDeliveryLabel(kind)
		if !strings.Contains(strings.Join(parts, ""), label) {
			t.Fatal("reviewed kind missing")
		}
		u := ApprovalOnlyInput{Host: in.Host, JobID: in.JobID, Operation: in.Operation, Expiry: in.Expiry, CapturedStdinBytes: 17, CapturedStdinKind: kind}
		parts, err = RenderApprovalOnlySummaryParts(u)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(parts, ""), label) {
			t.Fatal("unreviewed kind missing")
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
