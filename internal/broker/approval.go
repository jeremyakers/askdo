package broker

import (
	"context"

	"github.com/jeremyakers/askdo/internal/approval"
	"github.com/jeremyakers/askdo/internal/proto"
)

// runBrokerApproval starts only after EOF and successful exit of the isolated
// reviewer. The shared approval stage handles only immutable frozen facts; its
// callbacks still pass through recordApproval and consumeDecision's authority gates.
func (j *jobRuntime) runBrokerApproval(ctx context.Context, session WorkerSession, frozen any, history []proto.ModelHistoryEntry) {
	if err := waitFleetExit(ctx, session); err != nil {
		j.fail("reviewer did not exit cleanly before broker approval")
		return
	}
	approvalCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-j.done:
			cancel()
		case <-approvalCtx.Done():
		}
	}()
	defer func() { cancel(); <-joined }()
	bootstrap := j.bootstrap()
	client, err := j.daemon.telegramClient(bootstrap.ConfigProjection.Telegram.TokenFile)
	if err != nil {
		j.fail("initialize approval client")
		return
	}
	transport := approval.Transport{Client: client, Subscribe: j.daemon.telegramHub.Subscribe,
		Progress: func(p proto.Progress) error {
			stage := p.Stage
			if stage == "awaiting_human" {
				stage = "awaiting-human"
			}
			j.progress(stage, p.Detail)
			return nil
		},
		OnSent: func(n proto.NotificationSent) error { return j.recordApproval(approvalCtx, &n) },
	}
	var decision *proto.Decision
	switch value := frozen.(type) {
	case proto.Frozen:
		decision, err = approval.NotifyReviewed(approvalCtx, transport, approval.ReviewedFacts{Bootstrap: bootstrap, History: history, Frozen: value})
	case proto.ApprovalOnlyFrozen:
		decision, err = approval.NotifyUnreviewed(approvalCtx, transport, approval.UnreviewedFacts{Bootstrap: bootstrap, Frozen: value})
	}
	if err != nil {
		j.fail("human approval did not complete")
		return
	}
	if decision == nil {
		j.expireIfApprovalLapsed(context.Background())
		return
	}
	// The approval expiry/cancellation context must never govern committed work.
	j.consumeDecision(ctx, decision)
}
