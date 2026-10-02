package fleetclient

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/jobid"
)

// PutTicket preserves the exact frozen submission bytes across reconnects.
// The signed acknowledgement is acceptance only, not delivery/approval proof.
func (c *Client) PutTicket(ctx context.Context, data []byte) (fleetproto.TicketAck, error) {
	sub, err := fleetproto.Parse[fleetproto.TicketSubmission](data)
	if err != nil || sub.Ticket.Binding.HostID != c.host {
		return fleetproto.TicketAck{}, &Error{fleetproto.ErrCodeProtocol}
	}
	wire, err := c.Request(ctx, http.MethodPut, "/v1/tickets/"+url.PathEscape(string(sub.Ticket.Binding.JobID)), data, false)
	if err != nil {
		return fleetproto.TicketAck{}, err
	}
	ack, _, err := VerifyResponse[fleetproto.TicketAck](c, wire)
	if err != nil {
		return ack, err
	}
	hash, _ := fleetproto.HashSubmissionBytes(data)
	if ack.Binding != sub.Ticket.Binding || ack.SubmissionHash != hash {
		return fleetproto.TicketAck{}, &Error{fleetproto.ErrCodeProtocol}
	}
	return ack, nil
}

func (c *Client) SubmitTicket(ctx context.Context, sub fleetproto.TicketSubmission) (fleetproto.TicketAck, error) {
	data, err := json.Marshal(sub)
	if err != nil {
		return fleetproto.TicketAck{}, &Error{fleetproto.ErrCodeProtocol}
	}
	return c.PutTicket(ctx, data)
}

// NextEvent makes one bounded long poll, never renewing the caller's lifecycle.
// A 204 returns false. Cryptographic and stream identity checks happen here;
// root must still CheckReceipt/CheckDecision against its frozen one-use state.
func (c *Client) NextEvent(ctx context.Context, job fleetproto.ID, after uint64) (fleetproto.Event, bool, error) {
	event, _, ok, err := c.NextEventProof(ctx, job, after)
	return event, ok, err
}

// NextEventProof additionally returns the original signed envelope for audit.
func (c *Client) NextEventProof(ctx context.Context, job fleetproto.ID, after uint64) (fleetproto.Event, []byte, bool, error) {
	if jobid.Validate(string(job)) != nil || after >= math.MaxInt64 {
		return fleetproto.Event{}, nil, false, &Error{fleetproto.ErrCodeProtocol}
	}
	target := "/v1/tickets/" + url.PathEscape(string(job)) + "/events?after=" + strconv.FormatUint(after, 10) + "&wait_ms=20000"
	wire, err := c.Request(ctx, http.MethodGet, target, nil, false)
	if err != nil {
		return fleetproto.Event{}, nil, false, err
	}
	if len(wire) == 0 {
		return fleetproto.Event{}, nil, false, nil
	}
	event, _, err := VerifyResponse[fleetproto.Event](c, wire)
	if err != nil {
		return fleetproto.Event{}, nil, false, err
	}
	if event.HostID != c.host || event.JobID != job || event.Sequence != after+1 {
		return fleetproto.Event{}, nil, false, &Error{fleetproto.ErrCodeProtocol}
	}
	return event, wire, true, nil
}
