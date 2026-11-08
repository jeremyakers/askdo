package fleetclient

import (
	"context"
	"net/http"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// ReportStatus tells the gateway which release this host runs and how its last
// upgrade ended. Nothing the host does depends on the answer, so only success
// or failure is read from it; a failure is the caller's to note and to repeat
// with its next report. A gateway that does not know the endpoint answers with
// an ordinary transport failure.
func (c *Client) ReportStatus(ctx context.Context, status fleetproto.HostStatus) error {
	data, err := fleetproto.MarshalHostStatus(status)
	if err != nil {
		return &Error{fleetproto.ErrCodeProtocol}
	}
	_, err = c.Request(ctx, http.MethodPut, "/v1/host-status", data, false)
	return err
}
