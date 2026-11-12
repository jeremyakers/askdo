package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func OperatorStatus(parent context.Context, socket, view string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	socket = withDefaults(Options{SocketPath: socket}).SocketPath
	conn, err := dial(ctx, socket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := send(conn, proto.OperatorStatusRequest{Op: "operator_status", View: view}); err != nil {
		return "", fmt.Errorf("cannot request status: %w; retry the status command", err)
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		return "", fmt.Errorf("cannot read status: %w; retry the status command", err)
	}
	var event proto.OperatorStatusEvent
	if proto.StrictUnmarshal(body, &event) == nil && event.Op == "operator_status" {
		return event.Text, nil
	}
	var failure proto.ErrorEvent
	if proto.StrictUnmarshal(body, &failure) == nil && failure.Validate() == nil {
		if failure.Code == "invalid_request" {
			return "", errors.New("this broker does not support read-only operator status; upgrade askdo and restart the service with sudo systemctl restart askdo, then retry")
		}
		return "", errors.New(failure.Message)
	}
	return "", errors.New("invalid status response; upgrade the askdo client and broker together")
}
