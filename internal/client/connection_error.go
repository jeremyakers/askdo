package client

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func connectionError(err error) error {
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("you are not in the askdo group (or need to log out and back in after sudo usermod -aG askdo USER): %w", err)
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("the askdo service is not running: sudo systemctl enable --now askdo: %w", err)
	default:
		return fmt.Errorf("cannot connect to the askdo broker; check the service with sudo systemctl status askdo: %w", err)
	}
}
