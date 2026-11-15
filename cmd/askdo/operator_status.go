package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/gateway"
)

func gatewayStatus(ctx context.Context, view string) (string, error) {
	return gatewayStatusAt(ctx, view, defaultGatewayConfig)
}

func gatewayStatusAt(ctx context.Context, view, path string) (string, error) {
	var out strings.Builder
	if err := ctx.Err(); err != nil {
		return "", err
	}
	store, err := openGatewayStatus(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "no fleet gateway is configured on this host\n", nil
		}
		return "", err
	}
	defer store.Close()
	if view == "hosts" {
		err := gatewayListHosts(ctx, store, &out)
		return out.String(), err
	}
	upgrades, err := gateway.NewUpgradeStore(store)
	if err != nil {
		return "", err
	}
	err = upgradeFleetStatus(ctx, store, upgrades, &out)
	return out.String(), err
}

func openGatewayStatus(ctx context.Context, path string) (*gateway.EnrollmentStore, error) {
	cfg, err := loadGatewayOperator(path)
	if err != nil {
		return nil, err
	}
	return gateway.OpenEnrollmentStatus(ctx, cfg.Database)
}

// gatewayHostsAvailable gates the reviewer tool with the same read-only,
// no-migration config/database existence check as the operator hosts view.
func gatewayHostsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return gatewayHostsAvailableAt(ctx, defaultGatewayConfig)
}

func gatewayHostsAvailableAt(ctx context.Context, path string) bool {
	store, err := openGatewayStatus(ctx, path)
	if err != nil {
		return false
	}
	return store.Close() == nil
}
