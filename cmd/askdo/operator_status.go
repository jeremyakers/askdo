package main

import (
	"context"
	"errors"
	"os"
	"strings"

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
	cfg, err := loadGatewayOperator(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "no fleet gateway is configured on this host\n", nil
		}
		return "", err
	}
	store, err := gateway.OpenEnrollmentStatus(ctx, cfg.Database)
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
