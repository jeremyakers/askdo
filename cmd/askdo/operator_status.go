package main

import (
	"context"
	"strings"

	"github.com/jeremyakers/askdo/internal/gateway"
)

func gatewayStatus(ctx context.Context, view string) (string, error) {
	return gatewayStatusAt(ctx, view, defaultGatewayConfig)
}

func gatewayStatusAt(ctx context.Context, view, path string) (string, error) {
	var out strings.Builder
	if view == "hosts" {
		err := gatewayHosts([]string{"list", "--config", path}, &out)
		return out.String(), err
	}
	cfg, err := loadGatewayOperator(path)
	if err != nil {
		return "", err
	}
	store, err := gateway.OpenEnrollmentStore(cfg.Database)
	if err != nil {
		return "", err
	}
	defer store.Close()
	upgrades, err := gateway.NewUpgradeStore(store)
	if err != nil {
		return "", err
	}
	err = upgradeFleetStatus(ctx, store, upgrades, &out)
	return out.String(), err
}
