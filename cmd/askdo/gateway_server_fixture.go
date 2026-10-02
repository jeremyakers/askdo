//go:build askdo_fleet_fixture

package main

import (
	"os"

	"github.com/jeremyakers/askdo/internal/gateway"
)

func newGatewayServer(c gateway.Config, s *gateway.EnrollmentStore) (*gateway.Server, error) {
	if url := os.Getenv("ASKDO_FLEET_TELEGRAM_URL"); url != "" {
		return gateway.NewFixtureServer(c, s, url)
	}
	return gateway.NewServer(c, s)
}
