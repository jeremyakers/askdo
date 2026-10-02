//go:build !askdo_fleet_fixture

package main

import "github.com/jeremyakers/askdo/internal/gateway"

func newGatewayServer(c gateway.Config, s *gateway.EnrollmentStore) (*gateway.Server, error) {
	return gateway.NewServer(c, s)
}
