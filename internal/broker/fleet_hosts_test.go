package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestRootFleetHostsCapabilityProjectionAndFailure(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	gatewayCalls := 0
	j.daemon.operatorStatus = func(context.Context, string) (string, error) {
		gatewayCalls++
		return "", errors.New("must not be called")
	}
	if r := directCall(t, j, "fleet_hosts", struct{}{}); r.Status != "inspection_denied" || r.ReasonCode != "disabled" || gatewayCalls != 0 {
		t.Fatalf("absent capability: %+v calls=%d", r, gatewayCalls)
	}

	j = directJob(t, t.TempDir(), nil)
	availabilityCalls := 0
	j.daemon.fleetHostsAvailable = func() bool {
		availabilityCalls++
		return true
	}
	projection := "host_123 enabled=true name=office-desktop release=v1.2.3\n"
	j.daemon.operatorStatus = func(_ context.Context, view string) (string, error) {
		if view != "hosts" {
			return "", errors.New("unexpected view")
		}
		gatewayCalls++
		return projection, nil
	}
	if !j.inspectionCapabilities().FleetHostsEnabled || !j.inspectionCapabilities().FleetHostsEnabled || availabilityCalls != 1 {
		t.Fatalf("capability was not probed once: calls=%d", availabilityCalls)
	}
	r := directCall(t, j, "fleet_hosts", struct{}{})
	var result proto.FleetHostsResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &result) != nil || result.Hosts != projection || gatewayCalls != 1 {
		t.Fatalf("projection: %+v %+v calls=%d", r, result, gatewayCalls)
	}
	if strings.Contains(string(r.Payload), "bearer") || strings.Contains(string(r.Payload), "secret") {
		t.Fatalf("secret field exposed: %s", r.Payload)
	}

	projection = strings.Repeat("x", proto.MaxInspectionMetadataResultBytes)
	if r := directCall(t, j, "fleet_hosts", struct{}{}); r.Status != "limit_exceeded" || r.ReasonCode != "output_limit" || len(r.Payload) != 0 {
		t.Fatalf("oversize projection: %+v", r)
	}
	j.daemon.operatorStatus = func(context.Context, string) (string, error) {
		return "", errors.New("private locked database diagnostic")
	}
	if r := directCall(t, j, "fleet_hosts", struct{}{}); r.Status != "unresolved" || r.ReasonCode != "inspection_failed" || len(r.Payload) != 0 {
		t.Fatalf("gateway failure: %+v", r)
	}
}

func TestRootFleetHostsGatewayDatabaseFixture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable root gateway fixture required")
	}
	path := filepath.Join(t.TempDir(), "gateway.db")
	store, err := gateway.OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	host, bearer, err := store.Create(t.Context(), gateway.EnrollmentPolicy{DisplayName: "office-desktop", AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	available := func() bool {
		status, err := gateway.OpenEnrollmentStatus(context.Background(), path)
		if err != nil {
			return false
		}
		return status.Close() == nil
	}
	status := func(ctx context.Context, view string) (string, error) {
		if view != "hosts" {
			return "", errors.New("unexpected view")
		}
		store, err := gateway.OpenEnrollmentStatus(ctx, path)
		if err != nil {
			return "", err
		}
		defer store.Close()
		var out bytes.Buffer
		if err := gateway.WriteHostsStatus(ctx, store, &out); err != nil {
			return "", err
		}
		return out.String(), nil
	}
	j := directJob(t, t.TempDir(), nil)
	j.daemon.fleetHostsAvailable = available
	j.daemon.operatorStatus = status
	r := directCall(t, j, "fleet_hosts", struct{}{})
	var result proto.FleetHostsResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &result) != nil || !strings.Contains(result.Hosts, host.HostID) || !strings.Contains(result.Hosts, "name=office-desktop") || !strings.Contains(result.Hosts, "release=unknown") {
		t.Fatalf("gateway projection: %+v %+v", r, result)
	}
	if strings.Contains(result.Hosts, bearer) || strings.Contains(result.Hosts, "bearer") || strings.Contains(result.Hosts, "secret") {
		t.Fatalf("gateway secret exposed: %s", result.Hosts)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing := directJob(t, t.TempDir(), nil)
	missing.daemon.fleetHostsAvailable = available
	missing.daemon.operatorStatus = status
	if r := directCall(t, missing, "fleet_hosts", struct{}{}); r.Status != "inspection_denied" || r.ReasonCode != "disabled" {
		t.Fatalf("missing database offered tool: %+v", r)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status recreated missing database: %v", err)
	}
}
