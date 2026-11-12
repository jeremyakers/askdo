package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/gateway"
)

func TestGatewayRootHostRenameAndStatusProjection(t *testing.T) {
	_, path := gatewayOperatorFixture(t)
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenEnrollmentStore(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host, _, err := store.Create(t.Context(), gateway.EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"hosts", "rename", host.HostID, "office-desktop", "--config", path}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, &stderr)
	}
	for _, view := range []string{"hosts", "fleet"} {
		text, err := gatewayStatusAt(t.Context(), view, path)
		if err != nil || !strings.Contains(text, "name=office-desktop") || !strings.Contains(text, "enabled=true") || !strings.Contains(text, "release=unknown") || !strings.Contains(text, "seen=never") {
			t.Fatalf("%s: %s %v", view, text, err)
		}
	}
	out.Reset()
	stderr.Reset()
	if code := runGateway([]string{"hosts", "rename", "host_missing", "name", "--config", path}, &out, &stderr); code == 0 || !strings.Contains(stderr.String(), "gateway hosts list") {
		t.Fatalf("%d %s", code, &stderr)
	}
	t.Run("duplicate-rename-output", func(t *testing.T) {
		other, _, err := store.Create(t.Context(), gateway.EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
		if err != nil {
			t.Fatal(err)
		}
		out.Reset()
		stderr.Reset()
		if code := runGateway([]string{"hosts", "rename", other.HostID, "office\u200b-desktop", "--config", path}, &out, &stderr); code != 0 {
			t.Fatalf("%d %s", code, &stderr)
		}
		want := "office-desktop-" + strings.TrimPrefix(other.HostID, "host_")[:4]
		if !strings.Contains(out.String(), "renamed "+other.HostID+" to \""+want+"\"") {
			t.Fatal(out.String())
		}
		stored, err := store.Get(t.Context(), other.HostID)
		if err != nil || stored.DisplayName != want {
			t.Fatalf("%+v %v", stored, err)
		}
	})
	t.Run("missing-status-database", func(t *testing.T) {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(cfg.Database); err != nil {
			t.Fatal(err)
		}
		for _, view := range []string{"hosts", "fleet"} {
			text, err := gatewayStatusAt(t.Context(), view, path)
			if err != nil || text != "no fleet gateway is configured on this host\n" {
				t.Fatalf("%s: %q %v", view, text, err)
			}
			if _, err := os.Stat(cfg.Database); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("status created database: %v", err)
			}
		}
	})
}
