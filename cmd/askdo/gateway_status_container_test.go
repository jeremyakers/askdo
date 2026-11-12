package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
)

func TestGatewayStatusCLIContainer(t *testing.T) {
	// The real CLI uses its normal service paths. Never create them or connect
	// to them outside the explicitly enabled, disposable foreground container.
	if os.Getenv("ASKDO_FOREGROUND_CONTAINER_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opt-in disposable root container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("requires Docker container marker")
	}
	dir, path := gatewayOperatorFixture(t)
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenEnrollmentStore(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host, bearer, err := store.Create(t.Context(), gateway.EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default", DisplayName: "office-desktop"})
	if err != nil {
		t.Fatal(err)
	}
	upgrades, err := gateway.NewUpgradeStore(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	if err := upgrades.Record(t.Context(), host.HostID, fleetproto.HostStatus{
		Version: fleetproto.HostStatusVersion, Hostname: "pop-os", Release: "v1.2.3", AutoUpgrade: true, Ready: true,
		Upgrade: &fleetproto.UpgradeResult{Operation: "up_" + strings.Repeat("1", 32), Release: "v1.2.3", State: "succeeded", UpdatedAt: now.Unix()},
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := upgrades.SetTarget(t.Context(), "v1.2.4", strings.Repeat("a", 64), now, host.HostID); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(defaultGatewayConfig), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultGatewayConfig, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(defaultGatewayConfig) })
	// The daemon does not need a live Telegram connection for status. Its
	// configured token remains root-private and must not reach either client.
	token, err := os.ReadFile(cfg.Bots[0].TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "host-telegram.token")
	if err := os.WriteFile(tokenPath, token, 0640); err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroup("askdo-review")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(tokenPath, 0, gid); err != nil {
		t.Fatal(err)
	}
	hostConfig := map[string]any{
		"config_version": 4, "inspection": map[string]any{"read_roots": []string{}},
		"review": map[string]any{"mode": "approval_only", "models": []any{}}, "limits": map[string]any{},
		"telegram": map[string]any{"token_file": tokenPath, "chat_id": -100, "operator_user_id": 77},
	}
	data, err = json.Marshal(hostConfig)
	if err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(dir, "host.json")
	if err := os.WriteFile(hostPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/var/lib/askdo", 0700); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process := exec.Command("/usr/local/bin/askdo-config", "daemon", "--config", hostPath)
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat("/run/askdo/request.sock"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			output, _ := os.ReadFile(log.Name())
			t.Fatalf("broker socket did not appear: %s", output)
		}
		time.Sleep(10 * time.Millisecond)
	}
	jobs, err := sql.Open("sqlite", "file:/var/lib/askdo/jobs.sqlite3?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	// A successful socket response also proves the broker has finished startup.
	for _, args := range [][]string{{"gateway", "hosts", "list"}, {"upgrade-fleet", "--status"}} {
		for _, user := range []string{"askdo-human", "askdo-outsider"} {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			command := append([]string{"-u", user, "--", "/usr/local/bin/askdo-config"}, args...)
			out, err := exec.CommandContext(ctx, "runuser", command...).CombinedOutput()
			cancel()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("%v: %v", command, err)
				}
				code = exit.ExitCode()
			}
			t.Logf("%s %v: exit=%d output=%s", user, args, code, out)
			if user == "askdo-human" {
				if code != 0 {
					t.Fatalf("member status failed: %s", out)
				}
				for _, want := range []string{host.HostID, "enabled=true", "name=office-desktop", "release=v1.2.3", "auto_upgrade=true", "upgrade=succeeded(v1.2.3)", "seen=" + now.Local().Format(time.RFC3339)} {
					if !strings.Contains(string(out), want) {
						t.Errorf("%v missing %q: %s", args, want, out)
					}
				}
				if args[0] == "upgrade-fleet" && (!strings.Contains(string(out), "Fleet upgrade to v1.2.4: running, offered to "+host.HostID) || !strings.Contains(string(out), "rollout=upgrading")) {
					t.Errorf("missing rollout: %s", out)
				}
			} else if code != 125 || !strings.Contains(string(out), "you are not in the askdo group") || !strings.Contains(string(out), "sudo usermod -aG askdo USER") {
				t.Fatalf("nonmember lacks actionable denial: code=%d %s", code, out)
			}
			if strings.Contains(string(out), bearer) || strings.Contains(string(out), strings.TrimSpace(string(token))) || strings.Contains(string(out), tokenPath) || strings.Contains(string(out), cfg.Bots[0].TokenFile) {
				t.Fatal("status exposed credentials")
			}
			var count int
			if err := jobs.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM jobs").Scan(&count); err != nil || count != 0 {
				t.Fatalf("status created a job: count=%d err=%v", count, err)
			}
		}
	}
}
