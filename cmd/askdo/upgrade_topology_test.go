package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/upgrade"
)

func TestUpgradeTopologyRejectsStandaloneGatewayBeforeSchedulingEffects(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsupported", true: "enrolled"}[enrolled], func(t *testing.T) {
			// Given: actual read-only topology validation and verified source fixtures.
			layout, _ := upgradeVerifyConfig(t, enrolled, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
			root, source := t.TempDir(), t.TempDir()
			raw, assets := cliReleaseFixture("v3.2.1")
			assets["install-manifest.v1"] = []byte(raw)
			for name, data := range assets {
				if err := os.WriteFile(filepath.Join(source, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			manifest, err := upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := upgrade.NewPlan(cliUpgradeID, manifest)
			if err != nil {
				t.Fatal(err)
			}
			captured, _ := json.Marshal(plan)
			managerCalls := 0
			helper := upgrade.Helper{BackupRoot: filepath.Join(root, "backups"), ReceiptRoot: filepath.Join(root, "receipts"), Preflight: func(context.Context) error {
				return preflightUpgradeTopology(layout.Config, layout.GatewayConfig)
			}, Manager: upgradeScheduleManagerFunc(func(context.Context, string, string) error { managerCalls++; return nil }), TrustDirectory: func(path string, create bool) error {
				if create {
					return os.MkdirAll(path, 0o755)
				}
				_, err := os.Stat(path)
				return err
			}}
			var stderr bytes.Buffer
			// When
			code := runUpgradeHelperWith(t.Context(), []string{"--operation", cliUpgradeID, "--source", source}, 0, func() upgrade.Helper { return helper }, bytes.NewReader(captured), io.Discard, &stderr)
			// Then: unsupported topology creates no stage, receipt, manager, stop or install effects.
			if !enrolled {
				if code != 1 || managerCalls != 0 || !strings.Contains(stderr.String(), "local fleet enrollment") {
					t.Fatalf("unsupported topology: code=%d manager=%d stderr=%s", code, managerCalls, &stderr)
				}
				for _, path := range []string{helper.BackupRoot, helper.ReceiptRoot} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("preflight produced state at %s: %v", path, err)
					}
				}
			} else if code != 0 || managerCalls != 1 {
				t.Fatalf("enrolled topology changed: code=%d manager=%d stderr=%s", code, managerCalls, &stderr)
			}
		})
	}
}

func TestUpgradeTopologyAllowsStandaloneBrokerWithoutGateway(t *testing.T) {
	layout, _ := upgradeVerifyConfig(t, false, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err := preflightUpgradeTopology(layout.Config, filepath.Join(t.TempDir(), "no-gateway.json")); err != nil {
		t.Fatal("standalone broker rejected:", err)
	}
}
