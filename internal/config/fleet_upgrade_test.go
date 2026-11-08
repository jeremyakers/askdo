package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fleetUpgradeBase = `{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["local"]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/keys/enrollment","verification_key_file":"/keys/verify","ca_file":"/keys/ca","approval_ttl":600}%s}`

func loadFleetUpgrade(t *testing.T, extra string) (*Config, error) {
	t.Helper()
	stubFleetFiles(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(strings.Replace(fleetUpgradeBase, "%s", extra, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestFleetHostAppliesPushedUpgradesUnlessItOptsOut(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		auto        bool
	}{
		{"no section: enrolling asks for it", ``, true},
		{"empty section", `,"fleet_upgrade":{}`, true},
		{"null section", `,"fleet_upgrade":null`, true},
		{"null auto", `,"fleet_upgrade":{"auto":null}`, true},
		{"explicitly on", `,"fleet_upgrade":{"auto":true}`, true},
		{"opted out", `,"fleet_upgrade":{"auto":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadFleetUpgrade(t, tc.extra)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.FleetUpgradeAuto(); got != tc.auto {
				t.Fatalf("FleetUpgradeAuto() = %v, want %v", got, tc.auto)
			}
		})
	}
}

func TestStandaloneHostHasNoGatewayToPushUpgrades(t *testing.T) {
	// Whatever it says, a host with no gateway has nothing to apply.
	for _, cfg := range []*Config{nil, {}, {FleetUpgrade: &FleetUpgradeConfig{Auto: boolPointer(true)}}} {
		if cfg.FleetUpgradeAuto() {
			t.Fatalf("%+v applies pushed upgrades without a fleet", cfg)
		}
	}
}

func boolPointer(v bool) *bool { return &v }

// The opt-out is an administrator file key: a misspelling must stop the file
// loading, not leave a host that its owner thinks is opted out still applying
// upgrades.
func TestFleetUpgradeSectionIsStrict(t *testing.T) {
	for name, extra := range map[string]string{
		"misspelled key":     `,"fleet_upgrade":{"auot":false}`,
		"another key":        `,"fleet_upgrade":{"auto":false,"interval":"1h"}`,
		"string for boolean": `,"fleet_upgrade":{"auto":"false"}`,
		"misspelled section": `,"fleet_upgrades":{"auto":false}`,
		"array":              `,"fleet_upgrade":[]`,
	} {
		if _, err := loadFleetUpgrade(t, extra); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestFleetUpgradeOptOutSurvivesSavingAndReenrolling(t *testing.T) {
	stubFleetFiles(t)
	body := strings.Replace(fleetUpgradeBase, "%s", `,"fleet_upgrade":{"auto":false}`, 1)
	cfg, err := DecodeForFleetMutation([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	// Saving the document writes the opt-out back, and nothing is added to a
	// document that never had the section.
	saved, err := json.Marshal(cfg)
	if err != nil || !strings.Contains(string(saved), `"fleet_upgrade":{"auto":false}`) {
		t.Fatalf("saved %s, %v", saved, err)
	}
	plain, err := DecodeForFleetMutation([]byte(strings.Replace(fleetUpgradeBase, "%s", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if saved, err := json.Marshal(plain); err != nil || strings.Contains(string(saved), "fleet_upgrade") {
		t.Fatalf("saving added a section: %s, %v", saved, err)
	}
	// Enrolling the host again replaces "fleet" but not the host's own choice.
	again := cfg.WithFleet(*cfg.Fleet, []string{"local"}, false)
	if again.FleetUpgradeAuto() {
		t.Fatal("re-enrolling dropped the opt-out")
	}
}
