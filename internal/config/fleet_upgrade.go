package config

// FleetUpgradeConfig is a fleet host's own say in the upgrades its gateway
// pushes. It lives beside "fleet", not inside it, so enrolling the host again
// does not discard it.
type FleetUpgradeConfig struct {
	// Auto says whether this host upgrades itself when its gateway's target
	// release is newer than the one it runs. Absent means yes; false opts the
	// host out, and the gateway then never offers it an upgrade.
	Auto *bool `json:"auto,omitempty"`
}

// FleetUpgradeAuto reports whether this host applies the upgrades its gateway
// pushes: it is enrolled in a gateway and has not opted out. A host with no
// "fleet_upgrade" section applies them, because enrolling in a gateway that
// can name a release is how an operator asks for that.
func (c *Config) FleetUpgradeAuto() bool {
	if c == nil || c.Fleet == nil {
		return false
	}
	return c.FleetUpgrade == nil || c.FleetUpgrade.Auto == nil || *c.FleetUpgrade.Auto
}
