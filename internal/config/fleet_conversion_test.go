package config

import (
	"testing"
)

func TestWithFleetRetainsInspectionPresenceAndDoesNotMutateOriginal(t *testing.T) {
	for _, masks := range []string{"[]", "null"} {
		data := []byte(`{"config_version":4,"inspection":{"read_roots":[],"sensitive_masks":` + masks + `},"review":{"mode":"approval_only","models":[]},"limits":{},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`)
		cfg, err := DecodeForFleetMutation(data)
		if err != nil {
			t.Fatal(err)
		}
		next := cfg.WithFleet(FleetConfig{URL: "https://gateway.example", HostID: "host_test", ApprovalTTL: 600}, []string{}, false)
		if err = next.ValidateInspection(); err == nil {
			t.Fatalf("conversion erased invalid mask presence: %s", masks)
		}
		if !hasField(cfg.present.top, "telegram") || !hasField(cfg.present.review, "models") || cfg.ConfigVersion != 4 {
			t.Fatal("conversion mutated original presence maps")
		}
		if hasField(next.present.top, "telegram") || hasField(next.present.review, "models") || !hasField(next.present.review, "gateway_profiles") {
			t.Fatal("converted presence retained direct fields or omitted fleet selection")
		}
	}
}
