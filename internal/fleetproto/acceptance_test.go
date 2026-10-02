package fleetproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestCanonicalJobIDsAcrossFleetMessages(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"2026-09-28_#1", "2024-02-29_#9223372036854775807", "job1", "job_7", "2026-02-29_#1", "2026-09-28_#0", "2026-09-28_#01", "2026-09-28_#+1", "2026-09-28_#9223372036854775808", "../2026-09-28_#1"} {
		t.Run(id, func(t *testing.T) {
			valid := id == "2026-09-28_#1" || id == "2024-02-29_#9223372036854775807"
			ticket, _, _ := fixture(t)
			ticket.Binding.JobID = ID(id)
			event := Event{Version: Version, Kind: KindEvent, HostID: "host1", JobID: ID(id), Sequence: 1, Type: EventFailed, Failure: &Failure{Code: ErrCodeDelivery}}
			turn := ModelTurn{Version: Version, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: ID(id), Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalogFixture(t).Profiles[0].Revision, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "review"}}, Tools: []modelwire.ToolDefinition{{Name: "submit_review", Description: "Submit", Schema: json.RawMessage(`{"type":"object"}`)}}}}
			if err := Validate(ticket); (err == nil) != valid {
				t.Errorf("Ticket job ID validity=%v: %v", valid, err)
			}
			if err := Validate(event); (err == nil) != valid {
				t.Errorf("Event job ID validity=%v: %v", valid, err)
			}
			if err := Validate(turn); (err == nil) != valid {
				t.Errorf("Turn job ID validity=%v: %v", valid, err)
			}
			if valid {
				wire, err := Sign(private, ticket)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := Verify[Ticket](public, wire); err != nil {
					t.Fatal(err)
				}
				wire, err = Sign(private, event)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := Verify[Event](public, wire); err != nil {
					t.Fatal(err)
				}
				wire, err = Sign(private, turn)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := Verify[ModelTurn](public, wire); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if _, err := ParseID("2026-09-28_#1"); err == nil {
		t.Fatal("canonical job grammar broadened non-job identity")
	}
}

func TestCatalogCapacitySeparateFromSelectedProfileLimit(t *testing.T) {
	if MaxProfiles != 16 || MaxCatalogProfiles != 128 {
		t.Fatal("published profile limits changed")
	}
	c := catalogFixture(t)
	profiles := make([]ProfileMetadata, 129)
	for i := range profiles {
		p := c.Profiles[0]
		p.ProfileID = ID(fmt.Sprintf("profile-%d", i))
		var err error
		p.Revision, err = HashProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		profiles[i] = p
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{16, 17, 128, 129} {
		c.Profiles = profiles[:count]
		if err := Validate(c); (err == nil) != (count <= 128) {
			t.Errorf("catalog count %d: %v", count, err)
		}
		if _, err := HashProfiles(c.Profiles); (err == nil) != (count <= 16) {
			t.Errorf("selection count %d: %v", count, err)
		}
		if count <= 128 {
			wire, err := Sign(private, c)
			if err != nil {
				t.Errorf("sign count %d: %v", count, err)
				continue
			}
			got, _, err := Verify[Catalog](public, wire)
			if err != nil || !reflect.DeepEqual(got, c) {
				t.Fatalf("catalog count %d roundtrip: %v", count, err)
			}
		}
	}
}

func TestWholeSecondMetadataDurationBoundaries(t *testing.T) {
	const maximum = int64((1<<63 - 1) / time.Second)
	if MaxDurationSeconds != maximum {
		t.Fatal("published duration limit changed")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []int64{1, 7201, 10800, maximum, maximum + 1, 0, -1} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			c := catalogFixture(t)
			p := c.Profiles[0]
			p.Upstreams = append([]Upstream(nil), p.Upstreams...)
			p.Upstreams[0].RequestTimeoutSeconds = seconds
			r := c.Route
			r.TTLSeconds = seconds
			valid := seconds > 0 && seconds <= maximum
			ph, pe := HashProfile(p)
			rh, re := HashRoute(r)
			if (pe == nil) != valid {
				t.Errorf("request seconds %d: %v", seconds, pe)
			}
			if (re == nil) != valid {
				t.Errorf("route seconds %d: %v", seconds, re)
			}
			if !valid {
				return
			}
			p.Revision = ph
			r.Revision = rh
			wire, err := Sign(private, p)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := Verify[ProfileMetadata](public, wire)
			if err != nil || !reflect.DeepEqual(got, p) {
				t.Fatalf("profile roundtrip: %v", err)
			}
			wire, err = Sign(private, r)
			if err != nil {
				t.Fatal(err)
			}
			gotRoute, _, err := Verify[RouteSnapshot](public, wire)
			if err != nil || !reflect.DeepEqual(gotRoute, r) {
				t.Fatalf("route roundtrip: %v", err)
			}
		})
	}
}
