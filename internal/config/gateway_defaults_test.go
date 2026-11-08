package config

import (
	"errors"
	"os/user"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// stubAccounts presents a small account database: "alice" and her alias
// "alicia" are UID 1001, "bob" is 1002 and "carol" 1003; the groups "ops" (GID
// 700) and "dev" (GID 701) exist. Any other name is not an account here.
func stubAccounts(t *testing.T) {
	t.Helper()
	oldUser, oldGroup := lookupUser, lookupGroup
	t.Cleanup(func() { lookupUser, lookupGroup = oldUser, oldGroup })
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "alice", "alicia":
			return &user.User{Username: name, Uid: "1001"}, nil
		case "bob":
			return &user.User{Username: name, Uid: "1002"}, nil
		case "carol":
			return &user.User{Username: name, Uid: "1003"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	lookupGroup = func(name string) (*user.Group, error) {
		switch name {
		case "ops":
			return &user.Group{Name: name, Gid: "700"}, nil
		case "dev":
			return &user.Group{Name: name, Gid: "701"}, nil
		}
		return nil, user.UnknownGroupError(name)
	}
}

// hostReview is a resolved host policy, as Load builds one: required-mode review
// with the given exemptions, timestamp windows (seconds) and grants.
func hostReview(t *testing.T, exempt []string, timestamps map[string]int, grants []AutoApproveGrant) ReviewConfig {
	t.Helper()
	review := ReviewConfig{
		Mode: "required", GatewayProfiles: []string{"gw"}, ApprovalOnlyUsers: exempt,
		ApprovalTimestampUsers: timestamps, AutoApproveGrants: grants,
		RequestTimeout: Duration(time.Minute), TotalTimeout: Duration(time.Minute), MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1,
	}
	for _, resolve := range []func() error{review.ResolveApprovalOnlyUsers, review.ResolveApprovalTimestampUsers, review.ResolveAutoApproveGrants, review.ResolveAccountNotes} {
		if err := resolve(); err != nil {
			t.Fatal(err)
		}
	}
	return review
}

func TestGatewayDefaultsExemptionPrecedence(t *testing.T) {
	stubAccounts(t)
	for _, tc := range []struct {
		name    string
		host    []string
		gateway []string
		uid     uint32
		want    PolicySource
	}{
		{"neither", nil, nil, 1001, SourceNone},
		{"gateway only", nil, []string{"alice"}, 1001, SourceGateway},
		{"host only", []string{"alice"}, nil, 1001, SourceHost},
		{"both name the login: the host's own entry is the source", []string{"alice"}, []string{"alice"}, 1001, SourceHost},
		{"the gateway never exempts another login", nil, []string{"alice"}, 1002, SourceNone},
		{"host exempts another login, gateway the caller", []string{"bob"}, []string{"alice"}, 1001, SourceGateway},
		{"a name with no account here is ignored", nil, []string{"nobody-here"}, 1001, SourceNone},
		{"an alias of the login exempts it", nil, []string{"alicia"}, 1001, SourceGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := hostReview(t, tc.host, nil, nil)
			review := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{ApprovalOnlyUsers: tc.gateway})
			if got := review.ExemptionSource(tc.uid); got != tc.want {
				t.Fatalf("source=%q want %q", got, tc.want)
			}
			if got, want := review.RequiresReview(tc.uid, false), tc.want == SourceNone; got != want {
				t.Fatalf("RequiresReview=%v want %v", got, want)
			}
			// --review=yes still adds a review for an exempt login.
			if !review.RequiresReview(tc.uid, true) {
				t.Fatal("forced review bypassed by a gateway exemption")
			}
		})
	}
	t.Run("global host approval-only wins over everything", func(t *testing.T) {
		host := hostReview(t, nil, nil, nil)
		host.Mode = "approval_only"
		review := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{})
		if review.ExemptionSource(1002) != SourceHost || review.RequiresReview(1002, false) {
			t.Fatal("global approval-only not reported as the host's")
		}
	})
}

func TestGatewayDefaultsTimestampPrecedence(t *testing.T) {
	stubAccounts(t)
	minute := func(n int) []fleetproto.UserTimestampTimeout {
		return []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: n * 60}}
	}
	for _, tc := range []struct {
		name    string
		host    map[string]int
		gateway []fleetproto.UserTimestampTimeout
		want    time.Duration
		source  PolicySource
	}{
		{"neither", nil, nil, 0, SourceNone},
		{"gateway only", nil, minute(10), 10 * time.Minute, SourceGateway},
		{"host only", map[string]int{"alice": 300}, nil, 5 * time.Minute, SourceHost},
		{"host wins over a longer gateway window", map[string]int{"alice": 300}, minute(30), 5 * time.Minute, SourceHost},
		{"host wins over a shorter gateway window", map[string]int{"alice": 600}, minute(1), 10 * time.Minute, SourceHost},
		{"host entry for another login leaves this one to the gateway", map[string]int{"bob": 300}, minute(10), 10 * time.Minute, SourceGateway},
		{"unknown name ignored", nil, []fleetproto.UserTimestampTimeout{{User: "nobody-here", Seconds: 600}}, 0, SourceNone},
		{"alias names: the shorter window applies", nil, []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 600}, {User: "alicia", Seconds: 120}}, 2 * time.Minute, SourceGateway},
		// The limits a host puts on its own setting hold for a default too.
		{"below 30s ignored", nil, []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 29}}, 0, SourceNone},
		{"above 1h ignored", nil, []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 3601}}, 0, SourceNone},
		{"30s accepted", nil, []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 30}}, 30 * time.Second, SourceGateway},
		{"1h accepted", nil, []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 3600}}, time.Hour, SourceGateway},
		{"entry without seconds ignored", nil, []fleetproto.UserTimestampTimeout{{User: "alice"}}, 0, SourceNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := hostReview(t, nil, tc.host, nil)
			review := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{TimestampTimeouts: tc.gateway})
			if got := review.TimestampTimeout(1001); got != tc.want {
				t.Fatalf("timeout=%v want %v", got, tc.want)
			}
			if got := review.TimestampSource(1001); got != tc.source {
				t.Fatalf("source=%q want %q", got, tc.source)
			}
		})
	}
}

func TestGatewayDefaultsAutoApprovalIsTheLowerOfTheTwo(t *testing.T) {
	stubAccounts(t)
	grant := func(user string, risk int) []AutoApproveGrant { return []AutoApproveGrant{{User: user, MaxRisk: risk}} }
	gateway := func(user string, risk int) []fleetproto.UserAutoApproveGrant {
		return []fleetproto.UserAutoApproveGrant{{User: user, MaxRisk: risk}}
	}
	for _, tc := range []struct {
		name    string
		host    []AutoApproveGrant
		gateway []fleetproto.UserAutoApproveGrant
		want    int
		source  PolicySource
	}{
		{"neither", nil, nil, 0, SourceNone},
		{"gateway only: a host with no grant gets the gateway's", nil, gateway("alice", 3), 3, SourceGateway},
		{"host only", grant("alice", 2), nil, 2, SourceHost},
		{"host lowers", grant("alice", 1), gateway("alice", 3), 1, SourceBoth},
		{"host cannot raise", grant("alice", 4), gateway("alice", 2), 2, SourceBoth},
		{"equal", grant("alice", 2), gateway("alice", 2), 2, SourceBoth},
		{"host zero turns the gateway grant off", grant("alice", 0), gateway("alice", 4), 0, SourceBoth},
		{"host grant for another login does not touch this one", grant("bob", 1), gateway("alice", 3), 3, SourceGateway},
		{"unknown name ignored", nil, gateway("nobody-here", 3), 0, SourceNone},
		{"alias names: the lower grant applies", nil, []fleetproto.UserAutoApproveGrant{{User: "alice", MaxRisk: 4}, {User: "alicia", MaxRisk: 1}}, 1, SourceGateway},
		// Risk 5 is never auto-approved, and 0 is no grant at all.
		{"risk 5 ignored", nil, gateway("alice", 5), 0, SourceNone},
		{"risk 0 ignored", nil, gateway("alice", 0), 0, SourceNone},
		{"negative risk ignored", nil, gateway("alice", -1), 0, SourceNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := hostReview(t, nil, nil, tc.host)
			review := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{AutoApproveGrants: tc.gateway})
			if got := review.MaxAutoRisk(1001); got != tc.want {
				t.Fatalf("cap=%d want %d", got, tc.want)
			}
			if got := review.AutoApprovalSource(1001); got != tc.source {
				t.Fatalf("source=%q want %q", got, tc.source)
			}
		})
	}
}

// With no gateway defaults the host's own policy is exactly what it was, and
// merging never changes the host configuration other reviews share.
func TestGatewayDefaultsLeaveTheHostPolicyUntouched(t *testing.T) {
	stubAccounts(t)
	host := hostReview(t, []string{"bob"}, map[string]int{"carol": 90}, []AutoApproveGrant{{User: "alice", MaxRisk: 2}})
	for _, none := range []*fleetproto.ReviewDefaults{nil, {}} {
		review := host.WithGatewayDefaults(none)
		for uid, want := range map[uint32]struct {
			review  bool
			timeout time.Duration
			cap     int
		}{1001: {true, 0, 2}, 1002: {false, 0, 0}, 1003: {true, 90 * time.Second, 0}} {
			if review.RequiresReview(uid, false) != want.review || review.TimestampTimeout(uid) != want.timeout || review.MaxAutoRisk(uid) != want.cap {
				t.Fatalf("uid %d: host policy changed by %+v", uid, none)
			}
		}
	}
	before := host
	merged := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{ApprovalOnlyUsers: []string{"alice"}, AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: "bob", MaxRisk: 4}}})
	if merged.gateway == nil || host.gateway != nil || !reflect.DeepEqual(before, host) {
		t.Fatal("WithGatewayDefaults modified the host policy it was called on")
	}
	if host.RequiresReview(1001, false) != true || host.MaxAutoRisk(1002) != 0 {
		t.Fatal("host policy picked up gateway defaults")
	}
	// A second merge starts again from the host: defaults never stack.
	again := merged.WithGatewayDefaults(nil)
	if again.RequiresReview(1001, false) != true {
		t.Fatal("a merge was not replaced by the next one")
	}
}

func TestGatewayDefaultsAccountNotes(t *testing.T) {
	stubAccounts(t)
	host := hostReview(t, nil, nil, nil)
	review := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{
		RiskPolicy: "gateway guidance\n",
		AccountNotes: &fleetproto.AccountNotes{
			// Deliberately out of order: the order a gateway lists notes in is not an authority.
			Users:  []fleetproto.AccountNote{{Name: "bob", Text: "bob note"}, {Name: "alicia", Text: "alicia note"}, {Name: "alice", Text: "alice note"}, {Name: "nobody-here", Text: "ignored"}, {Name: "carol", Text: ""}},
			Groups: []fleetproto.AccountNote{{Name: "ops", Text: "ops note"}, {Name: "dev", Text: "dev note"}, {Name: "ghosts", Text: "ignored"}},
		},
	})
	if text, ok := review.GatewayRiskPolicy(); !ok || text != "gateway guidance\n" {
		t.Fatalf("risk policy %q %v", text, ok)
	}
	if _, ok := host.GatewayRiskPolicy(); ok {
		t.Fatal("host policy reports a gateway risk policy")
	}
	names := func(notes []GatewayNote) (out []string) {
		for _, note := range notes {
			out = append(out, note.Name+":"+note.Text)
		}
		return
	}
	if got := names(review.GatewayUserNotes(1001)); !reflect.DeepEqual(got, []string{"alice:alice note", "alicia:alicia note"}) {
		t.Fatalf("user notes %v", got)
	}
	if got := names(review.GatewayUserNotes(1003)); got != nil {
		t.Fatalf("an empty note was kept: %v", got)
	}
	if got := names(review.GatewayUserNotes(4242)); got != nil {
		t.Fatalf("notes for a UID nobody named: %v", got)
	}
	if !review.HasGatewayGroupNotes() || host.HasGatewayGroupNotes() {
		t.Fatal("HasGatewayGroupNotes disagrees with the defaults")
	}
	if got := names(review.GatewayGroupNotes([]uint32{701, 700, 701, 999})); !reflect.DeepEqual(got, []string{"dev:dev note", "ops:ops note"}) {
		t.Fatalf("group notes %v: want each applicable note once, in group-name order", got)
	}
	if got := names(review.GatewayGroupNotes([]uint32{999})); got != nil {
		t.Fatalf("group notes for a group the submitter is not in: %v", got)
	}
	// Notes are returned as copies: a caller cannot reorder the frozen policy.
	notes := review.GatewayUserNotes(1001)
	notes[0].Text = "changed"
	if review.GatewayUserNotes(1001)[0].Text != "alice note" {
		t.Fatal("GatewayUserNotes exposed the frozen policy")
	}
}

// A host's explicit zero grant is the way to turn a gateway grant off on one
// host; zero is no grant anywhere else, and risk 5 stays invalid.
func TestHostGrantOfZeroIsValidAndGrantsNothing(t *testing.T) {
	stubAccounts(t)
	review := ReviewConfig{Mode: "required", GatewayProfiles: []string{"gw"}, AutoApproveGrants: []AutoApproveGrant{{User: "alice", MaxRisk: 0}}, RequestTimeout: Duration(time.Minute), TotalTimeout: Duration(time.Minute), MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}
	if err := review.ResolveAutoApproveGrants(); err != nil {
		t.Fatalf("explicit zero grant rejected: %v", err)
	}
	if got := review.MaxAutoRisk(1001); got != 0 {
		t.Fatalf("a zero grant grants %d", got)
	}
	for _, bad := range []int{-1, 5} {
		review.AutoApproveGrants = []AutoApproveGrant{{User: "alice", MaxRisk: bad}}
		review.autoResolved = false
		if err := review.ResolveAutoApproveGrants(); err == nil {
			t.Fatalf("max_risk %d accepted", bad)
		}
	}
}

func TestGatewayDefaultsDoNotAddRejectionPaths(t *testing.T) {
	// Account lookups that fail in any way are "not an account here", never an
	// error and never a panic: a gateway cannot make a host's review fail by
	// naming someone.
	stubAccounts(t)
	lookupUser = func(string) (*user.User, error) { return nil, errors.New("account database unavailable") }
	lookupGroup = func(string) (*user.Group, error) { return nil, errors.New("account database unavailable") }
	host := ReviewConfig{Mode: "required", GatewayProfiles: []string{"gw"}}
	review := host.WithGatewayDefaults(&fleetproto.ReviewDefaults{
		ApprovalOnlyUsers: []string{"alice"}, TimestampTimeouts: []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 60}},
		AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: "alice", MaxRisk: 2}},
		AccountNotes:      &fleetproto.AccountNotes{Users: []fleetproto.AccountNote{{Name: "alice", Text: "n"}}, Groups: []fleetproto.AccountNote{{Name: "ops", Text: "n"}}},
	})
	if !review.RequiresReview(1001, false) || review.TimestampTimeout(1001) != 0 || review.MaxAutoRisk(1001) != 0 || review.GatewayUserNotes(1001) != nil || review.HasGatewayGroupNotes() {
		t.Fatal("an unresolvable name changed the policy")
	}
}
