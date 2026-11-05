package broker

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/store"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// Fleet identity contract for UID-0 login shells (`askdo -u toor -i` on a
// host whose account database resolves the first UID-0 entry to toor): the
// broker places the resolved alias in USER/LOGNAME, the reviewer bootstrap,
// the manifest and the audit — so the signed Fleet display and the approval
// card rendered from it must carry the same account, not a silently
// normalized "root". Ordinary root and a canonical root-named login keep the
// unchanged identity, hash and card.
func TestFleetTicketBindsUIDZeroLoginAlias(t *testing.T) {
	freeze := func(t *testing.T, target ExecutionTarget, login bool) (fleetproto.Ticket, *fleetManifest) {
		t.Helper()
		j, _ := rootFleetReceiptFixture()
		db, err := store.Open(filepath.Join(t.TempDir(), "jobs.sqlite3"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		j.daemon.store = db
		j.fleet.ticket = fleetproto.Ticket{}
		j.route.ApprovalTTL = config.Duration(time.Minute)
		j.executionHost, j.submitterName = "fixture", "requester"
		j.req.Mode, j.req.Argv, j.resolvedArgv = "argv", []string{"id"}, []string{"/usr/bin/id", "-u"}
		j.req.LoginShell = login
		j.target = target
		manifest, err := j.freezeFleet(nil, nil, "administrator skipped review", nil, nil, captureIndex{})
		if err != nil {
			t.Fatal(err)
		}
		return j.fleet.ticket, manifest
	}
	// Given the identity handleSubmit binds for `askdo -u toor -i`.
	alias := ExecutionTarget{Name: "toor", Home: "/root", loginName: "toor", loginHome: "/root"}
	ticket, manifest := freeze(t, alias, true)
	identity := ticket.Display.Identity
	if identity.TargetUID != 0 || identity.TargetUser != "toor" {
		t.Fatalf("UID-0 login ticket lost the resolved alias: %+v", identity)
	}
	// Then the signed ticket and its frozen display hash bind the alias.
	// (HashDisplay enforces the display contract itself; fleetproto.Validate
	// on the whole ticket additionally requires the ManifestDigest that
	// runFleetTicket assigns after this freeze point.)
	hash, err := fleetproto.HashDisplay(ticket.Display)
	if err != nil || hash != manifest.DisplayHash || hash != ticket.Binding.DisplayHash {
		t.Fatalf("display hash %s manifest %s ticket %s (%v)", hash, manifest.DisplayHash, ticket.Binding.DisplayHash, err)
	}
	// The aliased display is a complete ticket the gateway contract accepts
	// once the freeze-point manifest digest is bound (runFleetTicket assigns
	// it in production; the fixture starts from an empty ticket).
	completed := ticket
	completed.Binding.ManifestDigest = fleetproto.Hash(strings.Repeat("a", 64))
	if err := fleetproto.Validate(completed); err != nil {
		t.Fatalf("UID-0 login alias ticket failed validation: %v", err)
	}
	// An aliased display is distinct data: another alias changes the hash,
	// and dropping the marker violates the contract outright (an unmarked
	// UID-0 name stays the rejected half-identity it always was).
	renamed := ticket.Display
	renamed.Identity.TargetUser = "admin0"
	if renamedHash, err := fleetproto.HashDisplay(renamed); err != nil || renamedHash == hash {
		t.Fatalf("display hash does not bind the resolved login alias: %v", err)
	}
	unmarked := ticket.Display
	unmarked.Identity.TargetLogin = false
	if _, err := fleetproto.HashDisplay(unmarked); err == nil {
		t.Fatal("a UID-0 login alias that drops its marker passed validation")
	}
	// And the fleet card shows the account the reviewer bootstrap, manifest,
	// USER/LOGNAME and audit carry — the approver never sees a bare root.
	rendered, err := telegram.RenderFleet(ticket)
	if err != nil || !strings.Contains(rendered.Final, "requester → toor (uid 0)") || strings.Contains(rendered.Final, "→ root") {
		t.Fatalf("fleet card identity: final=%s (%v)", rendered.Final, err)
	}
	if !strings.Contains(strings.Join(rendered.Details, ""), "<code>toor</code> (uid 0)") {
		t.Fatalf("fleet details identity: %s", strings.Join(rendered.Details, ""))
	}
	// Control: ordinary root (no login shell) keeps the canonical identity,
	// renders "root", and its display still validates without target fields.
	rootTicket, rootManifest := freeze(t, ExecutionTarget{}, false)
	if rootTicket.Display.Identity.TargetUID != 0 || rootTicket.Display.Identity.TargetUser != "" || rootTicket.Display.Identity.TargetLogin {
		t.Fatalf("ordinary root ticket identity changed: %+v", rootTicket.Display.Identity)
	}
	rootCompleted := rootTicket
	rootCompleted.Binding.ManifestDigest = fleetproto.Hash(strings.Repeat("a", 64))
	if err := fleetproto.Validate(rootCompleted); err != nil {
		t.Fatalf("ordinary root ticket: %v", err)
	}
	if rootManifest.DisplayHash == manifest.DisplayHash {
		t.Fatal("login alias display hash collides with ordinary root")
	}
	rootRendered, err := telegram.RenderFleet(rootTicket)
	if err != nil || !strings.Contains(rootRendered.Final, "requester → root") {
		t.Fatalf("ordinary root card changed: final=%s (%v)", rootRendered.Final, err)
	}
	// The canonical name needs no alias marker: a root login under the
	// account's real name "root" keeps the unchanged plain-root identity.
	bareLogin, _ := freeze(t, ExecutionTarget{Name: "root", Home: "/root", loginName: "root", loginHome: "/root"}, true)
	if bareLogin.Display.Identity.TargetUID != 0 || bareLogin.Display.Identity.TargetUser != "" || bareLogin.Display.Identity.TargetLogin {
		t.Fatalf("canonical root login identity changed: %+v", bareLogin.Display.Identity)
	}
}
