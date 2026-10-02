package broker

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func TestFreezeFleetProjectsSubmitterFacts(t *testing.T) {
	for _, mode := range []string{"argv", "bundle", "captured"} {
		t.Run(mode, func(t *testing.T) {
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
			j.req.Reason, j.req.CWD = "purpose for "+mode+" <canary>", "/work/"+mode
			j.req.Mode, j.req.Argv = "argv", []string{"true"}
			j.resolvedArgv = []string{"/usr/bin/true", "literal $HOME; `id`", "line\nnext"}
			want := "/usr/bin/true 'literal $HOME; `id`' $'line\\x0anext'"
			var captured int64
			if mode == "bundle" {
				j.req.Mode, j.req.Entry, j.req.Args = "bundle", "run.sh", []string{"literal $HOME"}
				j.spool.bundle = "/root/private/spool/bundle"
				want = "/bin/bash --noprofile --norc bundle:run.sh 'literal $HOME'"
			}
			if mode == "captured" {
				body := "echo private-script-canary\n"
				captured = int64(len(body))
				j.req.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte(body))
			}
			manifest, err := j.freezeFleet(nil, nil, "administrator skipped review", nil, nil, captureIndex{})
			if err != nil {
				t.Fatal(err)
			}
			d := j.fleet.ticket.Display
			if d.Operation != want {
				t.Fatalf("command contains metadata or loses literal argv: %q", d.Operation)
			}
			if d.Reason != j.req.Reason || d.CWD != j.req.CWD || d.CapturedStdinBytes != captured || d.UnreviewedReason != "administrator skipped review" {
				t.Fatalf("wrong frozen facts: %+v", d)
			}
			if strings.Contains(d.Operation, "private") {
				t.Fatal("command leaks root spool or script body")
			}
			hash, err := fleetproto.HashDisplay(d)
			if err != nil || hash != manifest.DisplayHash {
				t.Fatal("facts not bound by manifest")
			}
			rendered, err := telegram.RenderFleet(j.fleet.ticket)
			if err != nil || len(rendered.Parts) != d.SummaryParts {
				t.Fatal("wrong frozen delivery count")
			}
			j.fleet.ticket.Binding.ManifestDigest = fleetproto.Hash(strings.Repeat("a", 64))
			if err := fleetproto.CheckTicket(j.fleet.ticket, j.fleet.selection.Profiles, j.fleet.selection.Catalog.Route); err != nil {
				t.Fatal(err)
			}
			if _, err := j.freezeFleet((*proto.ReviewReport)(nil), nil, "policy", nil, nil, captureIndex{}); err == nil {
				t.Fatal("rewrote frozen ticket")
			}
		})
	}
}
