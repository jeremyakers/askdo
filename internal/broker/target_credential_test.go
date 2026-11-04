package broker

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestTargetCredentialManifestsBindCanonicalGroupsAndGID(t *testing.T) {
	for _, approvalOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("approval-only=%t", approvalOnly), func(t *testing.T) {
			h := newBrokerHarness(t, nil, nil)
			base, ctx := newFreezeTestJob(t, h)
			freeze := func(target ExecutionTarget) (map[string]json.RawMessage, string) {
				t.Helper()
				j, _ := newFreezeTestJob(t, h)
				j.req.RequestID, j.req.CWD, j.cwd = base.req.RequestID, base.req.CWD, base.cwd
				j.target = target
				var digest string
				var err error
				if approvalOnly {
					digest, err = j.freezeApprovalOnly(ctx, "policy", nil)
				} else {
					_, digest, err = j.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{}))
				}
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := os.ReadFile(j.spool.approval)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &fields); err != nil {
					t.Fatal(err)
				}
				return fields, digest
			}
			target := ExecutionTarget{UID: 1001, GID: 0, Groups: []uint32{88, 0, 17, 17}, Name: "target", Home: "/home/target"}
			fields, digest := freeze(target)
			if string(fields["target_gid"]) != "0" || string(fields["target_groups"]) != "[0,17,88]" {
				t.Errorf("credential missing or not canonical: %s", mustJSON(t, fields))
			}
			target.Groups = []uint32{17, 88, 0}
			if _, alias := freeze(target); alias != digest {
				t.Error("group order/duplicates changed approval digest")
			}
			target.GID = 17
			if _, changed := freeze(target); changed == digest {
				t.Error("primary GID is not authenticated")
			}
			target.GID, target.Groups = 0, []uint32{0, 17}
			if _, changed := freeze(target); changed == digest {
				t.Error("supplementary groups are not authenticated")
			}
			root, _ := freeze(ExecutionTarget{})
			if root["target_gid"] != nil || root["target_groups"] != nil {
				t.Errorf("root manifest acquired credential fields: %s", mustJSON(t, root))
			}
		})
	}
}

func TestTargetCredentialBootstrapProjectsNumbersAndResolvableNames(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	j, _ := newFreezeTestJob(t, h)
	j.target = ExecutionTarget{UID: 1001, GID: 0, Groups: []uint32{17, 0, 17}, Name: "target", Home: "/home/target"}
	boot := j.bootstrap()
	encoded, _ := json.Marshal(boot)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &fields)
	if string(fields["target_gid"]) != "0" || string(fields["target_groups"]) != "[0,17]" {
		t.Errorf("bootstrap lacks canonical credential: %s", encoded)
	}
	var names map[string]string
	_ = json.Unmarshal(fields["target_group_names"], &names)
	if group, err := user.LookupGroupId("0"); err == nil && names["0"] != group.Name {
		t.Errorf("resolved group name missing: %s", encoded)
	}
	if !slices.Equal(j.operation().Target.Groups, []uint32{0, 17}) {
		t.Errorf("installed groups differ from canonical approval: %+v", j.operation().Target)
	}
	if err := proto.ValidateWorkerMessage(&boot, proto.BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	j.target = ExecutionTarget{}
	encoded, _ = json.Marshal(j.bootstrap())
	for _, field := range []string{"target_gid", "target_groups", "target_group_names"} {
		if strings.Contains(string(encoded), `"`+field+`"`) {
			t.Errorf("root bootstrap acquired %s", field)
		}
	}
}

func TestTargetCredentialTimestampAuthority(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	j, _ := newFreezeTestJob(t, h)
	// The exact pre-change root payload must continue to identify root windows.
	rootPayload := struct {
		Route     any      `json:"route"`
		Fleet     any      `json:"fleet,omitempty"`
		Operator  int64    `json:"operator_user_id"`
		Profiles  []string `json:"profiles,omitempty"`
		TargetUID uint32   `json:"target_uid"`
	}{Route: j.route, Operator: j.configuration().Telegram.OperatorUserID, Profiles: j.configuration().Review.GatewayProfiles}
	if j.configuration().Fleet != nil {
		rootPayload.Fleet = j.configuration().Fleet
	}
	encoded, _ := json.Marshal(rootPayload)
	if got, want := j.approvalAuthorityHash(), fmt.Sprintf("%x", sha256.Sum256(encoded)); got != want {
		t.Fatalf("root authority changed: %s != %s", got, want)
	}
	j.target = ExecutionTarget{UID: 1001, GID: 17, Groups: []uint32{88, 17, 17}, Name: "first"}
	hash := j.approvalAuthorityHash()
	j.target.Name, j.target.Groups = "alias", []uint32{17, 88}
	if j.approvalAuthorityHash() != hash {
		t.Error("same credential aliases must share a window")
	}
	j.target.GID = 88
	if j.approvalAuthorityHash() == hash {
		t.Error("different primary GID reused approval authority")
	}
	j.target.GID, j.target.Groups = 17, []uint32{17, 99}
	if j.approvalAuthorityHash() == hash {
		t.Error("same-UID alias with different groups reused approval authority")
	}
}
