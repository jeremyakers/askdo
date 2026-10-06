package broker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"testing"
)

func TestRootReviewerExecutionGroup(t *testing.T) {
	requireRootTest(t)
	if os.Getenv("ASKDO_REVIEWER_GROUP_FIXTURE") != "1" {
		t.Skip("requires disposable mismatch fixture")
	}
	account, err := user.Lookup("askdo-review")
	if err != nil {
		t.Fatal(err)
	}
	if account.Uid != "2007" || account.Gid != "100" {
		t.Fatalf("wrong named fixture: %+v", account)
	}
	groups, err := account.GroupIds()
	if err != nil || !strings.Contains(","+strings.Join(groups, ",")+",", ",995,") {
		t.Fatalf("fixture must have reviewer secondary NSS membership: %v err=%v", groups, err)
	}
	uid, gid, err := resolveReviewCredentials(0, 0)
	if err != nil || uid != 2007 || gid != 995 {
		t.Fatalf("default reviewer uid=%d gid=%d err=%v", uid, gid, err)
	}
	listener, err := net.Listen("unix", "/fixture/request.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chown("/fixture/request.sock", 0, 996); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod("/fixture/request.sock", 0660); err != nil {
		t.Fatal(err)
	}
	worker := &processWorker{binary: "/artifacts/identity-probe", home: "/fixture", uid: uid, gid: gid}
	session, err := worker.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	data, err := io.ReadAll(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status                    map[string]string
		Credential, Broad, Socket bool
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("probe=%s err=%v", data, err)
	}
	for key, want := range map[string]string{"Uid": "2007 2007 2007 2007", "Gid": "995 995 995 995", "Groups": "", "CapEff": "0000000000000000", "CapPrm": "0000000000000000"} {
		if strings.Join(strings.Fields(got.Status[key]), " ") != want {
			t.Fatalf("%s=%q want=%q", key, got.Status[key], want)
		}
	}
	if !got.Credential || got.Broad || got.Socket {
		t.Fatalf("wrong DAC access: %s", data)
	}
	t.Logf("worker named mismatch identity and DAC: %s", data)
	// A submitting client may reach the request socket, not the secret.
	client := exec.Command("/artifacts/identity-probe")
	client.Env = []string{"HOME=/fixture"}
	client.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 2008, Gid: 100, Groups: []uint32{996}}}
	data, err = client.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Credential || !got.Broad || !got.Socket {
		t.Fatalf("client crossed credential boundary: %s", data)
	}
	t.Logf("client DAC: %s", data)
}

func TestReviewCredentialTestOverrideUnchanged(t *testing.T) {
	for _, pair := range [][2]uint32{{7, 995}, {7, 0}, {0, 995}} {
		uid, gid, err := resolveReviewCredentials(pair[0], pair[1])
		if err != nil || uid != pair[0] || gid != pair[1] {
			t.Fatalf("override=%v got=%d:%d err=%v", pair, uid, gid, err)
		}
	}
}
