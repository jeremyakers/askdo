package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type setupCall struct {
	tool string
	args []string
}

type fakeFleetSetup struct {
	calls      []setupCall
	dsm        bool
	member     bool
	uid        string
	addErr     error
	serviceErr error
	verifyFail bool
}

func (r *fakeFleetSetup) Exists(path string) (bool, error) {
	if path != "/usr/syno/sbin/synogroup" {
		return false, errors.New("unexpected tool probe")
	}
	return r.dsm, nil
}

func (r *fakeFleetSetup) Run(ctx context.Context, path string, args ...string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		return "", errors.New("command has no execution deadline")
	}
	r.calls = append(r.calls, setupCall{path, append([]string(nil), args...)})
	switch path {
	case "/usr/bin/id":
		if args[0] == "-u" {
			if r.uid != "" {
				return r.uid, nil
			}
			return "1000\n", nil
		}
		if r.member {
			return "users askdo\n", nil
		}
		return "users\n", nil
	case "/usr/sbin/usermod", "/usr/syno/sbin/synogroup":
		if !r.verifyFail && (r.addErr == nil || r.dsm) {
			r.member = true
		}
		return "", r.addErr
	case "/usr/bin/systemctl":
		return "", r.serviceErr
	default:
		return "", errors.New("unexpected tool execution")
	}
}

func TestFleetSetupGroupAndService(t *testing.T) {
	for _, tc := range []struct {
		name, user string
		runner     fakeFleetSetup
		wantAdd    string
		wantErr    bool
	}{
		{name: "Linux success", user: "lauren", wantAdd: "/usr/sbin/usermod"},
		{name: "already member", user: "lauren", runner: fakeFleetSetup{member: true}},
		{name: "DSM nonzero success", user: "lauren", runner: fakeFleetSetup{dsm: true, addErr: errors.New("exit 1")}, wantAdd: "/usr/syno/sbin/synogroup"},
		{name: "DSM verification failure", user: "lauren", runner: fakeFleetSetup{dsm: true, verifyFail: true}, wantAdd: "/usr/syno/sbin/synogroup", wantErr: true},
		{name: "Linux add failure", user: "lauren", runner: fakeFleetSetup{addErr: errors.New("exit 1")}, wantAdd: "/usr/sbin/usermod", wantErr: true},
		{name: "service failure", user: "lauren", runner: fakeFleetSetup{member: true, serviceErr: errors.New("exit 1")}, wantErr: true},
		{name: "direct root", user: "root"},
		{name: "no sudo user"},
		{name: "UID zero alias", user: "admin", runner: fakeFleetSetup{uid: "0\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a narrow fake runner: no command may touch the developer host.
			r := tc.runner
			var out bytes.Buffer
			// When final setup applies the invoking user's group and service steps.
			err := finishFleetSetup(t.Context(), tc.user, &r, &out)
			// Then Linux/DSM membership semantics and fixed service argv are honored.
			if (err != nil) != tc.wantErr {
				t.Fatalf("setup err=%v wantErr=%t", err, tc.wantErr)
			}
			var add string
			for _, call := range r.calls {
				if call.tool == "/usr/sbin/usermod" {
					add = call.tool
					if !reflect.DeepEqual(call.args, []string{"-a", "-G", "askdo", "--", tc.user}) {
						t.Fatalf("usermod argv: %v", call.args)
					}
				}
				if call.tool == "/usr/syno/sbin/synogroup" {
					add = call.tool
					if !reflect.DeepEqual(call.args, []string{"--memberadd", "askdo", tc.user}) {
						t.Fatalf("synogroup argv: %v", call.args)
					}
				}
			}
			if add != tc.wantAdd {
				t.Fatalf("add tool=%q want=%q; calls=%v", add, tc.wantAdd, r.calls)
			}
			last := r.calls[len(r.calls)-1]
			if last.tool != "/usr/bin/systemctl" || !reflect.DeepEqual(last.args, []string{"enable", "--now", "askdo"}) {
				t.Fatalf("service not attempted: %+v", last)
			}
			if tc.wantAdd == "" && !r.member && !strings.Contains(out.String(), "skip") {
				t.Fatalf("root membership skip was not explained: %s", out.String())
			}
		})
	}
}
