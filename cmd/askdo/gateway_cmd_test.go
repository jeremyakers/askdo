package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGatewayRootRefusalAndHelp(t *testing.T) {
	old := getEUID
	getEUID = func() int { return 1000 }
	defer func() { getEUID = old }()
	for _, args := range [][]string{{"init"}, {"hosts", "add"}, {"hosts", "list"}, {"hosts", "revoke", "host_test"}, {"connect"}, {"check"}, {"serve"}} {
		var out, err bytes.Buffer
		if code := runGateway(args, &out, &err); code != 125 || !strings.Contains(err.String(), "requires root") {
			t.Fatalf("%v: code=%d err=%s", args, code, err.String())
		}
	}
	var out, err bytes.Buffer
	if code := runGateway([]string{"--help"}, &out, &err); code != 0 || !strings.Contains(out.String(), "connect") {
		t.Fatalf("help: %d %s %s", code, out.String(), err.String())
	}
	out.Reset()
	err.Reset()
	if code := runGateway([]string{"init", "--help"}, &out, &err); code != 0 || !strings.Contains(out.String(), "tls-cert") {
		t.Fatalf("init help %d %s %s", code, out.String(), err.String())
	}
}

func TestGatewayArgumentErrorsNeverEchoSecret(t *testing.T) {
	old := getEUID
	getEUID = func() int { return 0 }
	defer func() { getEUID = old }()
	for _, args := range [][]string{{"init", "--bot-token", "secret-canary"}, {"hosts", "add", "--bearer=secret-canary"}, {"connect", "--bearer", "secret-canary"}, {"init", "--operator-user-id", "secret-canary"}} {
		var out, stderr bytes.Buffer
		if code := runGateway(args, &out, &stderr); code == 0 || strings.Contains(out.String()+stderr.String(), "secret-canary") {
			t.Fatalf("arguments leaked: code=%d out=%s err=%s", code, out.String(), stderr.String())
		}
	}
}
