package fleetclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestReportStatusSendsTheReportAuthenticatedAndReadsNothingFromTheAnswer(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got fleetproto.HostStatus
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/host-status" || r.URL.RawQuery != "" {
			t.Errorf("request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.Header.Get("X-Askdo-Host") != "host-a" || r.Header.Get("Authorization") != "Bearer "+base64.RawURLEncoding.EncodeToString(make([]byte, 32)) {
			t.Error("host authentication missing")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		status, err := fleetproto.ParseHostStatus(body)
		if err != nil {
			t.Errorf("gateway cannot read the report %s: %v", body, err)
		}
		mu.Lock()
		got, requests = status, requests+1
		mu.Unlock()
		// An unsigned acknowledgement: the host must not need to verify one.
		_, _ = w.Write([]byte(`{"version":1}`))
	}))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, pub))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	want := fleetproto.HostStatus{Version: fleetproto.HostStatusVersion, Hostname: "nas-01", Release: "v1.0.0", AutoUpgrade: true, Upgrade: &fleetproto.UpgradeResult{Release: "v1.0.0", State: "succeeded", UpdatedAt: 5}}
	if err := client.ReportStatus(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 || !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway received %d report(s): %+v", requests, got)
	}
}

func TestReportStatusFailuresAreTransportFailuresNotProtocolDamage(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	status := fleetproto.HostStatus{Version: fleetproto.HostStatusVersion, AutoUpgrade: true}
	for name, handler := range map[string]http.HandlerFunc{
		// A gateway from before the endpoint existed.
		"gateway without the endpoint": http.NotFound,
		"revoked host":                 func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"gateway error":                func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"empty answer":                 func(w http.ResponseWriter, r *http.Request) {},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			client, err := New(fixtureConfig(t, server, pub))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var failure *Error
			if err := client.ReportStatus(context.Background(), status); !errors.As(err, &failure) {
				t.Fatalf("err = %v, want a fleet error", err)
			}
		})
	}
	// A report the gateway could not read is never sent.
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, pub))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.ReportStatus(context.Background(), fleetproto.HostStatus{AutoUpgrade: true}); err == nil || called {
		t.Fatalf("report without a version was sent (err %v, called %v)", err, called)
	}
}
