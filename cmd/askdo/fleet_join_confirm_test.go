package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

type fleetJoinTestTTY struct {
	io.Reader
	bytes.Buffer
	closed bool
}

func (tty *fleetJoinTestTTY) Read(p []byte) (int, error) { return tty.Reader.Read(p) }
func (tty *fleetJoinTestTTY) Close() error               { tty.closed = true; return nil }

func stubFleetJoinTTY(t *testing.T, answer string) *fleetJoinTestTTY {
	t.Helper()
	tty := &fleetJoinTestTTY{Reader: strings.NewReader(answer)}
	old := openFleetJoinTTY
	t.Cleanup(func() { openFleetJoinTTY = old })
	openFleetJoinTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
	return tty
}

func TestFleetJoinConfirmationNeverUsesPipedStdin(t *testing.T) {
	if os.Getenv("ASKDO_TEST_FLEET_JOIN_NO_TTY") == "1" {
		// No injected opener: exercise the real /dev/tty boundary in a session
		// with no controlling terminal, even though stdin contains approval.
		err := confirmFleetJoin("ABC123")
		if err == nil || !strings.Contains(err.Error(), "enrollment not confirmed; local configuration unchanged") || !strings.Contains(err.Error(), "/dev/tty") {
			t.Fatalf("piped approval bypassed terminal confirmation: %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFleetJoinConfirmationNeverUsesPipedStdin$")
	cmd.Env = append(os.Environ(), "ASKDO_TEST_FLEET_JOIN_NO_TTY=1")
	cmd.Stdin = strings.NewReader("yes\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("terminal-only confirmation: %v\n%s", err, output)
	}
}

func TestFleetJoinProvisionalApprovalRequiresTerminalConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, answer               string
		noTTY, caFile, wantInstall bool
	}{
		{name: "yes", answer: "y\n", wantInstall: true},
		{name: "case insensitive yes", answer: "YeS\n", wantInstall: true},
		{name: "no", answer: "n\n"},
		{name: "default no", answer: "\n"},
		{name: "other answer", answer: "approved\n"},
		{name: "EOF"},
		{name: "unterminated yes EOF", answer: "y"},
		{name: "no tty", noTTY: true},
		{name: "explicit CA never prompts", caFile: true, noTTY: true, wantInstall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fleetJoinHostFixture(t, localJoinConfig)
			var request fleetproto.JoinRequest
			var hostNonce fleetproto.Hash
			var approved atomic.Bool
			var out, stderr bytes.Buffer
			var server *httptest.Server
			// This impostor has no Telegram bot or operator. It claims approval
			// immediately on reveal; its approved response alone is not authority.
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := fleetproto.JoinResponse{Version: fleetproto.JoinVersion, GatewayNonce: fixtureGatewayNonce, ExpiresAt: time.Now().Add(time.Minute).Unix()}
				if r.URL.Path == "/v1/join" {
					data, _ := io.ReadAll(r.Body)
					var err error
					request, err = fleetproto.ParseJoinRequest(data)
					if err != nil {
						t.Error(err)
					}
					response.State = fleetproto.JoinCommitted
				} else {
					data, _ := io.ReadAll(r.Body)
					reveal, err := fleetproto.ParseJoinReveal(data)
					if err != nil || !strings.HasSuffix(r.URL.Path, "/reveal") {
						t.Error("unexpected reveal", err, r.URL.Path)
					}
					hostNonce = reveal.HostNonce
					response.State, response.URL = fleetproto.JoinApproved, server.URL
					response.VerificationKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
					response.AllowedProfiles, response.DefaultProfiles = []string{}, []string{}
					approved.Store(true)
				}
				response.HostID = request.HostID
				wire, err := fleetproto.MarshalJoinResponse(response)
				if err != nil {
					t.Error(err)
				}
				_, _ = w.Write(wire)
			}))
			defer server.Close()
			tty := stubFleetJoinTTY(t, tc.answer)
			var opens int
			openFleetJoinTTY = func() (io.ReadWriteCloser, error) {
				opens++
				if tc.caFile {
					t.Error("trusted gateway prompted")
				}
				if !approved.Load() {
					t.Error("confirmation preceded gateway approval")
				}
				if fileContent(t, path) != localJoinConfig {
					t.Error("config written before confirmation")
				}
				if _, err := os.Stat(filepath.Join(filepath.Dir(path), "credentials")); !errors.Is(err, os.ErrNotExist) {
					t.Error("credentials written before confirmation", err)
				}
				if tc.noTTY {
					return nil, errors.New("no controlling terminal")
				}
				return tty, nil
			}
			args := []string{server.URL}
			if tc.caFile {
				caPath := filepath.Join(filepath.Dir(path), "gateway.pem")
				if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--ca-file", caPath)
			}
			runner := new(fakeFleetSetup)
			err := runFleetJoin(t.Context(), args, path, runner, &out, &stderr)
			if !approved.Load() {
				t.Fatal("fake gateway did not approve")
			}
			wantOpens := 1
			if tc.caFile {
				wantOpens = 0
			}
			if opens != wantOpens {
				t.Errorf("terminal opens = %d, want %d", opens, wantOpens)
			}
			if !tc.caFile && !tc.noTTY {
				code := expectedFleetJoinCode(request, server.Certificate().Raw, hostNonce)
				if tty.String() != "Did the Telegram card show code "+code+", and did you approve it? [y/N] " || !tty.closed {
					t.Errorf("missing confirmation/close: %q closed=%t", tty.String(), tty.closed)
				}
				if !strings.Contains(out.String(), "confirmation question") {
					t.Error("code announcement did not explain terminal confirmation", out.String())
				}
			}
			if tc.wantInstall {
				cfg, loadErr := config.Load(path)
				if err != nil || loadErr != nil || cfg.Fleet == nil || len(runner.calls) == 0 {
					t.Fatalf("confirmed join not installed: %v %v", err, loadErr)
				}
				for _, file := range []string{cfg.Fleet.EnrollmentFile, cfg.Fleet.VerificationKeyFile, cfg.Fleet.CAFile} {
					if _, err := os.Stat(file); err != nil {
						t.Error("credential missing", err)
					}
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "enrollment not confirmed; local configuration unchanged") {
					t.Errorf("unconfirmed enrollment accepted: %v", err)
				}
				if fileContent(t, path) != localJoinConfig || len(runner.calls) != 0 {
					t.Error("unconfirmed join changed config or ran setup")
				}
				if _, err := os.Stat(filepath.Join(filepath.Dir(path), "credentials")); !errors.Is(err, os.ErrNotExist) {
					t.Error("unconfirmed join installed credentials/CA", err)
				}
			}
		})
	}
}
