package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/reviewidentity"
)

// The helper runs in a separate root process: never drop the test runner.
func TestReviewerCLIIdentityHelper(t *testing.T) {
	if os.Getenv("ASKDO_CLI_IDENTITY_HELPER") != "1" {
		return
	}
	if os.Getenv("ASKDO_REVIEWER_GROUP_FIXTURE") != "1" || os.Geteuid() != 0 {
		t.Fatal("helper requires disposable root fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("helper must run in disposable Docker container")
	}
	if os.Getenv("ASKDO_CLI_RESOLUTION_FAIL") == "1" {
		resolveReviewerIdentity = func() (reviewidentity.Identity, error) {
			return reviewidentity.Identity{}, fmt.Errorf("synthetic missing identity")
		}
		dropToReviewer = func(reviewidentity.Identity) error { t.Fatal("drop after resolution failure"); return nil }
		newCodexClient = func() *codexauth.Client { t.Fatal("Codex preparation before identity validation"); return nil }
	}
	if os.Getenv("ASKDO_CLI_DROP_FAIL") == "1" {
		want, err := reviewidentity.Resolve()
		if err != nil || want != (reviewidentity.Identity{UID: 2007, GID: 995}) {
			t.Fatalf("drop-failure fixture requires valid named identity: %+v err=%v", want, err)
		}
		dropToReviewer = func(got reviewidentity.Identity) error {
			if got != want {
				t.Fatalf("drop received %+v, want actual resolved %+v", got, want)
			}
			fmt.Printf("drop failure received valid named identity %d:%d\n", got.UID, got.GID)
			return fmt.Errorf("synthetic privilege drop failure")
		}
	}
	code := runConfig([]string{"check", "--live", "--config", os.Getenv("ASKDO_CLI_CONFIG")}, os.Stdout, os.Stderr)
	if os.Getenv("ASKDO_CLI_RESOLUTION_FAIL") == "1" || os.Getenv("ASKDO_CLI_DROP_FAIL") == "1" {
		if code != 125 {
			t.Fatalf("identity/drop failure exit=%d, want 125", code)
		}
		os.Exit(code) // fatal path exits, rather than continuing provider work as root
	}
	if code != 0 {
		t.Fatalf("live check exit=%d", code)
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"Uid": "2007 2007 2007 2007", "Gid": "995 995 995 995", "Groups": "", "CapEff": "0000000000000000", "CapPrm": "0000000000000000"} {
		found := false
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, key+":"); ok {
				found = true
				if strings.Join(strings.Fields(value), " ") != want {
					t.Fatalf("CLI %s=%q want=%q", key, value, want)
				}
			}
		}
		if !found {
			t.Fatalf("CLI missing %s", key)
		}
	}
	probe := exec.Command("/artifacts/identity-probe")
	probe.Env = []string{"HOME=/fixture"}
	output, err := probe.Output()
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Credential, Broad, Socket bool }
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Credential || got.Broad || got.Socket {
		t.Fatalf("CLI wrong DAC: %s", output)
	}
	fmt.Printf("CLI process all IDs/capabilities verified; DAC: %s\n", output)
}

func TestRootReviewerCLIExecutionGroup(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Getenv("ASKDO_REVIEWER_GROUP_FIXTURE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable root mismatch fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("requires Docker")
	}
	account, err := user.Lookup("askdo-review")
	if err != nil || account.Uid != "2007" || account.Gid != "100" {
		t.Fatalf("wrong named fixture: %+v err=%v", account, err)
	}
	const fixtureKey = "synthetic-reviewer-key-do-not-disclose"
	if err := os.WriteFile("/fixture/credential", []byte(fixtureKey), 0640); err != nil {
		t.Fatal(err)
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
	// Root-only Codex material remains valid, but resolution failure must
	// precede even its broker-side refresh preparation.
	codexPath := t.TempDir() + "/codex-token"
	if err := os.WriteFile(codexPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	failurePath := writeFixtureConfig(t, fmt.Sprintf(`{"name":"codex","api":"openai_codex","base_url":"https://chatgpt.com/backend-api/codex","model":"m","api_key_file":%q,"data_boundary":"external"}`, codexPath))
	failureToken := strings.TrimSuffix(failurePath, "config.json") + "telegram.token"
	if err := os.WriteFile(failureToken, []byte("synthetic"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(failureToken, 0, 995); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"resolution-failure", "drop-failure", "success"} {
		t.Run(state, func(t *testing.T) {
			fixture := newLiveFixtureServer(t, "openai_chat")
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+fixtureKey {
					t.Error("provider request did not use the synthetic reviewer credential")
				}
				fixture.Config.Handler.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			entry := fmt.Sprintf(`{"name":"fixture","api":"openai_chat","base_url":%q,"model":"m","api_key_file":"/fixture/credential","data_boundary":"local"}`, server.URL)
			path := writeFixtureConfig(t, entry)
			// The synthetic Telegram file shares the worker-readable ownership rule.
			token := strings.TrimSuffix(path, "config.json") + "telegram.token"
			if err := os.WriteFile(token, []byte("synthetic"), 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(token, 0, 995); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestReviewerCLIIdentityHelper$", "-test.v")
			configPath, marker, failureEnv := path, "", ""
			switch state {
			case "resolution-failure":
				configPath, marker, failureEnv = failurePath, "synthetic missing identity", "ASKDO_CLI_RESOLUTION_FAIL=1"
			case "drop-failure":
				marker, failureEnv = "synthetic privilege drop failure", "ASKDO_CLI_DROP_FAIL=1"
			}
			command.Env = append(os.Environ(), "ASKDO_CLI_IDENTITY_HELPER=1", "ASKDO_CLI_CONFIG="+configPath)
			if failureEnv != "" {
				command.Env = append(command.Env, failureEnv)
			}
			output, err := command.CombinedOutput()
			count := requests.Load()
			t.Logf("state=%s ordinary-provider requests=%d CLI output:\n%s", state, count, output)
			if bytes.Contains(output, []byte(fixtureKey)) {
				t.Error("CLI output disclosed synthetic credential material")
			}
			if state != "success" {
				if count != 0 {
					t.Errorf("provider contacted after %s: requests=%d, want 0", state, count)
				}
				if !bytes.Contains(output, []byte(marker)) || err == nil || !strings.Contains(err.Error(), "exit status 125") {
					t.Errorf("failed %s err=%v output=%s", state, err, output)
				}
				if bytes.Contains(output, []byte("Bearer synthetic")) || bytes.Contains(output, []byte("model fixture: ok")) {
					t.Error("failure output disclosed credential material or successful provider work")
				}
			} else if err != nil || count != 2 {
				t.Errorf("CLI success err=%v requests=%d, want 2; output=%s", err, count, output)
			}
		})
	}
}
