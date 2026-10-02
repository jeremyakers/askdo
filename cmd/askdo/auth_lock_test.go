package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/providers"
)

func TestAuthWriterProcessHelper(t *testing.T) {
	path := os.Getenv("ASKDO_AUTH_LOCK_PATH")
	if path == "" {
		return
	}
	client := codexauth.NewClient(codexauth.WithIssuer(os.Getenv("ASKDO_AUTH_LOCK_ISSUER")))
	stubAuthSeams(t, 0, client)
	stubCredentialsWithCodex(t, path)
	fd, err := syscall.Open(path+".lock", syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	closeErr := syscall.Close(fd)
	if !errors.Is(err, syscall.EWOULDBLOCK) || closeErr != nil {
		t.Fatalf("refresh lock not held: %v %v", err, closeErr)
	}
	if _, err := os.Stdout.WriteString("writer-ready\n"); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	switch os.Getenv("ASKDO_AUTH_LOCK_ACTION") {
	case "login":
		if code := authLogin(path, filepath.Dir(path), &out, &stderr); code != 0 {
			t.Fatalf("login %d: %s", code, &stderr)
		}
	case "logout":
		if code := authLogout(path, &out, &stderr); code != 0 {
			t.Fatalf("logout %d: %s", code, &stderr)
		}
	case "replace":
		data, err := json.Marshal(codexauth.TokenSet{AccessToken: "admin-fixture", RefreshToken: "admin-refresh", AccountID: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := operator.WriteCredential(filepath.Dir(path), filepath.Base(path), data, operator.CredentialCodexToken, true); err != nil {
			t.Fatal(err)
		}
	case "reviewer-login":
		if code := reviewerEdit([]string{"codex", "--config", os.Getenv("ASKDO_AUTH_LOCK_CONFIG"), "--provider", "codex", "--force-login", "--yes"}, scripted(), &out, &stderr); code != 0 {
			t.Fatalf("reviewer login %d: %s", code, &stderr)
		}
	case "reviewer-delete":
		if code := reviewerDelete([]string{"codex", "--config", os.Getenv("ASKDO_AUTH_LOCK_CONFIG"), "--delete-key"}, &out, &stderr); code != 0 {
			t.Fatalf("reviewer delete %d: %s", code, &stderr)
		}
	default:
		t.Fatal("unknown fixture action")
	}
}

func TestAuthWritersCannotStaleOverwriteRefresh(t *testing.T) {
	for _, action := range []string{"login", "logout", "replace", "reviewer-login", "reviewer-delete"} {
		t.Run(action, func(t *testing.T) {
			// Given a refresh blocked on a synthetic issuer while holding ownership.
			started, finish := make(chan struct{}), make(chan struct{})
			rotated := authMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/accounts/deviceauth/usercode":
					_ = json.NewEncoder(w).Encode(map[string]any{"device_auth_id": "fixture", "user_code": "TEST", "interval": 0.01})
				case "/api/accounts/deviceauth/token":
					_ = json.NewEncoder(w).Encode(map[string]string{"authorization_code": "fixture", "code_verifier": "fixture"})
				case "/oauth/token":
					if err := r.ParseForm(); err != nil {
						t.Error(err)
						return
					}
					if r.Form.Get("grant_type") == "refresh_token" {
						close(started)
						select {
						case <-finish:
						case <-r.Context().Done():
							return
						}
					}
					account, refresh := "admin", "admin-refresh"
					if r.Form.Get("grant_type") == "refresh_token" {
						account, refresh = "rotated", "rotated-refresh"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": rotated, "refresh_token": refresh, "id_token": authMintJWT(t, map[string]any{"chatgpt_account_id": account})})
				case "/oauth/revoke":
					if err := r.ParseForm(); err != nil {
						t.Error(err)
						return
					}
					if r.Form.Get("token") != "rotated-refresh" {
						t.Error("logout read a pre-refresh snapshot")
					}
				default:
					t.Errorf("unexpected fixture path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), codexCredentialsFile)
			if err := codexauth.NewStore(path, codexauth.TokenSet{AccessToken: authMintJWT(t, map[string]any{"exp": time.Now().Unix()}), RefreshToken: "old-refresh"}).Save(); err != nil {
				t.Fatal(err)
			}
			configPath, _ := onboardFixture(t, fmt.Sprintf(`{"name":"codex","api":"openai_codex","base_url":"https://chatgpt.com/backend-api/codex","model":"fixture","api_key_file":%q,"data_boundary":"external","request_timeout":"1m"},{"name":"local","api":"openai_chat","base_url":"http://localhost:1234/v1","model":"fixture","data_boundary":"local","request_timeout":"1m"}`, path), "")
			done := make(chan providers.CodexLiveToken, 1)
			go func() {
				done <- providers.CodexLivePrepare(ctx, codexauth.NewClient(codexauth.WithIssuer(server.URL)), path, true)
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// When a distinct process logs in, removes, or imports a replacement.
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuthWriterProcessHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "ASKDO_AUTH_LOCK_PATH="+path, "ASKDO_AUTH_LOCK_ISSUER="+server.URL, "ASKDO_AUTH_LOCK_ACTION="+action, "ASKDO_AUTH_LOCK_CONFIG="+configPath)
			var output bytes.Buffer
			cmd.Stderr = &output
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			reader := bufio.NewReader(pipe)
			if line, err := reader.ReadString('\n'); err != nil || line != "writer-ready\n" {
				cancel()
				close(finish)
				_ = cmd.Wait()
				t.Fatalf("child readiness %q: %v %s", line, err, &output)
			}
			wait := make(chan error, 1)
			go func() { wait <- cmd.Wait() }()
			select {
			case err := <-wait:
				close(finish)
				<-done
				t.Fatalf("writer passed refresh lock: %v %s", err, &output)
			case <-time.After(200 * time.Millisecond):
			}
			close(finish)
			result := <-done
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			if err := <-wait; err != nil {
				t.Fatalf("admin child: %v %s", err, &output)
			}
			// Then no late refresh resurrects/removes the administrator's change.
			stored, err := codexauth.Load(path)
			if action == "logout" || action == "reviewer-delete" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("logout target remains: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if stored.AccountID != "admin" || stored.RefreshPending {
				t.Fatal("refresh overwrote administrative credentials")
			}
		})
	}
}
