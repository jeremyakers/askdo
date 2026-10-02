package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

func TestGatewayRootForceInitPinsExistingIdentity(t *testing.T) {
	for _, fault := range []string{"new-directory", "missing-seed", "missing-keys", "mismatched-public-key", "unchanged"} {
		t.Run(fault, func(t *testing.T) {
			dir, path := gatewayOperatorFixture(t)
			c, err := gateway.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			bundle := filepath.Join(dir, "bundle.json")
			if code := runGateway([]string{"hosts", "add", "--config", path, "--output", bundle, "--channel", "default", "--default-channel", "default"}, &out, &stderr); code != 0 {
				t.Fatalf("enroll %d %s", code, stderr.String())
			}
			before, _ := os.ReadFile(path)
			pubPath := filepath.Join(filepath.Dir(c.SigningKeyFile), "verification.pub")
			pub, _ := os.ReadFile(pubPath)
			creds := filepath.Dir(c.SigningKeyFile)
			switch fault {
			case "new-directory":
				creds = filepath.Join(dir, "other-credentials")
				if err = os.Mkdir(creds, 0750); err != nil {
					t.Fatal(err)
				}
			case "missing-seed":
				if err = os.Remove(c.SigningKeyFile); err != nil {
					t.Fatal(err)
				}
			case "missing-keys":
				if err = os.Remove(c.SigningKeyFile); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(pubPath); err != nil {
					t.Fatal(err)
				}
				pub = nil
			case "mismatched-public-key":
				if err = os.Chmod(pubPath, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(pubPath, []byte("invalid-key\n"), 0400); err != nil {
					t.Fatal(err)
				}
				if err = os.Chmod(pubPath, 0400); err != nil {
					t.Fatal(err)
				}
				pub = []byte("invalid-key\n")
			}
			args := []string{"init", "--config", path, "--url", c.PublicURL, "--listen", c.Listen, "--tls-cert", c.TLSCertFile, "--tls-key", c.TLSKeyFile, "--bot-token-file", c.Bots[0].TokenFile, "--chat-id", "-100", "--operator-user-id", "77", "--database", c.Database, "--credentials-dir", creds, "--force"}
			code := runGateway(args, &out, &stderr)
			if fault == "unchanged" {
				if code != 0 {
					t.Fatalf("force refused unchanged identity: %s", stderr.String())
				}
			} else if code == 0 {
				t.Fatal("force accepted a changed or missing existing identity")
			}
			after, _ := os.ReadFile(path)
			actualPub, _ := os.ReadFile(pubPath)
			if !bytes.Equal(before, after) || !bytes.Equal(pub, actualPub) {
				t.Fatal("refusal changed config or existing public key")
			}
			if fault == "new-directory" {
				entries, _ := os.ReadDir(creds)
				if len(entries) != 0 {
					t.Fatal("refusal generated replacement credentials")
				}
			}
			if fault == "missing-seed" || fault == "missing-keys" {
				if _, err = os.Lstat(c.SigningKeyFile); !os.IsNotExist(err) {
					t.Fatal("force regenerated missing signing seed")
				}
			}
		})
	}
}

func TestGatewayRootExportFailureAndSQLCleanupFailureStayDisabled(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER fail_update BEFORE UPDATE ON gateway_enrollments BEGIN SELECT RAISE(ABORT,'fixture update failure'); END; CREATE TRIGGER fail_delete BEFORE DELETE ON gateway_enrollments BEGIN SELECT RAISE(ABORT,'fixture cleanup failure'); END;`); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "existing.bundle")
	if err = os.WriteFile(output, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"hosts", "add", "--config", path, "--output", output, "--channel", "default", "--default-channel", "default"}, &out, &stderr); code == 0 {
		t.Fatal("export accepted existing output")
	}
	var count, enabled int
	if err = db.QueryRow("SELECT count(*),coalesce(sum(enabled),0) FROM gateway_enrollments").Scan(&count, &enabled); err != nil {
		t.Fatal(err)
	}
	if count != 1 || enabled != 0 {
		t.Fatalf("failed export/cleanup left enabled record: count=%d enabled=%d", count, enabled)
	}
	data, _ := os.ReadFile(output)
	if string(data) != "untouched" {
		t.Fatal("export failure changed existing output")
	}
}

func TestGatewayRootRollbackPreservesInPlaceEdit(t *testing.T) {
	dir, _ := gatewayOperatorFixture(t)
	path := filepath.Join(dir, "new.bearer")
	tx := new(gatewayFiles)
	if err := tx.write(path, []byte("own-secret"), operator.CredentialGatewaySecret); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("root-edit!"), 0600); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "failed-host.json")
	before := []byte(`{"config_version":4,"inspection":{"read_roots":[]},"review":{"mode":"approval_only","models":[]},"limits":{"max_log_bytes_per_stream":0},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`)
	if err := os.WriteFile(host, before, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := operator.LoadForFleetMutation(host)
	if err != nil {
		t.Fatal(err)
	}
	next := store.Config().WithFleet(config.FleetConfig{URL: "https://gateway.example", HostID: "host_test", EnrollmentFile: path, VerificationKeyFile: filepath.Join(dir, "credentials", "verification.pub"), ApprovalTTL: 600}, []string{}, false)
	if err = store.SaveFleet(next); err == nil {
		t.Fatal("invalid retained budget did not fail later save")
	}
	if err := tx.rollback(); err == nil {
		t.Fatal("rollback did not refuse changed content")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "root-edit!" {
		t.Fatal("rollback deleted concurrent in-place edit")
	}
	after, _ := os.ReadFile(host)
	if !bytes.Equal(before, after) {
		t.Fatal("failed save changed original config")
	}
}

func TestGatewayRootPublicationReceiptSurvivesDelayedTracking(t *testing.T) {
	dir, _ := gatewayOperatorFixture(t)
	path := filepath.Join(dir, "published.bearer")
	_, receipt, err := operator.WriteManagedTracked(path, []byte("own bytes"), operator.CredentialGatewaySecret, false)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err = os.WriteFile(replacement, []byte("concurrent replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	// Simulate replacement after publication but before the transaction records
	// the receipt. No post-publication pathname snapshot may adopt this inode.
	tx := &gatewayFiles{files: []*operator.ManagedReceipt{receipt}}
	if err = tx.rollback(); err == nil {
		t.Fatal("rollback adopted replacement")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "concurrent replacement" {
		t.Fatal("rollback removed replacement", err)
	}
}

func TestGatewayRootFreshDatabaseReceiptPreservesConcurrentEnrollment(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Database = filepath.Join(dir, "new.db")
	tx := new(gatewayFiles)
	if err = initializeGatewayDatabase(*c, tx); err != nil {
		t.Fatal(err)
	}
	other, err := gateway.OpenEnrollmentStore(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := other.Create(t.Context(), gateway.EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
	if err != nil {
		other.Close()
		t.Fatal(err)
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tx.rollback(); err == nil {
		t.Fatal("rollback accepted a changed initialized database")
	}
	check, err := gateway.OpenEnrollmentStore(c.Database)
	if err != nil {
		t.Fatal("concurrent database was removed", err)
	}
	defer check.Close()
	if _, err = check.Get(t.Context(), host.HostID); err != nil {
		t.Fatal("concurrent enrollment was lost", err)
	}
}

func TestGatewayRootActivationFailureLeavesPrivateBundleDisabled(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER fail_activation BEFORE UPDATE OF enabled ON gateway_enrollments WHEN NEW.enabled=1 BEGIN SELECT RAISE(ABORT,'fixture activation failure'); END;`); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "disabled.bundle")
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"hosts", "add", "--config", path, "--output", output, "--channel", "default", "--default-channel", "default"}, &out, &stderr); code == 0 {
		t.Fatal("activation fault reported ready enrollment")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal("published disabled bundle was removed", err)
	}
	bundle, err := gateway.DecodeEnrollmentBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err = db.QueryRow("SELECT enabled FROM gateway_enrollments WHERE host_id=?", bundle.HostID).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatal("activation fault left enabled host", err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("disabled bundle is not private")
	}
}

func TestGatewayRootConnectRejectsInvalidRetainedInspection(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	bundle := filepath.Join(dir, "bundle.json")
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"hosts", "add", "--config", path, "--output", bundle, "--channel", "default", "--default-channel", "default"}, &out, &stderr); code != 0 {
		t.Fatalf("add %d %s", code, stderr.String())
	}
	for _, inspection := range []string{`{"read_roots":[],"sensitive_masks":[]}`, `{"read_roots":[],"sensitive_masks":null}`, `{"read_roots":null}`, `{}`} {
		host := filepath.Join(dir, "host.json")
		creds := filepath.Join(dir, "host-credentials")
		before := []byte(`{"config_version":4,"inspection":` + inspection + `,"review":{"mode":"approval_only","models":[{"name":"placeholder","api":"placeholder","base_url":"placeholder","model":"placeholder"}]},"limits":{},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`)
		if err := os.WriteFile(host, before, 0600); err != nil {
			t.Fatal(err)
		}
		if code := runGateway([]string{"connect", "--config", host, "--enrollment", bundle, "--credentials-dir", creds}, &out, &stderr); code == 0 {
			t.Fatalf("accepted invalid retained inspection %s", inspection)
		}
		after, _ := os.ReadFile(host)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid retained policy changed config")
		}
		entries, err := os.ReadDir(creds)
		if err != nil && !os.IsNotExist(err) || len(entries) != 0 {
			t.Fatal("invalid retained policy installed credentials")
		}
	}
}
