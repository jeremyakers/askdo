package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func stubDBOwner(t *testing.T) {
	t.Helper()
	old := enrollmentOwner
	enrollmentOwner = func(info os.FileInfo) bool {
		s, ok := info.Sys().(*syscall.Stat_t)
		return ok && s.Uid == uint32(os.Getuid())
	}
	t.Cleanup(func() { enrollmentOwner = old })
}

func TestEnrollmentCreateDoesNotReadAfterCommittedInsert(t *testing.T) {
	stubDBOwner(t)
	s, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(`CREATE TRIGGER corrupt_read AFTER INSERT ON gateway_enrollments BEGIN UPDATE gateway_enrollments SET policy_json='invalid fixture JSON' WHERE host_id=NEW.host_id; END;`); err != nil {
		t.Fatal(err)
	}
	host, bearer, err := s.Create(t.Context(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
	if err != nil || host.HostID == "" || bearer == "" {
		t.Fatalf("committed creation discarded its identity before caller cleanup: err=%v", err)
	}
}

func TestEnrollmentProvisionDisabledUntilActivation(t *testing.T) {
	stubDBOwner(t)
	s, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	policy := EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"}
	host, bearer, err := s.ProvisionDisabled(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if host.Enabled {
		t.Fatal("provision returned enabled host")
	}
	if _, err = s.Authenticate(t.Context(), host.HostID, bearer); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unpublished credential authenticated", err)
	}
	if err = s.Activate(t.Context(), host.HostID, bearer); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(t.Context(), host.HostID, bearer); err != nil {
		t.Fatal(err)
	}
	if err = s.Activate(t.Context(), host.HostID, bearer); err == nil {
		t.Fatal("activation succeeded twice")
	}
	if err = s.Revoke(t.Context(), host.HostID); err != nil {
		t.Fatal(err)
	}
	if err = s.Activate(t.Context(), host.HostID, bearer); err == nil {
		t.Fatal("activation revived a revoked host")
	}
	pending, token, err := s.ProvisionDisabled(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Revoke(t.Context(), pending.HostID); err != nil {
		t.Fatal(err)
	}
	if err = s.Activate(t.Context(), pending.HostID, token); err == nil {
		t.Fatal("activation won after provisioning was explicitly revoked")
	}
}

func TestEnrollmentIsolationLiveRevokeReopen(t *testing.T) {
	stubDBOwner(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gateway.sqlite")
	s, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	policy := EnrollmentPolicy{AllowedProfiles: []string{"local"}, AllowedChannels: []string{"admin", "other"}, DefaultChannel: "admin", UIDChannels: map[uint32]string{1001: "other"}}
	a, tokenA, err := s.Create(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	b, tokenB, err := s.Create(ctx, EnrollmentPolicy{AllowedProfiles: []string{"cloud"}, AllowedChannels: []string{"second"}, DefaultChannel: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if a.HostID == b.HostID || tokenA == tokenB {
		t.Fatal("shared identity/secret")
	}
	for _, tok := range []string{tokenA, tokenB} {
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil || len(raw) != 32 {
			t.Fatal("not random 32-byte token")
		}
	}
	auth, err := s.Authenticate(ctx, a.HostID, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if auth.HostID != a.HostID || !auth.AllowsProfile("local") || auth.AllowsProfile("cloud") {
		t.Fatal("wrong authenticated identity/allowlists")
	}
	if channel, err := auth.ChannelForUID(1001); err != nil || channel != "other" {
		t.Fatal(channel, err)
	}
	if channel, err := auth.ChannelForUID(1002); err != nil || channel != "admin" {
		t.Fatal(channel, err)
	}
	for _, pair := range [][2]string{{a.HostID, tokenB}, {b.HostID, tokenA}, {"missing", tokenA}, {a.HostID, "bad"}, {a.HostID, ""}} {
		if _, err := s.Authenticate(ctx, pair[0], pair[1]); !errors.Is(err, ErrUnauthorized) {
			t.Fatal(err)
		}
	}
	other, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.UpdatePolicy(ctx, a.HostID, EnrollmentPolicy{AllowedProfiles: []string{"new"}, AllowedChannels: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	auth, err = s.Authenticate(ctx, a.HostID, tokenA)
	if err != nil || !auth.AllowsProfile("new") || auth.AllowsProfile("local") {
		t.Fatal("stale policy", err)
	}
	if _, err := auth.ChannelForUID(1001); err == nil {
		t.Fatal("missing default granted a route")
	}
	if err := other.Revoke(ctx, a.HostID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, a.HostID, tokenA); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("live revoke failed", err)
	}
	if _, err := s.Authenticate(ctx, b.HostID, tokenB); err != nil {
		t.Fatal("other host revoked", err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Authenticate(ctx, b.HostID, tokenB); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Authenticate(ctx, a.HostID, tokenA); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	// Check every SQLite artifact, including journals, for both text and decoded secrets.
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{tokenA, tokenB} {
			raw, _ := base64.RawURLEncoding.DecodeString(tok)
			if bytes.Contains(data, []byte(tok)) || bytes.Contains(data, raw) {
				t.Fatal("bearer persisted")
			}
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tokenB)
	hash := sha256.Sum256(raw)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, hash[:]) {
		t.Fatal("hash not persisted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("DB permissions", err)
	}
}

func TestEnrollmentPolicyAndTransactionalRevoke(t *testing.T) {
	stubDBOwner(t)
	ctx := context.Background()
	s, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gw.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, policy := range []EnrollmentPolicy{
		{AllowedProfiles: []string{"a", "a"}}, {AllowedChannels: []string{""}}, {DefaultChannel: "unknown"},
		{AllowedChannels: []string{"a"}, UIDChannels: map[uint32]string{1: "unknown"}},
	} {
		if _, _, err := s.Create(ctx, policy); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	a, token, err := s.Create(ctx, EnrollmentPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeWithTickets(ctx, a.HostID, func(context.Context, *sql.Tx, string) error { return errors.New("ticket rollback") }); err == nil {
		t.Fatal("callback error ignored")
	}
	if _, err := s.Authenticate(ctx, a.HostID, token); err != nil {
		t.Fatal("failed revoke committed", err)
	}
	if err := s.Delete(ctx, a.HostID); !errors.Is(err, ErrHostEnabled) {
		t.Fatal("deleted enabled host", err)
	}
	if err := s.Revoke(ctx, a.HostID); err != nil {
		t.Fatal("revoke requires nonexistent ticket table", err)
	}
	if err := s.Delete(ctx, a.HostID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, a.HostID); !errors.Is(err, ErrHostNotFound) {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "missing"); !errors.Is(err, ErrHostNotFound) {
		t.Fatal(err)
	}
}

func TestEnrollmentDatabaseRefusesConflicts(t *testing.T) {
	stubDBOwner(t)
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0644, 0666} {
		path := filepath.Join(dir, mode.String())
		if err := os.WriteFile(path, []byte("not a gateway DB"), mode); err != nil {
			t.Fatal(err)
		}
		if s, err := OpenEnrollmentStore(path); err == nil {
			s.Close()
			t.Fatal("unsafe existing file accepted")
		}
	}
	path := filepath.Join(dir, "foreign.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE jobs (id TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenEnrollmentStore(path); err == nil {
		s.Close()
		t.Fatal("local jobs DB adopted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenEnrollmentStore(link); err == nil {
		s.Close()
		t.Fatal("symlink accepted")
	}
	if s, err := OpenEnrollmentStore(dir); err == nil {
		s.Close()
		t.Fatal("directory accepted")
	}
}

func TestEnrollmentRejectsUnsafeSidecars(t *testing.T) {
	stubDBOwner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.sqlite")
	s, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	victim := filepath.Join(dir, "unrelated")
	original := []byte("do not modify")
	if err := os.WriteFile(victim, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		sidecar := path + suffix
		if err := os.Symlink(victim, sidecar); err != nil {
			t.Fatal(err)
		}
		if s, err := OpenEnrollmentStore(path); err == nil {
			s.Close()
			t.Fatalf("accepted symlink sidecar %s", suffix)
		}
		data, err := os.ReadFile(victim)
		if err != nil || !bytes.Equal(data, original) {
			t.Fatal("unrelated file touched", err)
		}
		if err := os.Remove(sidecar); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnrollmentNetworkIDsAndCatalogAllowlist(t *testing.T) {
	stubDBOwner(t)
	ctx := context.Background()
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, id := range []string{"with space", "with/slash", "with\\slash", "with:colon", "unicode-é"} {
		for _, policy := range []EnrollmentPolicy{
			{AllowedProfiles: []string{id}},
			{AllowedChannels: []string{id}},
			{AllowedChannels: []string{id}, DefaultChannel: id},
			{AllowedChannels: []string{id}, UIDChannels: map[uint32]string{1001: id}},
			{AllowedChannels: []string{"valid"}, DefaultChannel: id},
			{AllowedChannels: []string{"valid"}, UIDChannels: map[uint32]string{1001: id}},
		} {
			if _, _, err := store.Create(ctx, policy); !errors.Is(err, fleetproto.ErrProtocol) {
				t.Errorf("invalid enrollment ID %q must preserve protocol error: %v", id, err)
			}
		}
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 0 {
		t.Fatalf("invalid policies persisted: %d records, %v", len(list), err)
	}
	policy := EnrollmentPolicy{AllowedChannels: []string{"Channel_A-1.2"}, DefaultChannel: "Channel_A-1.2", UIDChannels: map[uint32]string{1001: "Channel_A-1.2"}}
	for i := 0; i < 128; i++ {
		policy.AllowedProfiles = append(policy.AllowedProfiles, fmt.Sprintf("profile-%03d", i))
	}
	host, bearer, err := store.Create(ctx, policy)
	if err != nil {
		t.Fatal("128 allowed profiles must remain valid", err)
	}
	auth, err := store.Authenticate(ctx, host.HostID, bearer)
	if err != nil || len(auth.AllowedProfiles) != 128 {
		t.Fatalf("catalog allowlist lost: %d profiles, %v", len(auth.AllowedProfiles), err)
	}
	badUpdate := policy
	badUpdate.UIDChannels = map[uint32]string{1001: "with/slash"}
	if err := store.UpdatePolicy(ctx, host.HostID, badUpdate); !errors.Is(err, fleetproto.ErrProtocol) {
		t.Fatalf("invalid UID route update must fail at boundary: %v", err)
	}
	unchanged, err := store.Authenticate(ctx, host.HostID, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if channel, err := unchanged.ChannelForUID(1001); err != nil || channel != "Channel_A-1.2" {
		t.Fatalf("rejected update changed route: %q, %v", channel, err)
	}
	policy.AllowedProfiles = append(policy.AllowedProfiles, "profile-128")
	if err := store.UpdatePolicy(ctx, host.HostID, policy); err == nil {
		t.Fatal("129 allowed profiles accepted")
	}
}
