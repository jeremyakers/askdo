package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jeremyakers/askdo/internal/fleetproto"

	_ "modernc.org/sqlite"
)

var (
	ErrUnauthorized = errors.New("gateway enrollment unauthorized")
	ErrHostNotFound = errors.New("gateway host not found")
	ErrHostEnabled  = errors.New("gateway host must be revoked before deletion")
)

// EnrollmentPolicy grants explicit identities, never wildcard authority. No
// default channel means a UID without an explicit route cannot create tickets.
type EnrollmentPolicy struct {
	AllowedProfiles []string          `json:"allowed_profiles"`
	AllowedChannels []string          `json:"allowed_channels"`
	DefaultChannel  string            `json:"default_channel,omitempty"`
	UIDChannels     map[uint32]string `json:"uid_channels,omitempty"`
}

// Enrollment is safe for administrative listing: it contains no bearer/hash.
type Enrollment struct {
	HostID  string `json:"host_id"`
	Enabled bool   `json:"enabled"`
	EnrollmentPolicy
}

// AuthenticatedHost is derived only from database-authenticated credentials,
// independently of any request body. It is a per-request policy snapshot, not a
// cached authorization for later requests or pending decision delivery.
type AuthenticatedHost struct {
	HostID string
	EnrollmentPolicy
}

func (h AuthenticatedHost) AllowsProfile(id string) bool { return containsID(h.AllowedProfiles, id) }

func (h AuthenticatedHost) ChannelForUID(uid uint32) (string, error) {
	channel, ok := h.UIDChannels[uid]
	if !ok {
		channel = h.DefaultChannel
	}
	if channel == "" || !containsID(h.AllowedChannels, channel) {
		return "", ErrUnauthorized
	}
	return channel, nil
}

func containsID(list []string, id string) bool {
	for _, value := range list {
		if value == id {
			return true
		}
	}
	return false
}

func (p EnrollmentPolicy) validate() error {
	for _, list := range []struct {
		field string
		ids   []string
		max   int
	}{{"enrollment.allowed_profiles", p.AllowedProfiles, fleetproto.MaxCatalogProfiles}, {"enrollment.allowed_channels", p.AllowedChannels, 128}} {
		if len(list.ids) > list.max {
			return errors.New("enrollment allowlist has too many entries")
		}
		seen := map[string]bool{}
		for index, id := range list.ids {
			if err := validateID(fmt.Sprintf("%s[%d]", list.field, index), id); err != nil {
				return err
			}
			if seen[id] {
				return errors.New("enrollment allowlist has duplicate IDs")
			}
			seen[id] = true
		}
	}
	if p.DefaultChannel != "" {
		if err := validateID("enrollment.default_channel", p.DefaultChannel); err != nil {
			return err
		}
		if !containsID(p.AllowedChannels, p.DefaultChannel) {
			return errors.New("default channel must be allowed")
		}
	}
	if len(p.UIDChannels) > 128 {
		return errors.New("enrollment has too many UID routes")
	}
	for uid, channel := range p.UIDChannels {
		if err := validateID(fmt.Sprintf("enrollment.uid_channels[%d]", uid), channel); err != nil {
			return err
		}
		if !containsID(p.AllowedChannels, channel) {
			return errors.New("UID channel must be allowed")
		}
	}
	return nil
}

type EnrollmentStore struct {
	db   *sql.DB
	path string
	// changes wakes the dispatcher after this process commits work for it. Other
	// processes' commits reach it through dataVersion instead.
	changes wakeHub
}

// Test seam only for Unix ownership: production always requires root ownership.
var enrollmentOwner = func(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

const gatewayApplicationID = 0x41534757 // ASGW; never adopt a local jobs DB.

// OpenEnrollmentStore opens only this gateway database. Existing permissions,
// symlinks, ownership and application/schema identity are checked, never fixed
// silently. New databases are created 0600 in an existing trusted directory.
func OpenEnrollmentStore(path string) (*EnrollmentStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("gateway database path must be absolute and clean")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || !enrollmentOwner(parent) || parent.Mode().Perm()&0022 != 0 {
		return nil, errors.New("gateway database directory must be root-owned and not group/world writable")
	}
	fresh := false
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		fresh = true
		if err = file.Close(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !enrollmentOwner(info) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errors.New("gateway database must be a root:root nonsymlink regular file mode 0600")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		artifact, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !artifact.Mode().IsRegular() || artifact.Mode().Perm() != 0600 || !enrollmentOwner(artifact) || artifact.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return nil, errors.New("unsafe gateway database sidecar")
		}
	}
	// Check the header before opening SQLite: even a PRAGMA can trigger hot
	// journal recovery, which must never mutate an unrelated local job store.
	if !fresh {
		fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		var header [100]byte
		_, readErr := io.ReadFull(fd, header[:])
		closeErr := fd.Close()
		if readErr != nil || closeErr != nil || string(header[:16]) != "SQLite format 3\x00" || binary.BigEndian.Uint32(header[68:72]) != gatewayApplicationID || binary.BigEndian.Uint32(header[60:64]) != 1 {
			return nil, errors.New("not a supported gateway enrollment database")
		}
	}
	uri := url.URL{Scheme: "file", Path: path}
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*EnrollmentStore, error) { db.Close(); return nil, err }
	var appID, version int
	if err = db.QueryRow("PRAGMA application_id").Scan(&appID); err != nil {
		return fail(err)
	}
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if fresh {
		if appID != 0 || version != 0 {
			return fail(errors.New("gateway database initialization conflict"))
		}
		tx, err := db.Begin()
		if err != nil {
			return fail(err)
		}
		_, err = tx.Exec(`PRAGMA application_id = 1095976791;
   PRAGMA user_version = 1;
   CREATE TABLE gateway_enrollments (
    host_id TEXT PRIMARY KEY,
    bearer_hash BLOB NOT NULL CHECK(length(bearer_hash)=32),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    policy_json TEXT NOT NULL
   );`)
		if err != nil {
			tx.Rollback()
			return fail(err)
		}
		if err = tx.Commit(); err != nil {
			return fail(err)
		}
	} else if appID != gatewayApplicationID || version != 1 {
		return fail(errors.New("not a supported gateway enrollment database"))
	}
	rows, err := db.Query("SELECT host_id,bearer_hash,enabled,policy_json FROM gateway_enrollments LIMIT 0")
	if err != nil {
		return fail(err)
	}
	rows.Close()
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return fail(errors.New("gateway database path changed during open"))
	}
	return &EnrollmentStore{db: db, path: path}, nil
}

func (s *EnrollmentStore) Close() error { return s.db.Close() }

// Create returns the random bearer exactly once, as a separate secret value.
// Only its SHA256 hash is bound into SQL. No token appears in errors or records.
func (s *EnrollmentStore) Create(ctx context.Context, policy EnrollmentPolicy) (Enrollment, string, error) {
	return s.create(ctx, policy, true)
}

// ProvisionDisabled creates an unauthenticatable identity for one-time export.
// The operator activates it only after durable bundle publication succeeds.
func (s *EnrollmentStore) ProvisionDisabled(ctx context.Context, policy EnrollmentPolicy) (Enrollment, string, error) {
	return s.create(ctx, policy, false)
}

func (s *EnrollmentStore) create(ctx context.Context, policy EnrollmentPolicy, enabled bool) (Enrollment, string, error) {
	if err := policy.validate(); err != nil {
		return Enrollment{}, "", err
	}
	var id, secret [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Enrollment{}, "", err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return Enrollment{}, "", err
	}
	hostID := "host_" + hex.EncodeToString(id[:])
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256(secret[:])
	data, err := json.Marshal(policy)
	if err != nil {
		return Enrollment{}, "", err
	}
	// Decode our own typed snapshot before insertion, never perform a fallible
	// post-commit read that could discard the new identity before cleanup.
	host, err := decodeEnrollment(hostID, enabled, string(data))
	if err != nil {
		return Enrollment{}, "", err
	}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO gateway_enrollments(host_id,bearer_hash,enabled,policy_json) VALUES(?,?,?,?)", hostID, hash[:], enabled, string(data)); err != nil {
		return Enrollment{}, "", fmt.Errorf("create enrollment: %w", err)
	}
	return host, token, nil
}

// Activate is a compare-and-set transition: duplicate/concurrent activation
// cannot succeed. Only the provisioning operator invokes this administrative
// primitive; a revoked host is never automatically activated or retried.
func (s *EnrollmentStore) Activate(ctx context.Context, hostID, bearer string) error {
	if err := validateID("host_id", hostID); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(bearer)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != bearer {
		return ErrUnauthorized
	}
	hash := sha256.Sum256(raw)
	result, err := s.db.ExecContext(ctx, "UPDATE gateway_enrollments SET enabled=1 WHERE host_id=? AND enabled=0 AND bearer_hash=?", hostID, hash[:])
	return enrollmentAffected(result, err)
}

func decodeEnrollment(hostID string, enabled bool, data string) (Enrollment, error) {
	var policy EnrollmentPolicy
	if err := strictConfigJSON([]byte(data), &policy); err != nil {
		return Enrollment{}, fmt.Errorf("invalid stored enrollment policy: %w", err)
	}
	if err := policy.validate(); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{HostID: hostID, Enabled: enabled, EnrollmentPolicy: policy}, nil
}

func (s *EnrollmentStore) Get(ctx context.Context, hostID string) (Enrollment, error) {
	var enabled bool
	var data string
	err := s.db.QueryRowContext(ctx, "SELECT enabled,policy_json FROM gateway_enrollments WHERE host_id=?", hostID).Scan(&enabled, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, ErrHostNotFound
	}
	if err != nil {
		return Enrollment{}, err
	}
	return decodeEnrollment(hostID, enabled, data)
}

func (s *EnrollmentStore) List(ctx context.Context) ([]Enrollment, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT host_id,enabled,policy_json FROM gateway_enrollments ORDER BY host_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hosts := []Enrollment{}
	for rows.Next() {
		var id, data string
		var enabled bool
		if err := rows.Scan(&id, &enabled, &data); err != nil {
			return nil, err
		}
		host, err := decodeEnrollment(id, enabled, data)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

// Authenticate always reads enabled and policy from SQLite: long-running
// servers observe another store/CLI connection's committed edits and revokes.
func (s *EnrollmentStore) Authenticate(ctx context.Context, hostID, bearer string) (AuthenticatedHost, error) {
	raw, err := base64.RawURLEncoding.DecodeString(bearer)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != bearer {
		return AuthenticatedHost{}, ErrUnauthorized
	}
	candidate := sha256.Sum256(raw)
	expected := make([]byte, 32)
	var enabled bool
	var data string
	err = s.db.QueryRowContext(ctx, "SELECT bearer_hash,enabled,policy_json FROM gateway_enrollments WHERE host_id=?", hostID).Scan(&expected, &enabled, &data)
	match := subtle.ConstantTimeCompare(candidate[:], expected)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!enabled || match != 1) {
		return AuthenticatedHost{}, ErrUnauthorized
	}
	if err != nil {
		return AuthenticatedHost{}, err
	}
	host, err := decodeEnrollment(hostID, enabled, data)
	if err != nil {
		return AuthenticatedHost{}, err
	}
	return AuthenticatedHost{HostID: host.HostID, EnrollmentPolicy: host.EnrollmentPolicy}, nil
}

func (s *EnrollmentStore) UpdatePolicy(ctx context.Context, hostID string, policy EnrollmentPolicy) error {
	if err := policy.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE gateway_enrollments SET policy_json=? WHERE host_id=?", string(data), hostID)
	return enrollmentAffected(result, err)
}

func enrollmentAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrHostNotFound
	}
	return nil
}

// TicketRevoker is the later ticket store's atomic seam. It must touch only
// this host's pending tickets, use tx (not a new DB connection), and do no I/O.
// No callback means enrollment-only revocation, without assuming ticket tables.
type TicketRevoker func(context.Context, *sql.Tx, string) error

func (s *EnrollmentStore) Revoke(ctx context.Context, hostID string) error {
	return s.RevokeWithTickets(ctx, hostID, nil)
}

func (s *EnrollmentStore) RevokeWithTickets(ctx context.Context, hostID string, revoke TicketRevoker) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Retire the credential as well as disabling the record: a provisioning
	// activation racing an explicit revoke must never revive that identity.
	result, err := tx.ExecContext(ctx, "UPDATE gateway_enrollments SET enabled=0,bearer_hash=zeroblob(32) WHERE host_id=?", hostID)
	if err := enrollmentAffected(result, err); err != nil {
		return err
	}
	if revoke != nil {
		if err := revoke(ctx, tx, hostID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Pending tickets of the revoked host are the dispatcher's to settle.
	s.changes.notify()
	return nil
}

// Delete is limited to disabled hosts. Future ticket schemas should retain
// their frozen host binding; deletion must never revive that identity.
func (s *EnrollmentStore) Delete(ctx context.Context, hostID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM gateway_enrollments WHERE host_id=?", hostID).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return ErrHostNotFound
	} else if err != nil {
		return err
	}
	if enabled {
		return ErrHostEnabled
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM gateway_enrollments WHERE host_id=?", hostID)
	if err := enrollmentAffected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}
