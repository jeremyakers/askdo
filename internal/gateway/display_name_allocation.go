package gateway

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// allocateDisplayName runs within the caller's enrollment transaction. Ignore
// the renamed host's own label, but include active pending joins and legacy
// hostname-only records, whose rendered labels are just as significant.
func allocateDisplayName(ctx context.Context, tx *sql.Tx, hostID, name string, now time.Time) (string, error) {
	name = fleetproto.NormalizeDisplayName(name)
	rows, err := tx.QueryContext(ctx, `SELECT json_extract(policy_json,'$.display_name') FROM gateway_enrollments WHERE host_id<>?
UNION ALL SELECT COALESCE(NULLIF(json_extract(policy_json,'$.display_name'),''),hostname) FROM gateway_pending_joins WHERE host_id<>? AND state='pending' AND expires_at>?`, hostID, hostID, now.Unix())
	if err != nil {
		return "", err
	}
	taken := make(map[string]bool)
	for rows.Next() {
		var existing sql.NullString
		if err = rows.Scan(&existing); err != nil {
			rows.Close()
			return "", err
		}
		if existing.Valid {
			taken[fleetproto.NormalizeDisplayName(existing.String)] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	var hasStatus int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='gateway_host_status'").Scan(&hasStatus); err != nil {
		return "", err
	}
	if hasStatus != 0 {
		rows, err := tx.QueryContext(ctx, "SELECT s.hostname FROM gateway_host_status s JOIN gateway_enrollments e ON e.host_id=s.host_id WHERE e.host_id<>? AND COALESCE(json_extract(e.policy_json,'$.display_name'),'')=''", hostID)
		if err != nil {
			return "", err
		}
		for rows.Next() {
			var hostname string
			if err = rows.Scan(&hostname); err != nil {
				rows.Close()
				return "", err
			}
			taken[fleetproto.NormalizeDisplayName(hostname)] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return "", err
		}
	}
	if !taken[name] {
		return name, nil
	}
	id := strings.TrimPrefix(hostID, "host_")
	base := name
	for width := 4; ; width++ {
		suffix := id[:min(width, len(id))]
		if width > len(id) {
			suffix += "-" + strconv.Itoa(width-len(id)+1)
		}
		prefix := []rune(base)
		for len(string(prefix))+1+len(suffix) > fleetproto.MaxJoinHostnameBytes {
			prefix = prefix[:len(prefix)-1]
		}
		name = string(prefix) + "-" + suffix
		if !taken[name] {
			return name, nil
		}
	}
}
