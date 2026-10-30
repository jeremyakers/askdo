package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jeremyakers/askdo/internal/upgrade"
)

// upgradeBootstrapScript verifies a root-owned copy before executing the new
// helper. The old installed helper is not involved, and a mutable download can
// never become root code before its approved digest has been checked.
func upgradeBootstrapScript(plan upgrade.Plan, capturedPlan []byte, backupRoot string) ([]byte, error) {
	if !filepath.IsAbs(backupRoot) || filepath.Clean(backupRoot) != backupRoot || strings.ContainsAny(backupRoot, "'\n\r") {
		return nil, errors.New("upgrade bootstrap root must be a clean absolute path")
	}
	if len(capturedPlan) == 0 || strings.ContainsAny(string(capturedPlan), "'\n\r") {
		return nil, errors.New("upgrade plan cannot be embedded safely")
	}
	if !upgradeRuntimeOperation.MatchString(plan.Operation) || plan.CLIAsset != "askdo-linux-"+runtime.GOARCH || len(plan.CLIDigest) != 64 {
		return nil, errors.New("upgrade bootstrap plan identity is invalid")
	}
	if _, err := hex.DecodeString(plan.CLIDigest); err != nil {
		return nil, errors.New("upgrade bootstrap CLI digest is invalid")
	}
	bootstrap := filepath.Join(backupRoot, "bootstrap-"+plan.Operation)
	candidate := filepath.Join(bootstrap, plan.CLIAsset)
	script := fmt.Sprintf(`set -eu
operation=$1
source=$2
backup='%s'
bootstrap='%s'
candidate='%s'
if [ ! -e "$backup" ]; then
  /usr/bin/install -d -m 0700 "$backup"
fi
owner=$(/usr/bin/stat -c '%%u' "$backup")
mode=$(/usr/bin/stat -c '%%a' "$backup")
kind=$(/usr/bin/stat -c '%%F' "$backup")
if [ "$owner" != "$(/usr/bin/id -u)" ] || [ "$kind" != directory ] || [ -L "$backup" ]; then
  printf 'untrusted backup root: %%s\n' "$backup" >&2
  exit 1
fi
case "$mode" in
  700|750|755) ;;
  *) printf 'untrusted backup root mode: %%s\n' "$mode" >&2; exit 1 ;;
esac
/bin/mkdir -m 0700 "$bootstrap"
trap '/bin/rm -rf -- "$bootstrap"' EXIT
/usr/bin/install -m 0700 "$source/%s" "$candidate"
printf '%%s  %%s\n' '%s' "$candidate" | /usr/bin/sha256sum -c -
status=0
printf '%%s' '%s' | "$candidate" upgrade-helper --operation "$operation" --source "$source" || status=$?
exit "$status"
`, backupRoot, bootstrap, candidate, plan.CLIAsset, plan.CLIDigest, capturedPlan)
	return []byte(script), nil
}
