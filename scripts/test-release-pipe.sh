#!/bin/sh
# Bare `curl TAG-URL | sudo sh` against a REAL producer RELEASE bundle.
# Disposable rootless-Docker container, --network none, no bind mounts. github.com
# is a LOCAL STAND-IN (container /etc/hosts + throwaway CA + Go file server);
# real curl and real sudo are used for the pipeline. Systemctl is stubbed; this is
# not native-NAS or published-GitHub proof. Synthetic validators are not used
# because the container's real visudo satisfies the installer.
set -eu
TAG=v1.0.0-rc.11
IMAGE=${ASKDO_PIPE_IMAGE:-askdo-host-evidence-fixture:46b0b95}
if [ "${1:-}" != --inside ]; then
  ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
  case "$(docker info --format '{{json .SecurityOptions}}')" in *'"name=rootless"'*) ;; *) exit 1;; esac
  W=$(mktemp -d "${TMPDIR:-/var/tmp}/askdo-pipe.XXXXXX")
  C=
  trap 'rm -rf -- "$W"; [ -z "$C" ] || docker rm -f "$C" >/dev/null 2>&1 || :' 0
  trap 'exit 1' 1 2 3 15
  # Clean throwaway repository holding the working-tree bytes, tagged like a release.
  mkdir "$W/src"
  git -C "$ROOT" ls-files -z | tar -C "$ROOT" --null -T - -cf - | tar -C "$W/src" -xf -
  git -C "$W/src" init -q
  git -C "$W/src" add -A
  git -C "$W/src" -c user.name=fixture -c user.email=fixture@invalid commit -q -m fixture
  git -C "$W/src" -c user.name=fixture -c user.email=fixture@invalid tag "$TAG"
  sh "$ROOT/scripts/test-build-release.sh" --make-validators "$W"
  sh "$W/src/scripts/build-release.sh" "$W/out" --release "$TAG" \
    --validator-amd64 "$W/amd64" --validator-arm64 "$W/arm64" --evidence "$W/evidence" >/dev/null
  # Producer contract: only line 5 differs, manifest records derived bytes, source SHA unchanged.
  python3 -I -S -B - "$W" "$TAG" <<'PY'
import hashlib, json, pathlib, sys
w, tag = pathlib.Path(sys.argv[1]), sys.argv[2]
src, out = (w / 'src/install.sh').read_bytes(), (w / 'out/install.sh').read_bytes()
a, b = src.split(b'\n'), out.split(b'\n')
assert [i for i, (x, y) in enumerate(zip(a, b)) if x != y] == [4] and len(a) == len(b)
assert b[4] == b'VERSION=${ASKDO_VERSION:-' + tag.encode() + b'}'
sha = lambda d: hashlib.sha256(d).hexdigest()
proof = json.loads((w / 'evidence/provenance.json').read_text())
assert proof['mode'] == 'RELEASE' and proof['source_files']['install.sh'] == sha(src)
assert proof['installer_default_tag'] == tag and proof['installer_asset_sha256'] == sha(out)
assert ('file install.sh ' + sha(out) + ' ') in (w / 'out/install-manifest.v1').read_text()
for name in ('uninstall.sh', 'askdo.service', 'askdo.sudoers', 'LICENSE'):
    assert (w / 'out' / name).read_bytes() == (w / 'src' / {'askdo.service': 'contrib/askdo.service',
        'askdo.sudoers': 'contrib/askdo.sudoers'}.get(name, name)).read_bytes()
PY
  # Public route layout; the source installer is kept for the pre-fix control.
  R=$W/www/jeremyakers/askdo/releases/download/$TAG
  mkdir -p "$R" "$W/tools"
  cp "$W/out/"* "$R/"
  cp "$W/src/install.sh" "$W/source-install.sh"
  # Host curl (identical Ubuntu 22.04 ABI) copied into the container; never overwrite.
  tool=/usr/bin/curl
  { printf '%s\n' "$tool"; ldd "$tool" | awk '$3 ~ /^\// {print $3}'; } | tar -C / -hcf - -T - | tar -C "$W/tools" -xf -
  cat > "$W/server.go" <<'GO'
// Throwaway fixture HTTPS file server: own CA, github.com certificate, real 404s, request log.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "github.com"},
		DNSNames: []string{"github.com"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	files := http.FileServer(http.Dir("/www"))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET %s", r.URL.Path)
		files.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: "127.0.0.1:443", Handler: handler, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	// Publishing the CA is the fixture readiness signal: bind the listener first.
	if err := os.WriteFile("/tmp/ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.ServeTLS(listener, "", ""))
}
GO
  mkdir -p "$W/tools/usr/local/bin"
  CGO_ENABLED=0 GOFLAGS='' GOTOOLCHAIN=local go build -trimpath -o "$W/tools/usr/local/bin/pipe-server" "$W/server.go"
  C=$(docker create --network none -w /root "$IMAGE" sh /pipe/test-release-pipe.sh --inside)
  docker cp "$W/www" "$C:/www"
  docker cp "$W/tools" "$C:/tools"
  docker cp "$W/source-install.sh" "$C:/source-install.sh"
  docker cp "$W/out" "$C:/bundle"
  docker cp "$ROOT/scripts" "$C:/pipe"
  docker start -a "$C"
  exit "$(docker inspect --format '{{.State.ExitCode}}' "$C")"
fi
chmod -R go+rX /tools
for d in /tools/*; do cp -rn "$d/." "/$(basename "$d")/"; done
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
URL=https://github.com/jeremyakers/askdo/releases/download/$TAG/install.sh
printf '127.0.0.1 github.com\n' >> /etc/hosts
(exec pipe-server > /tmp/server.log 2>&1) &
for _ in 1 2 3 4 5 6 7 8 9 10; do test -s /tmp/ca.crt && break; sleep 1; done
mkdir -p /etc/ssl/certs
cat /tmp/ca.crt >> /etc/ssl/certs/ca-certificates.crt
curl -fsS -o /dev/null "$URL"
if curl -fsS -o /dev/null https://github.com/jeremyakers/askdo/releases/latest/download/install-manifest.v1 2>/dev/null; then
  echo 'latest manifest unexpectedly exists'; exit 1
fi
useradd -m fixture
printf 'fixture ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/fixture
chmod 0440 /etc/sudoers.d/fixture
printf '#!/bin/sh\ncase "$1" in is-active) exit 3;; *) exit 0;; esac\n' > /usr/local/bin/systemctl
chmod 0755 /usr/local/bin/systemctl
pipe() { su fixture -c "curl --proto '=https' --proto-redir '=https' -fsSL $URL | sudo sh $*" > /tmp/result 2>&1; }
same_as_bundle() {
  cmp /usr/local/bin/askdo /bundle/askdo-linux-amd64
  cmp /usr/local/libexec/askdo-launch /bundle/askdo-launch-linux-amd64
}
# Control: the pre-fix (unbound) installer served at the tag URL fails with no env/args.
mkdir /www-good && cp /www/jeremyakers/askdo/releases/download/"$TAG"/install.sh /www-good/install.sh
cp /source-install.sh /www/jeremyakers/askdo/releases/download/"$TAG"/install.sh
if pipe; then cat /tmp/result; echo 'unbound installer unexpectedly installed'; exit 1; fi
grep -q 'release manifest unavailable' /tmp/result
test ! -e /usr/local/bin/askdo
cp /www-good/install.sh /www/jeremyakers/askdo/releases/download/"$TAG"/install.sh
printf 'control: unbound installer fails on 404 latest, as in the reported defect\n'
# Default bare pipe, normal user, no env, no arguments.
pipe || { cat /tmp/result; exit 1; }
same_as_bundle
test "$(stat -c %u:%g:%a /usr/local/bin/askdo)" = 0:0:755
test -f /etc/sudoers.d/askdo
grep -q "GET /jeremyakers/askdo/releases/download/$TAG/install-manifest.v1" /tmp/server.log
for f in install.sh uninstall.sh askdo.service; do
  cmp "/bundle/$f" "/www/jeremyakers/askdo/releases/download/$TAG/$f"
done
printf 'default pipe: installed exact release bytes from tag URL\n'
# Compatible reinstall preserves config, credentials accounts/IDs and helper policy.
before=$( { find /etc/askdo -type f -exec sha256sum {} +; getent passwd askdo-review; getent group askdo; sha256sum /etc/sudoers.d/askdo; } 2>&1 | sort)
pipe || { cat /tmp/result; exit 1; }
after=$( { find /etc/askdo -type f -exec sha256sum {} +; getent passwd askdo-review; getent group askdo; sha256sum /etc/sudoers.d/askdo; } 2>&1 | sort)
test "$before" = "$after"
same_as_bundle
printf 'reinstall: config, accounts, IDs and helper policy preserved\n'
# Explicit overrides still work and never touch latest.
sh /bundle/uninstall.sh --purge --yes >/dev/null
pipe -s -- --version "$TAG" || { cat /tmp/result; exit 1; }
same_as_bundle
sh /bundle/uninstall.sh --purge --yes >/dev/null
su fixture -c "curl --proto '=https' --proto-redir '=https' -fsSL $URL | ASKDO_VERSION=$TAG sudo env ASKDO_VERSION=$TAG sh" > /tmp/result 2>&1 || { cat /tmp/result; exit 1; }
same_as_bundle
sh /bundle/uninstall.sh --purge --yes >/dev/null
# Local source checkout installer with --version: line-5 difference must not break self-binding.
cp /source-install.sh /home/fixture/install.sh
chown fixture /home/fixture/install.sh
su fixture -c "sh /home/fixture/install.sh --version $TAG" > /tmp/result 2>&1 || { cat /tmp/result; exit 1; }
same_as_bundle
sh /bundle/uninstall.sh --purge --yes >/dev/null
# A tag-default-only local installer remains compatible with an explicit override.
sed '5s/latest/v1.0.0-rc.10/' /source-install.sh > /home/fixture/install.sh
su fixture -c "sh /home/fixture/install.sh --version $TAG" > /tmp/result 2>&1 || { cat /tmp/result; exit 1; }
same_as_bundle
sh /bundle/uninstall.sh --purge --yes >/dev/null
# Extra VERSION statements elsewhere (even syntactically valid) remain differences.
for extra in 'VERSION=${ASKDO_VERSION:-latest}' 'VERSION=${ASKDO_VERSION:-other}; :'; do
  { cat /source-install.sh; printf '%s\n' "$extra"; } > /home/fixture/install.sh
  if su fixture -c "sh /home/fixture/install.sh --version $TAG" > /tmp/result 2>&1; then cat /tmp/result; exit 1; fi
  grep -q 'installer differs from selected release' /tmp/result
  test ! -e /usr/local/bin/askdo
done
cp /source-install.sh /home/fixture/install.sh
printf '# divergent\n' >> /home/fixture/install.sh
if su fixture -c "sh /home/fixture/install.sh --version $TAG" > /tmp/result 2>&1; then cat /tmp/result; exit 1; fi
grep -q 'installer differs from selected release' /tmp/result
test ! -e /usr/local/bin/askdo
printf 'overrides and local --version self-binding preserved; divergent installer refused\n'
printf 'PASS (local github.com stand-in with real curl+sudo; not native NAS or published-GitHub proof)\n'
