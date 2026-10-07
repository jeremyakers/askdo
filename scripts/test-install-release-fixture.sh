#!/bin/sh
# Test-artifact preparation ONLY, invoked inside disposable builder containers.
# Never sourced/executed by install.sh. Destination commands use download stubs.
set -eu
mkdir -p /fixture/release /usr/local/bin
CGO_ENABLED=0 /usr/local/go/bin/go build -buildvcs=false -trimpath -o /fixture/release/askdo-linux-amd64 ./cmd/askdo
CGO_ENABLED=0 /usr/local/go/bin/go build -buildvcs=false -trimpath -o /fixture/release/askdo-launch-linux-amd64 ./cmd/askdo-launch
GOARCH=arm64 CGO_ENABLED=0 /usr/local/go/bin/go build -buildvcs=false -trimpath -o /fixture/release/askdo-linux-arm64 ./cmd/askdo
GOARCH=arm64 CGO_ENABLED=0 /usr/local/go/bin/go build -buildvcs=false -trimpath -o /fixture/release/askdo-launch-linux-arm64 ./cmd/askdo-launch
cp install.sh uninstall.sh askdo-config.example.json LICENSE /fixture/release/
cp contrib/askdo.service contrib/askdo-gateway.service contrib/askdo.sudoers /fixture/release/
cp examples/fleet/gateway-config.example.json examples/fleet/host-config.example.json /fixture/release/
for name in askdo-linux-amd64 askdo-launch-linux-amd64 askdo-linux-arm64 askdo-launch-linux-arm64; do
  (cd /fixture/release && sha256sum "$name" > "$name.sha256")
done
# ADAPTER ONLY. Not a bundled upstream binary: executes real installed visudo
# for parsing while exposing the proposed bundle version contract for tests.
cat > /fixture/validator-adapter.c <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "-V") == 0) {
    puts("visudo version 1.9.5p2\nvisudo grammar version 48"); return 0;
  }
  argv[0] = "/usr/sbin/visudo.saved";
  execv(argv[0], argv); return 1;
}
EOF
cc -o /fixture/release/visudo-linux-amd64 /fixture/validator-adapter.c
cp /fixture/release/visudo-linux-amd64 /fixture/release/visudo-linux-arm64
printf 'validator adapter license fixture, not upstream distribution\n' > /fixture/release/visudo-LICENSE
printf 'validator adapter provenance fixture, not upstream distribution\n' > /fixture/release/visudo-SOURCE
if [ -f /fixture/real-validator/visudo-linux-amd64 ]; then
  [ "$(sha256sum /fixture/real-validator/visudo-linux-amd64 | cut -d' ' -f1)" = dc2765868dd971a913fb88bd0cafcbacdeea12b1a05dde0a55f098deb7e15b54 ] || exit 1
  cp /fixture/real-validator/visudo-linux-amd64 /fixture/release/visudo-linux-amd64
  cp /fixture/real-validator/visudo-LICENSE /fixture/real-validator/visudo-SOURCE /fixture/release/
  printf 'real upstream amd64 validator fixture, pinned dc276586...\n'
fi
manifest() {
  printf 'askdo-install-v1\nrepository jeremyakers/askdo\nrelease %s\nsource %s\nvalidator 1.9.5p2 48\n' "$1" "$(git rev-parse HEAD 2>/dev/null || printf 'f56c4be5523817cbaea6f8b971227ea68fadc3ce')"
  for file in /fixture/release/*; do
    case "$file" in */install-manifest.v1) continue ;; esac
    printf 'file %s %s %s\n' "$(basename "$file")" "$(sha256sum "$file" | cut -d' ' -f1)" "$(wc -c < "$file" | tr -d ' ')"
  done
}
manifest fixture-ref > /fixture/manifest
cat > /usr/local/bin/curl <<'EOF'
#!/bin/sh
set -eu
# Match literal production HTTPS owner/release URLs, no alternate URL feature.
url= dest=
while [ "$#" -gt 0 ]; do
  case "$1" in -o) dest=$2; shift 2;; https://*) url=$1; shift;; *) shift;; esac
done
printf '%s\n' "$url" >> /tmp/fetch-urls
case "$url" in
 https://github.com/jeremyakers/askdo/releases/latest/download/install-manifest.v1|https://github.com/jeremyakers/askdo/releases/download/fixture-ref/install-manifest.v1) cp /fixture/manifest "$dest";;
 https://github.com/jeremyakers/askdo/releases/latest/download/install.sh|https://github.com/jeremyakers/askdo/releases/download/fixture-ref/install.sh) cp /fixture/release/install.sh "$dest";;
 https://github.com/jeremyakers/askdo/releases/download/fixture-ref/*)
   file=${url##*/}
   test -f "/fixture/release/$file"
   cp "/fixture/release/$file" "$dest";;
 *) exit 1;;
esac
EOF
cat > /usr/local/bin/go <<'EOF'
#!/bin/sh
echo forbidden-go >> /fixture/calls
exit 1
EOF
chmod 0755 /usr/local/bin/curl /usr/local/bin/go
for tool in cc gcc make; do
  printf '#!/bin/sh\necho forbidden-compiler >> /fixture/calls\nexit 1\n' > "/usr/local/bin/$tool"
  chmod 0755 "/usr/local/bin/$tool"
done
touch /tmp/fetch-urls /fixture/calls
chmod 0666 /tmp/fetch-urls
