#!/bin/sh
# OFFHOST producer contract test. Validator fixtures are SYNTHETIC, not upstream.
# Optional argument: NEW private evidence directory retaining this fixture bundle.
# --guards-only: bounded typed-boundary/serialization checks, no Go compilation.
# --verify-bundle BUNDLE EVIDENCE: verify an already built actual snapshot.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ "${1:-}" = --verify-bundle ]; then
  test "$#" -eq 3 || { printf '%s\n' 'expected BUNDLE EVIDENCE' >&2; exit 1; }
  python3 -I -S -B - "$ROOT" "$2" "$3" <<'PY'
import hashlib, json, pathlib, re, subprocess, sys, tarfile
root, bundle, evidence = map(pathlib.Path, sys.argv[1:])
sha = lambda data: hashlib.sha256(data).hexdigest()
common = {'install.sh': 'install.sh', 'uninstall.sh': 'uninstall.sh',
          'askdo-config.example.json': 'askdo-config.example.json', 'LICENSE': 'LICENSE',
          'askdo.service': 'contrib/askdo.service', 'askdo-gateway.service': 'contrib/askdo-gateway.service',
          'askdo.sudoers': 'contrib/askdo.sudoers',
          'gateway-config.example.json': 'examples/fleet/gateway-config.example.json',
          'host-config.example.json': 'examples/fleet/host-config.example.json'}
expected = set(common) | {'visudo-LICENSE', 'visudo-SOURCE'}
for arch in ('amd64', 'arm64'):
    expected.add('visudo-linux-' + arch)
    for name in ('askdo', 'askdo-launch'):
        expected.update({f'{name}-linux-{arch}', f'{name}-linux-{arch}.sha256'})
assert len(expected) == 21 and {p.name for p in bundle.iterdir()} == expected | {'install-manifest.v1'}
lines = (bundle / 'install-manifest.v1').read_text('ascii').splitlines()
assert len(lines) == 26 and max(map(len, lines)) <= 512
assert lines[0] == 'askdo-install-v1' and lines[1] == 'repository jeremyakers/askdo'
assert lines[4] == 'validator 1.9.5p2 48'
assert re.fullmatch(r'release snapshot-[A-Za-z0-9][A-Za-z0-9._-]{0,118}', lines[2])
assert re.fullmatch(r'source [0-9a-f]{40}', lines[3])
assert (bundle / 'install-manifest.v1').stat().st_size <= 16384
records = {}
metadata = json.loads((evidence / 'artifacts.json').read_text())
assert set(metadata) == expected
for line in lines[5:]:
    kind, name, digest, size = line.split(' ')
    assert kind == 'file' and name not in records
    assert re.fullmatch(r'[0-9a-f]{64}', digest) and re.fullmatch(r'[1-9][0-9]*', size)
    assert 0 < int(size) <= 512 * 1024 * 1024
    data = (bundle / name).read_bytes()
    assert sha(data) == digest and str(len(data)) == size
    assert metadata[name]['sha256'] == digest and metadata[name]['size'] == len(data)
    records[name] = digest
assert set(records) == expected
proof = json.loads((evidence / 'provenance.json').read_text())
assert proof['mode'] == 'SNAPSHOT' and proof['bundle_complete'] and not proof['release_ready']
assert proof['base_commit'] == lines[3].split()[1] and proof['release'] == lines[2].split()[1]
assert proof['repository'] == 'jeremyakers/askdo'
assert proof['base_commit'] == subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip()
assert sha((evidence / 'source.tar').read_bytes()) == proof['source_archive_sha256']
with tarfile.open(evidence / 'source.tar') as archive:
    names = archive.getnames()
    assert 'scripts/build-sudo-validator-arm64.sh' in names
    assert set(names) == set(proof['source_files'])
    assert not any(part.startswith('.') for name in names for part in name.split('/'))
    for name in names:
        data = archive.extractfile(name).read()
        assert sha(data) == proof['source_files'][name]
        assert data == (root / name).read_bytes(), 'post-freeze public source drift: ' + name
    for name, original in common.items():
        assert archive.extractfile(original).read() == (bundle / name).read_bytes()
assert records['install.sh'] == proof['source_files']['install.sh'] == sha((root / 'install.sh').read_bytes())
assert records['visudo-linux-amd64'] == 'dc2765868dd971a913fb88bd0cafcbacdeea12b1a05dde0a55f098deb7e15b54'
assert records['visudo-linux-arm64'] == 'd53eac0749d2436bee2bc84bc96ce9ef5c7a3c7c4f005adb787d45a1d2b34a2b'
source = (bundle / 'visudo-SOURCE').read_text()
assert 'image=debian@sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91' in source
assert 'not native ARM64 kernel' in source and 'native AMD64 build default only; not actual cross image' in source
for arch, machine in (('amd64', 62), ('arm64', 183)):
    for name in ('askdo', 'askdo-launch', 'visudo'):
        asset = f'{name}-linux-{arch}'
        data = (bundle / asset).read_bytes()
        assert data[:7] == b'\x7fELF\x02\x01\x01' and int.from_bytes(data[18:20], 'little') == machine
        report = subprocess.check_output(['readelf', '-W', '-h', '-l', '-d', str(bundle / asset)]).decode()
        assert 'INTERP' not in report and '(NEEDED)' not in report and 'LOAD' in report
        assert metadata[asset]['static'] and metadata[asset]['architecture'] == arch
        if name != 'visudo':
            info = subprocess.check_output(['go', 'version', '-m', str(bundle / asset)]).decode()
            assert all(setting in info for setting in ('CGO_ENABLED=0', 'GOOS=linux', 'GOARCH=' + arch))
            assert 'askdo_fleet_fixture' not in info and '-tags=' not in info
            assert (bundle / (asset + '.sha256')).read_text() == records[asset] + '  ' + asset + '\n'
print('PASS actual complete 22-asset snapshot: exact manifest, digests, static targets, Go metadata, frozen source/common bytes and cross provenance')
print('source_archive_sha256=' + proof['source_archive_sha256'])
print('manifest_sha256=' + sha((bundle / 'install-manifest.v1').read_bytes()))
PY
  exit 0
fi
if [ "${1:-}" = --guards-only ]; then
  python3 -I -S -B - "$ROOT" "${2:-}" "${3:-}" "${4:-}" <<'PY'
import dataclasses, importlib.util, json, pathlib, sys, tempfile
import shutil
from unittest.mock import patch
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('producer', root / 'scripts/build-release-bundle.py')
producer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = producer
spec.loader.exec_module(producer)
source = producer.parse_validator_source((root / 'contrib/validator/source.env').read_bytes())
cross = producer.parse_cross_pins((root / 'scripts/build-sudo-validator-arm64.sh').read_bytes())
assert source.version == '1.9.5p2' and source.sha256 == '539e2ef43c8a55026697fb0474ab6a925a11206b5aa58710cb42a0e1c81f0978'
for raw in (b'SUDO_VERSION=1.9.5p2\n', source.raw + b'SUDO_VERSION=9\n', b'not an assignment\n'):
    try:
        producer.parse_validator_source(raw)
        raise AssertionError('accepted malformed typed source boundary')
    except producer.BuildError:
        pass
base = ['new-output', '--validator-amd64', 'amd', '--validator-arm64', 'arm', '--evidence', 'new-evidence']
for flag, value, kind in (('--release', 'v1', producer.ReleaseTag), ('--snapshot', 'test', producer.SnapshotLabel)):
    options = producer.parse_options(base + [flag, value])
    assert isinstance(options, producer.BuildOptions) and isinstance(options.selection, kind)
    assert isinstance(options.output, pathlib.Path)
    try:
        options.output = pathlib.Path('changed')
        raise AssertionError('mutable build options')
    except dataclasses.FrozenInstanceError:
        pass
for extra in ([], ['--release', 'v1', '--snapshot', 'test']):
    try:
        producer.parse_options(base + extra)
        raise AssertionError('accepted missing/ambiguous selection')
    except SystemExit as error:
        assert error.code == 2
elf = producer.ElfMetadata('amd64', True)
record = producer.ArtifactRecord('a' * 64, 10, elf, 'CGO_ENABLED=0')
assert record.json_value() == {'sha256': 'a' * 64, 'size': 10, 'architecture': 'amd64', 'static': True, 'go_build_info': 'CGO_ENABLED=0'}
validator = producer.ArtifactRecord('b' * 64, 20, elf, version_trace='trace', validation='supplier records only')
assert validator.json_value() == {'sha256': 'b' * 64, 'size': 20, 'architecture': 'amd64', 'static': True, 'version_trace': 'trace', 'validation': 'supplier records only'}
if sys.argv[2]:
    baseline = pathlib.Path(sys.argv[2])
    records = json.loads((baseline / 'artifacts.json').read_text())
    assert len(records) == 21
    for name, value in records.items():
        elf = producer.ElfMetadata(value['architecture'], value['static']) if 'architecture' in value else None
        restored = producer.ArtifactRecord(value['sha256'], value['size'], elf,
                                           value.get('go_build_info'), value.get('version_trace'), value.get('validation'))
        assert restored.json_value() == value, name
    value = json.loads((baseline / 'provenance.json').read_text())
    restored_proof = producer.Provenance(**value)
    assert restored_proof.json_value() == value
    assert producer.digest((baseline / 'source.tar').read_bytes()) == restored_proof.source_archive_sha256
    print('PASS all 21 historical artifact JSON records/provenance round-trip unchanged; old source hash retained')
with tempfile.TemporaryDirectory(prefix='askdo-typed-guards-') as temporary:
    work = pathlib.Path(temporary)
    frozen = producer.freeze(work, None)
    assert frozen.head == producer.git('rev-parse', 'HEAD').decode().strip()
    assert frozen.files['scripts/build-release-bundle.py'].data == producer.PRODUCER_BYTES
    assert producer.digest((work / 'source.tar').read_bytes()) == frozen.archive_sha256
    proof = producer.Provenance('SNAPSHOT', False, False, frozen.head, 'snapshot-test', frozen.dirty,
                                'jeremyakers/askdo', frozen.archive_sha256, 'base only', {'install.sh': 'c' * 64})
    producer.json_file(work / 'proof.json', proof.json_value())
    assert json.loads((work / 'proof.json').read_text()) == proof.json_value()
    producer.json_file(work / 'assets.json', {'binary': record.json_value()})
    assert json.loads((work / 'assets.json').read_text()) == {'binary': record.json_value()}
    with patch.object(producer, 'git', return_value=b'1' * 40 + b'\n'):
        producer.clean_release('v1', '1' * 40, b'')
        for head, status in (('2' * 40, b''), ('1' * 40, b' M install.sh')):
            try:
                producer.clean_release('v1', head, status)
                raise AssertionError('accepted dirty/mismatching source')
            except producer.BuildError:
                pass
    stage, output = work / 'stage', work / 'appeared'
    stage.mkdir()
    output.mkdir()
    try:
        producer.publish(stage, output)
        raise AssertionError('overwrote raced empty directory')
    except producer.BuildError:
        pass
    if sys.argv[3] or sys.argv[4]:
        assert sys.argv[3] and sys.argv[4]
        validated = {}
        for arch, supplied in (('amd64', sys.argv[3]), ('arm64', sys.argv[4])):
            candidate = pathlib.Path(supplied)
            inputs = producer.validator_inputs(candidate, arch, source, work,
                                               producer.expected_build(arch, source, cross))
            validated[arch] = inputs
        assert producer.digest(validated['amd64'].binary) == 'dc2765868dd971a913fb88bd0cafcbacdeea12b1a05dde0a55f098deb7e15b54'
        assert producer.digest(validated['arm64'].binary) == 'd53eac0749d2436bee2bc84bc96ce9ef5c7a3c7c4f005adb787d45a1d2b34a2b'
        assert validated['amd64'].license == validated['arm64'].license
        for arch, supplied in (('amd64', sys.argv[3]), ('arm64', sys.argv[4])):
            mutated = work / ('mutated-' + arch)
            shutil.copytree(pathlib.Path(supplied), mutated)
            for filename, old, replacement, message in (
                    ('visudo-BUILD', b'image=', b'image=wrong-', 'build metadata'),
                    ('visudo-BUILD', b'architecture=' + arch.encode(), b'architecture=unknown', 'build metadata'),
                    ('visudo-SOURCE', b'SUDO_VERSION=1.9.5p2', b'SUDO_VERSION=9.9.9', 'source'),
                    ('visudo-linux-' + arch, b'\x7fELF\x02\x01\x01', b'\x7fELF\x01\x02\x01', 'ELF')):
                path = mutated / filename
                original = path.read_bytes()
                path.write_bytes(original.replace(old, replacement, 1))
                try:
                    producer.validator_inputs(mutated, arch, source, work,
                                              producer.expected_build(arch, source, cross))
                    raise AssertionError('accepted wrong actual input: ' + filename)
                except producer.BuildError as error:
                    assert message in str(error), str(error)
                path.write_bytes(original)
            build = mutated / 'visudo-BUILD'
            original = build.read_bytes()
            invalid = [original + b'image=duplicate\n', original + b'method=unknown\n']
            if arch == 'arm64':
                invalid += [original.replace(b'image_index=', b'image_index=wrong-', 1),
                            original.replace(b'selected_manifest=', b'selected_manifest=wrong-', 1),
                            original.replace(b'method=AMD64', b'method=unknown', 1)]
            for data in invalid:
                build.write_bytes(data)
                try:
                    producer.validator_inputs(mutated, arch, source, work,
                                              producer.expected_build(arch, source, cross))
                    raise AssertionError('accepted unknown/duplicate method/image/index')
                except producer.BuildError:
                    pass
            build.write_bytes(original)
        for raw in (b'CROSS_IMAGE=dynamic\nCROSS_INDEX=dynamic\n',
                    (root / 'scripts/build-sudo-validator-arm64.sh').read_bytes() + b'\nCROSS_IMAGE=duplicate\n'):
            try:
                producer.parse_cross_pins(raw)
                raise AssertionError('accepted nonfixed/duplicate script pin')
            except producer.BuildError:
                pass
        print('PASS real amd64/arm64 supplier records and actual byte digests')
print('PASS typed options/source/records/provenance serialization, source freeze, clean-tag/output guards; no compilation')
PY
  exit 0
fi
TMPROOT=${TMPDIR:-/var/tmp}
test -d "$TMPROOT" || { printf '%s\n' 'temporary parent is missing' >&2; exit 1; }
TMP=$(mktemp -d "$TMPROOT/askdo-release-test.XXXXXX")
trap 'rm -rf -- "$TMP"' 0
trap 'exit 1' 1 2 3 15

# A legitimate cross-architecture static ELF, but deliberately not a sudo parser.
cat > "$TMP/validator.go" <<'GO'
package main
import "fmt"
func main() { fmt.Println("SYNTHETIC producer fixture; not upstream visudo 1.9.5p2 grammar 48") }
GO
for arch in amd64 arm64; do
  mkdir "$TMP/$arch"
  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 GOFLAGS='' GOTOOLCHAIN=local \
    go build -trimpath -o "$TMP/$arch/visudo-linux-$arch" "$TMP/validator.go"
  cp "$ROOT/contrib/validator/source.env" "$TMP/$arch/visudo-SOURCE"
  printf '%s\n' 'SYNTHETIC producer fixture license, not an upstream license' > "$TMP/$arch/visudo-LICENSE"
  printf 'visudo-linux-%s version 1.9.5p2\nvisudo-linux-%s grammar version 48\n' "$arch" "$arch" > "$TMP/$arch/visudo-V.stdout"
  : > "$TMP/$arch/visudo-V.stderr"
  image=$(awk -F= '$1 == "VALIDATOR_IMAGE" { print $2 }' "$ROOT/contrib/validator/source.env")
  printf 'image=%s\narchitecture=%s\ntargets=lib/util/libsudo_util.la plugins/sudoers/visudo\ninstallation=none; artifact mode=0755; no capabilities or setuid\n' "$image" "$arch" > "$TMP/$arch/visudo-BUILD"
  if [ "$arch" = arm64 ]; then
    cross_image=$(awk -F= '$1 == "CROSS_IMAGE" { print $2 }' "$ROOT/scripts/build-sudo-validator-arm64.sh")
    cross_index=$(awk -F= '$1 == "CROSS_INDEX" { print $2 }' "$ROOT/scripts/build-sudo-validator-arm64.sh")
    selected=${cross_image#*@}
    printf 'image=%s\nimage_index=%s\nselected_manifest=%s\narchitecture=arm64\nmethod=AMD64 cross GCC; source-built musl; explicit qemu-aarch64-static user mode\n' "$cross_image" "$cross_index" "$selected" > "$TMP/$arch/visudo-BUILD"
    printf 'cross_image=%s\ncross_image_index=%s\nselected_manifest=%s\nmethod=arm64-cross-explicit-qemu-user; no binfmt; not native ARM64 kernel\nheader_VALIDATOR_IMAGE=native AMD64 build default only; not actual cross image\n' "$cross_image" "$cross_index" "$selected" >> "$TMP/$arch/visudo-SOURCE"
  fi
  (cd "$TMP/$arch" && sha256sum "visudo-linux-$arch" > "visudo-linux-$arch.sha256")
done

# This assertion fails against the old eight-file producer before any implementation.
GOFLAGS=-tags=askdo_fleet_fixture sh "$ROOT/scripts/build-release.sh" "$TMP/release" --snapshot producer-contract \
  --validator-amd64 "$TMP/amd64" --validator-arm64 "$TMP/arm64" --evidence "$TMP/evidence"

python3 -I -S -B - "$ROOT" "$TMP" "${1:-}" <<'PY'
import hashlib, importlib.util, json, pathlib, shutil, subprocess, sys, tarfile
from unittest.mock import patch
root, tmp = map(pathlib.Path, sys.argv[1:3])
out = tmp / 'release'
expected = {'install.sh', 'uninstall.sh', 'askdo-config.example.json', 'askdo.service',
            'askdo-gateway.service', 'askdo.sudoers', 'gateway-config.example.json',
            'host-config.example.json', 'LICENSE', 'visudo-LICENSE', 'visudo-SOURCE'}
for arch in ('amd64', 'arm64'):
    expected.add('visudo-linux-' + arch)
    for name in ('askdo', 'askdo-launch'):
        expected.update({f'{name}-linux-{arch}', f'{name}-linux-{arch}.sha256'})
assert {p.name for p in out.iterdir()} == expected | {'install-manifest.v1'}
manifest = (out / 'install-manifest.v1').read_text('ascii').splitlines()
assert manifest[:3] == ['askdo-install-v1', 'repository jeremyakers/askdo', 'release snapshot-producer-contract']
assert manifest[4] == 'validator 1.9.5p2 48'
assert len(manifest) == 26 and max(map(len, manifest)) <= 512
records = {}
for line in manifest[5:]:
    kind, name, sha, size = line.split(' ')
    assert kind == 'file' and name not in records
    data = (out / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha and str(len(data)) == size
    records[name] = sha
assert set(records) == expected
proof = json.loads((tmp / 'evidence/provenance.json').read_text())
assert proof['mode'] == 'SNAPSHOT' and proof['release_ready'] is False
assert proof['bundle_complete'] is True
assert manifest[3] == 'source ' + proof['base_commit']
archive = tmp / 'evidence/source.tar'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == proof['source_archive_sha256']
with tarfile.open(archive) as source:
    names = source.getnames()
    assert 'scripts/build-release-bundle.py' in names
    assert 'scripts/build-sudo-validator.sh' in names and 'contrib/validator/source.env' in names
    assert 'scripts/build-sudo-validator-arm64.sh' in names
    assert not any(part.startswith('.') for name in names for part in name.split('/'))
    assert source.extractfile('install.sh').read() == (out / 'install.sh').read_bytes()
    assert source.extractfile('scripts/build-release.sh').read() == (root / 'scripts/build-release.sh').read_bytes()
metadata = json.loads((tmp / 'evidence/artifacts.json').read_text())
assert set(metadata) == expected
for arch in ('amd64', 'arm64'):
    for name in ('askdo', 'askdo-launch'):
        asset = f'{name}-linux-{arch}'
        assert (out / (asset + '.sha256')).read_text() == records[asset] + '  ' + asset + '\n'
        assert metadata[asset]['sha256'] == records[asset]
        assert metadata[asset]['static'] and metadata[asset]['architecture'] == arch
        assert 'CGO_ENABLED=0' in metadata[asset]['go_build_info']
        assert 'askdo_fleet_fixture' not in metadata[asset]['go_build_info']

def run_failure(label, args, message):
    dest = tmp / label
    command = ['sh', str(root / 'scripts/build-release.sh'), str(dest), *args,
               '--validator-amd64', str(tmp / 'amd64'), '--validator-arm64', str(tmp / 'arm64'),
               '--evidence', str(tmp / (label + '-evidence'))]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0, (label, result.stdout, result.stderr)
    assert message in result.stderr, (label, result.stderr)
    assert not dest.exists(), label

run_failure('dirty-release', ['--release', 'v-producer-contract'], 'clean')
for tag in ('latest', 'main', 'master', '../bad', '-bad', 'bad tag'):
    run_failure('bad-tag-' + hashlib.sha256(tag.encode()).hexdigest()[:8], ['--release=' + tag], 'invalid')
run_failure('no-mode', [], 'required')
run_failure('both-modes', ['--release', 'v1', '--snapshot', 'test'], 'not allowed')

# Reject missing provenance/version/license and wrong-architecture bytes before Go builds.
for filename in ('visudo-LICENSE', 'visudo-SOURCE', 'visudo-V.stdout', 'visudo-BUILD'):
    path = tmp / 'arm64' / filename
    data = path.read_bytes()
    path.unlink()
    run_failure('missing-' + filename, ['--snapshot', 'missing'], 'validator')
    path.write_bytes(data)
path = tmp / 'arm64/visudo-V.stdout'
old = path.read_bytes()
path.write_bytes(old.replace(b'1.9.5p2', b'1.9.6p1'))
run_failure('bad-version', ['--snapshot', 'bad'], 'version')
path.write_bytes(old)
for filename, replacement, message in (
        ('visudo-linux-arm64', b'not an ELF placeholder\n', 'ELF'),
        ('visudo-linux-arm64.sha256', b'0' * 64 + b'  visudo-linux-arm64\n', 'checksum'),
        ('visudo-SOURCE', b'SUDO_VERSION=9\n', 'source'),
        ('visudo-LICENSE', b'different architecture license\n', 'licenses differ'),
        ('visudo-BUILD', b'architecture=amd64\n', 'build metadata')):
    path = tmp / 'arm64' / filename
    old = path.read_bytes()
    path.write_bytes(replacement)
    run_failure('invalid-' + filename, ['--snapshot', 'bad'], message)
    path.write_bytes(old)
path = tmp / 'arm64/visudo-linux-arm64'
old = path.read_bytes()
path.write_bytes((tmp / 'amd64/visudo-linux-amd64').read_bytes())
run_failure('wrong-architecture', ['--snapshot', 'bad'], 'architecture')
path.write_bytes(old)

before = {p.name: p.read_bytes() for p in out.iterdir()}
result = subprocess.run(['sh', str(root / 'scripts/build-release.sh'), str(out), '--snapshot', 'again',
                         '--validator-amd64', str(tmp / 'amd64'), '--validator-arm64', str(tmp / 'arm64'),
                         '--evidence', str(tmp / 'again-evidence')], capture_output=True, text=True)
assert result.returncode and 'exists' in result.stderr
assert before == {p.name: p.read_bytes() for p in out.iterdir()}

# Narrow helper seams: no Git writes, no second full product build.
spec = importlib.util.spec_from_file_location('producer', root / 'scripts/build-release-bundle.py')
producer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = producer
spec.loader.exec_module(producer)
assert producer.valid_tag('v1.2.3') and not producer.valid_tag('latest')
with patch.object(producer, 'git', return_value=b'1' * 40 + b'\n'):
    producer.clean_release('v1', '1' * 40, b'')
    try:
        producer.clean_release('v1', '2' * 40, b'')
        raise AssertionError('accepted a tag not at HEAD')
    except producer.BuildError:
        pass
    try:
        producer.clean_release('v1', '1' * 40, b' M install.sh')
        raise AssertionError('accepted a dirty release')
    except producer.BuildError:
        pass
with tarfile.open(archive) as tar:
    frozen = {entry.name: (tar.extractfile(entry).read(), 0o755 if entry.mode & 0o111 else 0o644)
              for entry in tar if entry.isfile()}
names = sorted(frozen)
def fake_git(*args):
    if args[0] == 'archive':
        return archive.read_bytes()
    if args[0] == 'status':
        return b''
    return (proof['base_commit'] + '\n').encode()
def assert_freeze_failure(label, message, inventory, contents, release=None):
    target = tmp / label
    target.mkdir()
    with patch.object(producer, 'git', side_effect=fake_git), \
         patch.object(producer, 'public_inventory', side_effect=inventory), \
         patch.object(producer, 'read_regular', side_effect=lambda root, name: contents[name]):
        try:
            producer.freeze(target, release)
            raise AssertionError('accepted ' + label)
        except producer.BuildError as error:
            assert message in str(error), str(error)
assert_freeze_failure('inventory-drift', 'drift', [names, names[:-1]], frozen)
changed = dict(frozen)
changed['install.sh'] = (b'not the committed installer\n', 0o644)
assert_freeze_failure('falsely-clean-source', 'exact clean committed', [names], changed, 'v1')
target = tmp / 'byte-drift'
target.mkdir()
reads = 0
def drifting_read(root, name):
    global reads
    reads += 1
    return changed[name] if reads > len(names) else frozen[name]
with patch.object(producer, 'git', side_effect=fake_git), \
     patch.object(producer, 'public_inventory', return_value=names), \
     patch.object(producer, 'read_regular', side_effect=drifting_read):
    try:
        producer.freeze(target, None)
        raise AssertionError('accepted mixed byte-drifting source')
    except producer.BuildError as error:
        assert 'drift' in str(error)
target = tmp / 'mock-clean-commit'
target.mkdir()
with patch.object(producer, 'git', side_effect=fake_git), \
     patch.object(producer, 'public_inventory', return_value=names), \
     patch.object(producer, 'read_regular', side_effect=lambda root, name: frozen[name]):
    head, dirty, captured, archive_hash = producer.freeze(target, 'v-unit-test')
assert not dirty and head == proof['base_commit'] and captured == frozen
assert archive_hash == hashlib.sha256((target / 'source.tar').read_bytes()).hexdigest()
alias = tmp / 'source-alias'
alias.symlink_to(tmp / 'validator.go')
try:
    producer.read_regular(tmp, 'source-alias')
    raise AssertionError('accepted symlink source')
except producer.BuildError:
    pass
race = tmp / 'race'
race.mkdir()
stage = tmp / 'race-stage'
stage.mkdir()
(stage / 'new').write_text('new')
try:
    producer.publish(stage, race)
    raise AssertionError('accepted concurrently appeared empty destination')
except producer.BuildError:
    pass
assert not (race / 'new').exists()
if sys.argv[3]:
    retained = pathlib.Path(sys.argv[3]).absolute()
    assert retained.parent.is_dir() and not retained.exists()
    retained.mkdir()
    shutil.copytree(out, retained / 'SYNTHETIC-bundle')
    shutil.copytree(tmp / 'evidence', retained / 'evidence')
    (retained / 'NOT-A-RELEASE.txt').write_text('SYNTHETIC validator fixtures; producer contract only. Not upstream ARM acceptance or publishable release.\n')
    print('retained synthetic producer evidence: ' + str(retained))
print('PASS: complete 22-asset producer matrix, static cross-ELF and metadata, exact manifest, frozen source, rejection/immutability')
print('SYNTHETIC validators only; no upstream ARM runtime or publication proof')
PY
