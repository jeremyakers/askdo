#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# How to run: uv run scripts/build-release-bundle.py NEW_OUTPUT --snapshot LABEL
#   --validator-amd64 DIR --validator-arm64 DIR --evidence NEW_DIR
"""OFFHOST bundle producer. No installer fallback, Git writes or publication API.

One immutable public-source archive feeds both Go builds and common assets.
Prebuilt validator build records are checked as data, never sourced or executed.
They are supplier attestations, not cryptographic source-to-binary proof.
"""

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import FrameType, MappingProxyType
from typing import Final, Literal, NamedTuple, NoReturn, TypeAlias


Architecture: TypeAlias = Literal['amd64', 'arm64']
JsonValue: TypeAlias = str | int | bool | None | list['JsonValue'] | Mapping[str, 'JsonValue']

ROOT: Final = Path(__file__).resolve().parent.parent
PRODUCER_BYTES: Final = Path(__file__).read_bytes()
COMMON: Final[Mapping[str, str]] = {
    'install.sh': 'install.sh',
    'uninstall.sh': 'uninstall.sh',
    'askdo-config.example.json': 'askdo-config.example.json',
    'askdo.service': 'contrib/askdo.service',
    'askdo-gateway.service': 'contrib/askdo-gateway.service',
    'askdo.sudoers': 'contrib/askdo.sudoers',
    'gateway-config.example.json': 'examples/fleet/gateway-config.example.json',
    'host-config.example.json': 'examples/fleet/host-config.example.json',
    'LICENSE': 'LICENSE',
}
PUBLIC_ROOT_FILES: Final = {'LICENSE', 'README.md', 'THIRD-PARTY-NOTICES',
                     'askdo-config.example.json', 'go.mod', 'go.sum',
                     'install.sh', 'uninstall.sh'}
PUBLIC_DIRS: Final = {'cmd', 'internal', 'contrib', 'docs', 'examples', 'licenses', 'scripts'}
# Only these reviewed additions may supplement tracked files in a dirty snapshot.
# Never glob the worktree, ignored files, .git, operational evidence or credentials.
INTENDED_ADDITIONS: Final = {
    'scripts/build-release-bundle.py', 'scripts/build-sudo-validator.sh',
    'scripts/build-sudo-validator-arm64.sh',
    'scripts/test-sudo-validator.sh', 'scripts/test-dsm-install.sh',
    'scripts/test-install-release-fixture.sh', 'scripts/test-release-install.sh',
    'contrib/validator/source.env', 'contrib/validator/gcc-runtime-NOTICE',
}
ARCHES: Final[Mapping[Architecture, tuple[int, str]]] = {
    'amd64': (62, 'Advanced Micro Devices X86-64'), 'arm64': (183, 'AArch64')}
MAX_ASSET: Final = 512 * 1024 * 1024


class BuildError(Exception):
    """Expected producer failure propagated to the CLI boundary."""

    message: str

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def assert_never(value: NoReturn) -> NoReturn:
    """Stdlib-only exhaustive match guard compatible with Python 3.10."""
    raise BuildError(f'unreachable variant: {value}')


@dataclass(frozen=True, slots=True)
class ReleaseTag:
    tag: str


@dataclass(frozen=True, slots=True)
class SnapshotLabel:
    label: str


@dataclass(frozen=True, slots=True)
class BuildOptions:
    output: Path
    evidence: Path
    validator_amd64: Path
    validator_arm64: Path
    selection: ReleaseTag | SnapshotLabel


class SourceFile(NamedTuple):
    data: bytes
    mode: int


class FrozenSource(NamedTuple):
    head: str
    dirty: bool
    files: Mapping[str, SourceFile]
    archive_sha256: str


@dataclass(frozen=True, slots=True)
class ValidatorSource:
    raw: bytes
    version: str
    sha256: str
    image: str


@dataclass(frozen=True, slots=True)
class CrossBuildPins:
    image: str
    index: str


@dataclass(frozen=True, slots=True)
class ExpectedBuild:
    build_fields: tuple[tuple[str, str], ...]
    source_fields: tuple[tuple[str, str], ...] = ()
    forbidden_build_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ElfMetadata:
    architecture: Architecture
    static: bool


@dataclass(frozen=True, slots=True)
class ValidatorInputs:
    binary: bytes
    license: bytes
    source: bytes
    build: bytes
    version_trace: str
    elf: ElfMetadata


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    sha256: str
    size: int
    elf: ElfMetadata | None = None
    go_build_info: str | None = None
    version_trace: str | None = None
    validation: str | None = None

    def json_value(self) -> JsonValue:
        """Flatten fixed metadata only at the JSON serialization boundary."""
        value: dict[str, JsonValue] = {'sha256': self.sha256, 'size': self.size}
        if self.elf is not None:
            value.update(architecture=self.elf.architecture, static=self.elf.static)
        if self.go_build_info is not None:
            value['go_build_info'] = self.go_build_info
        if self.version_trace is not None:
            value['version_trace'] = self.version_trace
        if self.validation is not None:
            value['validation'] = self.validation
        return value


@dataclass(frozen=True, slots=True)
class Provenance:
    mode: Literal['RELEASE', 'SNAPSHOT']
    release_ready: bool
    bundle_complete: bool
    base_commit: str
    release: str
    dirty_checkout: bool
    repository: str
    source_archive_sha256: str
    source_meaning: str
    source_files: Mapping[str, str]

    def json_value(self) -> JsonValue:
        """Serialize the fixed provenance schema without an untyped tree."""
        return {'mode': self.mode, 'release_ready': self.release_ready,
                'bundle_complete': self.bundle_complete, 'base_commit': self.base_commit,
                'release': self.release, 'dirty_checkout': self.dirty_checkout,
                'repository': self.repository, 'source_archive_sha256': self.source_archive_sha256,
                'source_meaning': self.source_meaning, 'source_files': dict(self.source_files)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def command(args: Sequence[str], cwd: Path | None = None,
            env: Mapping[str, str] | None = None) -> bytes:
    result: subprocess.CompletedProcess[bytes] = subprocess.run(args, cwd=cwd, env=env, capture_output=True)
    require(result.returncode == 0,
            f"command failed: {args[0]}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def git(*args: str) -> bytes:
    return command(['git', *args], cwd=ROOT)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def valid_tag(tag: str) -> bool:
    return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', tag)) and tag not in {
        'latest', 'main', 'master'}


def new_destination(value: Path) -> Path:
    path = Path(value).absolute()
    require(path.name not in ('', '.', '..'), 'invalid output directory')
    require(path.parent.is_dir(), f'output parent does not exist: {path.parent}')
    path = path.parent.resolve() / path.name
    require(not os.path.lexists(path), f'output already exists: {path}')
    return path


def publish(stage: Path, output: Path) -> None:
    # GNU mv uses no-replace rename semantics. A raced empty directory is not
    # overwritten either; mv -n can succeed without moving, so check the source.
    _ = command(['mv', '-T', '-n', '--', str(stage), str(output)])
    require(not stage.exists(), f'output appeared during publication: {output}')


def read_regular(root: Path, name: str, maximum: int = MAX_ASSET) -> SourceFile:
    path = root / name
    for part in (path, *path.parents):
        require(not part.is_symlink(), f'symlink input is forbidden: {name}')
        if part == root:
            break
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before: os.stat_result = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                f'invalid regular input: {name}')
        data = stream.read(maximum + 1)
        after: os.stat_result = os.fstat(stream.fileno())
    require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            f'input changed during freeze: {name}')
    require(len(data) == before.st_size, f'input changed during freeze: {name}')
    return SourceFile(data, 0o755 if before.st_mode & 0o111 else 0o644)


def public_inventory() -> list[str]:
    tracked = set(git('ls-files', '-z').decode().split('\0')) - {''}
    additions = set(git('ls-files', '--others', '--exclude-standard', '-z').decode().split('\0'))
    names = tracked | (additions & INTENDED_ADDITIONS)
    return sorted(name for name in names
                  if not any(part.startswith('.') for part in name.split('/'))
                  and (name in PUBLIC_ROOT_FILES or name.split('/')[0] in PUBLIC_DIRS))


def clean_release(tag: str, head: str, status: bytes) -> None:
    require(not status, 'release requires a clean checkout, including untracked files')
    # Tags are selected by the owner; this producer never creates or moves one.
    tagged = git('rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}').decode().strip()
    require(tagged == head, 'release tag must resolve to exact HEAD')


def freeze(destination: Path, release: str | None) -> FrozenSource:
    head = git('rev-parse', 'HEAD').decode().strip()
    require(bool(re.fullmatch('[0-9a-f]{40}', head)), 'source must be a full SHA-1 commit')
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all')
    if release:
        clean_release(release, head, status)
    names = public_inventory()
    files = {name: read_regular(ROOT, name) for name in names}
    require(set(COMMON.values()) <= files.keys() and
            {'scripts/build-release.sh', 'scripts/build-release-bundle.py',
             'scripts/build-sudo-validator-arm64.sh',
             'contrib/validator/source.env'} <= files.keys(), 'public source inventory is incomplete')
    require(files['scripts/build-release-bundle.py'][0] == PRODUCER_BYTES,
            'producer code drift before source freeze')
    if release:
        # Status alone can miss assume-unchanged/skip-worktree or filtered bytes.
        # Bind the clean archive to actual commit objects, not merely a status claim.
        committed: dict[str, SourceFile] = {}
        archive_bytes = git('archive', '--format=tar', head, *names)
        with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as committed_tar:
            for entry in committed_tar:
                if entry.name in files:
                    require(entry.isfile(), f'nonregular committed source: {entry.name}')
                    stream = committed_tar.extractfile(entry)
                    if stream is None:
                        raise BuildError(f'missing committed source: {entry.name}')
                    committed[entry.name] = SourceFile(stream.read(), 0o755 if entry.mode & 0o111 else 0o644)
        require(committed == files, 'release requires exact clean committed source bytes and modes')
    # Re-capture, not a metadata-only comparison: a mixed concurrently edited
    # tree is refused before its immutable archive can become a build input.
    require(public_inventory() == names and
            all(read_regular(ROOT, name) == files[name] for name in names) and
            git('rev-parse', 'HEAD').decode().strip() == head and
            git('status', '--porcelain=v1', '-z', '--untracked-files=all') == status,
            'source drift during freeze; retry after edits settle')
    archive = destination / 'source.tar'
    with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for name, (data, mode) in files.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), mode, 0
            tar.addfile(entry, io.BytesIO(data))
    return FrozenSource(head, bool(status), MappingProxyType(files), digest(archive.read_bytes()))


def elf_metadata(path: Path, arch: Architecture) -> ElfMetadata:
    data = path.read_bytes()
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01',
            f'not a Linux ELF64 little-endian asset: {path.name}')
    require(int.from_bytes(data[18:20], 'little') == ARCHES[arch][0],
            f'wrong validator/binary architecture: {path.name}')
    require(int.from_bytes(data[16:18], 'little') in (2, 3),
            f'not an executable ELF: {path.name}')
    report = command(['readelf', '-W', '-h', '-l', '-d', str(path)]).decode()
    require(ARCHES[arch][1] in report and 'LOAD' in report,
            f'invalid ELF architecture/load segments: {path.name}')
    require('INTERP' not in report and '(NEEDED)' not in report,
            f'asset is not static: {path.name}')
    return ElfMetadata(architecture=arch, static=True)


def parse_validator_source(raw: bytes) -> ValidatorSource:
    """Read pinned source.env as data; require the three producer-owned fields."""
    fields: dict[str, str] = {}
    try:
        for line in raw.decode('ascii').splitlines():
            if not line or line.startswith('#'):
                continue
            name, separator, value = line.partition('=')
            require(bool(separator) and name not in fields, 'invalid validator source field')
            fields[name] = value
    except UnicodeError as error:
        raise BuildError('validator source.env is not ASCII data') from error
    version, sha256, image = (fields.get(name) for name in ('SUDO_VERSION', 'SUDO_SHA256', 'VALIDATOR_IMAGE'))
    if version is None or sha256 is None or image is None:
        raise BuildError('missing required validator source fields')
    require(version == '1.9.5p2' and sha256 ==
            '539e2ef43c8a55026697fb0474ab6a925a11206b5aa58710cb42a0e1c81f0978',
            'validator source pin does not match consumer grammar contract')
    return ValidatorSource(raw, version, sha256, image)


def parse_cross_pins(raw: bytes) -> CrossBuildPins:
    """Read unique fixed cross-image assignments from frozen public code as data."""
    try:
        lines = raw.decode('ascii').splitlines()
    except UnicodeError as error:
        raise BuildError('cross builder pins are not ASCII data') from error
    values: dict[str, str] = {}
    for name in ('CROSS_IMAGE', 'CROSS_INDEX'):
        assignments = [line for line in lines if line.startswith(name + '=')]
        require(len(assignments) == 1 and bool(re.fullmatch(
            name + r'=debian@sha256:[0-9a-f]{64}', assignments[0])),
            f'invalid fixed cross builder pin: {name}')
        values[name] = assignments[0].partition('=')[2]
    return CrossBuildPins(values['CROSS_IMAGE'], values['CROSS_INDEX'])


def expected_build(arch: Architecture, source: ValidatorSource,
                   cross: CrossBuildPins) -> ExpectedBuild:
    """Closed per-architecture supplier contracts; never accept arbitrary methods."""
    match arch:
        case 'amd64':
            return ExpectedBuild(
                (('image', source.image), ('architecture', arch),
                 ('targets', 'lib/util/libsudo_util.la plugins/sudoers/visudo'),
                 ('installation', 'none; artifact mode=0755; no capabilities or setuid')),
                forbidden_build_fields=('method', 'image_index', 'selected_manifest'))
        case 'arm64':
            selected = cross.image.partition('@')[2]
            return ExpectedBuild(
                (('image', cross.image), ('image_index', cross.index),
                 ('selected_manifest', selected), ('architecture', arch),
                 ('method', 'AMD64 cross GCC; source-built musl; explicit qemu-aarch64-static user mode')),
                (('cross_image', cross.image), ('cross_image_index', cross.index),
                 ('selected_manifest', selected),
                 ('method', 'arm64-cross-explicit-qemu-user; no binfmt; not native ARM64 kernel'),
                 ('header_VALIDATOR_IMAGE', 'native AMD64 build default only; not actual cross image')))
        case _:
            assert_never(arch)


def validator_inputs(directory: Path, arch: Architecture, source_env: ValidatorSource,
                     work: Path, expected: ExpectedBuild) -> ValidatorInputs:
    require(directory.is_dir() and not directory.is_symlink(), f'missing validator directory: {arch}')
    try:
        names = (f'visudo-linux-{arch}', f'visudo-linux-{arch}.sha256',
                 'visudo-LICENSE', 'visudo-SOURCE', 'visudo-BUILD', 'visudo-V.stdout')
        inputs = {name: read_regular(directory, name)[0] for name in names}
        stderr = directory / 'visudo-V.stderr'
        require(stderr.is_file() and not stderr.is_symlink() and stderr.stat().st_size == 0,
                f'validator version stderr must be empty: {arch}')
        binary = inputs[f'visudo-linux-{arch}']
        path = work / f'visudo-linux-{arch}'
        _ = path.write_bytes(binary)
        metadata = elf_metadata(path, arch)
        require(inputs[f'visudo-linux-{arch}.sha256'] ==
                f'{digest(binary)}  visudo-linux-{arch}\n'.encode(), f'validator checksum mismatch: {arch}')
        require(inputs['visudo-V.stdout'] ==
                f'visudo-linux-{arch} version 1.9.5p2\nvisudo-linux-{arch} grammar version 48\n'.encode(),
                f'validator version/grammar build trace mismatch: {arch}')
        require(inputs['visudo-SOURCE'].startswith(source_env.raw),
                f'validator source does not match frozen pinned source.env: {arch}')
        build_lines = inputs['visudo-BUILD'].decode('ascii').splitlines()
        for name, value in expected.build_fields:
            prefix = name + '='
            require([line for line in build_lines if line.startswith(prefix)] == [prefix + value],
                    f'validator build metadata mismatch: {arch} {prefix}')
        require(not any(line.startswith(name + '=') for name in expected.forbidden_build_fields
                        for line in build_lines), f'unknown validator build method metadata: {arch}')
        source_lines = inputs['visudo-SOURCE'].decode('utf-8').splitlines()
        for name, value in expected.source_fields:
            prefix = name + '='
            require([line for line in source_lines if line.startswith(prefix)] == [prefix + value],
                    f'validator source metadata mismatch: {arch} {prefix}')
        for name in ('visudo-SOURCE', 'visudo-LICENSE', 'visudo-BUILD'):
            # Upstream legal notices include UTF-8 names; retain their bytes.
            text = inputs[name].decode('utf-8')
            require(all(char in '\t\n\r' or char.isprintable() for char in text),
                    f'validator notice/provenance is not plain text: {arch} {name}')
        return ValidatorInputs(binary, inputs['visudo-LICENSE'], inputs['visudo-SOURCE'],
                               inputs['visudo-BUILD'], inputs['visudo-V.stdout'].decode('ascii'), metadata)
    except (OSError, UnicodeError) as error:
        raise BuildError(f'invalid or missing validator input for {arch}: {error}') from error


def json_file(path: Path, value: JsonValue) -> None:
    _ = path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='ascii')


def build(args: BuildOptions) -> None:
    match args.selection:
        case ReleaseTag(tag=selected):
            release: str | None = selected
            tag = selected
        case SnapshotLabel(label=selected):
            release = None
            tag = 'snapshot-' + selected
        case _:
            assert_never(args.selection)
    require(valid_tag(selected), 'invalid release tag or snapshot label')
    require(valid_tag(tag), 'invalid snapshot tag length')
    output, evidence = new_destination(args.output), new_destination(args.evidence)
    require(output != evidence and output not in evidence.parents and evidence not in output.parents,
            'evidence must be outside the release asset directory')
    # Evidence cannot appear inside the frozen public allowlist during capture.
    require(ROOT not in evidence.parents and ROOT not in output.parents,
            'output/evidence must be outside the source checkout')
    with tempfile.TemporaryDirectory(prefix='.askdo-release.', dir=output.parent) as temporary:
        stage = Path(temporary)
        assets, source, proof = stage / 'assets', stage / 'source', stage / 'proof'
        for directory in (assets, source, proof):
            directory.mkdir()
        head, dirty, files, archive_sha = freeze(proof, release)
        provenance = Provenance(
            mode='RELEASE' if release else 'SNAPSHOT', release_ready=False, bundle_complete=False,
            base_commit=head, release=tag, dirty_checkout=dirty, repository='jeremyakers/askdo',
            source_archive_sha256=archive_sha,
            source_meaning='exact clean tagged HEAD' if release else
            'base commit ONLY; source.tar identifies actual SNAPSHOT bytes, not a release commit',
            source_files=MappingProxyType({name: digest(value.data) for name, value in files.items()}))
        json_file(proof / 'provenance.json', provenance.json_value())
        # Keep failed-attempt source evidence too, but no incomplete release output.
        # Copy through a separate sibling staging directory for cross-filesystem parents.
        with tempfile.TemporaryDirectory(prefix='.askdo-proof.', dir=evidence.parent) as proof_tmp:
            proof_stage = Path(proof_tmp) / 'evidence'
            _ = shutil.copytree(proof, proof_stage)
            publish(proof_stage, evidence)
        for name, (data, mode) in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            _ = path.write_bytes(data)
            path.chmod(mode)
        metadata: dict[str, ArtifactRecord] = {}
        validators: dict[Architecture, ValidatorInputs] = {}
        validator_records: dict[str, ArtifactRecord] = {}
        source_env = parse_validator_source(files['contrib/validator/source.env'].data)
        cross_pins = parse_cross_pins(files['scripts/build-sudo-validator-arm64.sh'].data)
        validator_dirs: Mapping[Architecture, Path] = {
            'amd64': args.validator_amd64, 'arm64': args.validator_arm64}
        for arch, directory in validator_dirs.items():
            validated = validator_inputs(directory.absolute(), arch, source_env, assets,
                                         expected_build(arch, source_env, cross_pins))
            validators[arch] = validated
            binary = validated.binary
            record = ArtifactRecord(digest(binary), len(binary), validated.elf,
                                    version_trace=validated.version_trace,
                                    validation='ELF/static/checksum and supplier build records; not source-to-binary proof')
            metadata['visudo-linux-' + arch] = record
            validator_records[arch] = record
            json_file(evidence / 'validator-inputs.json',
                      {name: item.json_value() for name, item in validator_records.items()})
            (assets / ('visudo-linux-' + arch)).chmod(0o755)
        require(validators['amd64'].license == validators['arm64'].license,
                'validator licenses differ across architectures')
        _ = (assets / 'visudo-LICENSE').write_bytes(validators['amd64'].license)
        notice = b'askdo standalone validator per-architecture supplier provenance\n'
        for arch, inputs in validators.items():
            notice += f'\n===== linux/{arch} visudo-SOURCE =====\n'.encode() + inputs.source
            notice += f'\n===== linux/{arch} visudo-BUILD =====\n'.encode() + inputs.build
            notice += f'\nartifact=visudo-linux-{arch} sha256={digest(inputs.binary)}\n'.encode()
            notice += inputs.version_trace.encode('ascii')
        _ = (assets / 'visudo-SOURCE').write_bytes(notice)
        for name, original in COMMON.items():
            _ = (assets / name).write_bytes(files[original][0])
        env = os.environ.copy()
        env.update(CGO_ENABLED='0', GOTOOLCHAIN='local', GOFLAGS='', GOWORK='off', GOEXPERIMENT='',
                   GOAMD64='v1', GOARM64='v8.0', GOOS='linux', GOENV='off')
        for arch in ARCHES:
            env['GOARCH'] = arch
            for name in ('askdo', 'askdo-launch'):
                asset = f'{name}-linux-{arch}'
                path = assets / asset
                _ = command(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(path), './cmd/' + name],
                        cwd=source, env=env)
                info = command(['go', 'version', '-m', str(path)]).decode()
                for setting in ('CGO_ENABLED=0', 'GOOS=linux', 'GOARCH=' + arch):
                    require('\tbuild\t' + setting in info, f'incorrect Go build metadata: {asset} {setting}')
                require('-tags=' not in info and 'askdo_fleet_fixture' not in info,
                        f'test build tag in release asset: {asset}')
                binary = path.read_bytes()
                metadata[asset] = ArtifactRecord(digest(binary), len(binary), elf_metadata(path, arch), info)
                _ = (assets / (asset + '.sha256')).write_text(f'{digest(path.read_bytes())}  {asset}\n', encoding='ascii')
        expected = set(COMMON) | {'visudo-LICENSE', 'visudo-SOURCE'}
        for arch in ARCHES:
            expected.add('visudo-linux-' + arch)
            for name in ('askdo', 'askdo-launch'):
                expected.update({f'{name}-linux-{arch}', f'{name}-linux-{arch}.sha256'})
        require({path.name for path in assets.iterdir()} == expected and len(expected) == 21,
                'release payload inventory mismatch')
        manifest = ['askdo-install-v1', 'repository jeremyakers/askdo', 'release ' + tag,
                    'source ' + head, 'validator 1.9.5p2 48']
        for name in sorted(expected):
            data = (assets / name).read_bytes()
            require(0 < len(data) <= MAX_ASSET, f'asset outside consumer size bound: {name}')
            previous = metadata.get(name)
            metadata[name] = (replace(previous, sha256=digest(data), size=len(data))
                              if previous is not None else ArtifactRecord(digest(data), len(data)))
            manifest.append(f'file {name} {digest(data)} {len(data)}')
        text = '\n'.join(manifest) + '\n'
        require(len(text) <= 16384 and max(map(len, manifest)) <= 512, 'manifest exceeds consumer bounds')
        _ = (assets / 'install-manifest.v1').write_text(text, encoding='ascii')
        json_file(evidence / 'artifacts.json', {name: item.json_value() for name, item in metadata.items()})
        if release:
            clean_release(release, git('rev-parse', 'HEAD').decode().strip(),
                          git('status', '--porcelain=v1', '-z', '--untracked-files=all'))
            require(git('rev-parse', 'HEAD').decode().strip() == head, 'release HEAD drift after freeze')
        provenance = replace(provenance, bundle_complete=True, release_ready=bool(release))
        json_file(evidence / 'provenance.json', provenance.json_value())
        publish(assets, output)
    print(f'{provenance.mode} bundle: {output}')
    print(f'source base={head} archive_sha256={archive_sha}; evidence={evidence}')
    if not release:
        print('TEST ONLY SNAPSHOT: not approved for release publication; source is base commit, not dirty bytes')


def parse_options(argv: Sequence[str] | None = None) -> BuildOptions:
    """Contain argparse's dynamic Namespace at one typed CLI boundary."""
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument('output', type=Path, help='new directory outside the checkout')
    mode = parser.add_mutually_exclusive_group(required=True)
    _ = mode.add_argument('--release', dest='selection', type=ReleaseTag, help='existing local tag at clean exact HEAD')
    _ = mode.add_argument('--snapshot', dest='selection', type=SnapshotLabel, help='explicit TEST ONLY dirty-source snapshot label')
    _ = parser.add_argument('--validator-amd64', type=Path, required=True, help='prebuilt validator builder output')
    _ = parser.add_argument('--validator-arm64', type=Path, required=True, help='prebuilt validator builder output')
    _ = parser.add_argument('--evidence', type=Path, required=True, help='new provenance directory outside checkout')
    # Argument actions construct these exact types; typed namespace declarations
    # below make the stdlib parser boundary explicit without leaking Namespace.
    parsed = ParsedArguments()
    _ = parser.parse_args(argv, namespace=parsed)
    return BuildOptions(parsed.output, parsed.evidence, parsed.validator_amd64,
                        parsed.validator_arm64, parsed.selection)


class ParsedArguments(argparse.Namespace):
    """Fixed parser-owned fields; never passed to production build functions."""

    output: Path
    evidence: Path
    validator_amd64: Path
    validator_arm64: Path
    selection: ReleaseTag | SnapshotLabel

    def __init__(self) -> None:
        """Temporary parser storage; required actions overwrite every field."""
        super().__init__()
        self.output = Path()
        self.evidence = Path()
        self.validator_amd64 = Path()
        self.validator_arm64 = Path()
        self.selection = SnapshotLabel('')


def main() -> int:
    def interrupted(signum: int, _frame: FrameType | None) -> NoReturn:
        raise BuildError(f'interrupted by signal {signum}')

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        _ = signal.signal(signum, interrupted)
    try:
        build(parse_options())
    except (BuildError, OSError) as error:
        print(f'build-release: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
