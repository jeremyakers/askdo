# Installation details and DSM notes

The [README](../README.md) quickstart covers the everyday install. This page
documents how the release installer pins and verifies its assets, and the
additional behavior on Synology DSM. It is a reference for advanced setups,
not an alternative install path.

## How the installer pins assets

- The `install.sh` published with a release defaults to its own tag; no
  arguments are needed. `--version TAG` (or `ASKDO_VERSION`) selects any
  other published release tag — never a source branch.
- The `releases/latest/...` URL selects the newest stable (non-prerelease)
  release only, with no prerelease fallback; prefer the exact-tag URL shown
  in the README while only release candidates exist.
- One closed `install-manifest.v1` pins the tag, source commit, installer,
  both architecture inventories and asset hashes/sizes. All subsequent
  assets use that exact tag.
- A local installer must byte-match the selected release installer except
  for its line-5 `VERSION` default; any other difference refuses rather than
  silently executing different policy.
- `ASKDO_SOURCE_DIR` is obsolete and rejected. The installer never compiles
  on the destination, falls back to source, or starts/stops services.
- Manifest/hash binding relies on the owner's HTTPS release publication; it
  is not a signature or reproducible-build claim.

## Synology DSM specifics

The same installer entry point recognizes DSM metadata/native-tool paths and
uses native Synology role operations instead of ordinary Linux steps.

- DSM uses the vendor `/usr/bin/python3` and `synoacltool`. Ordinary Linux
  installation needs no Python.
- A checked canonical native `visudo` may be used when it matches the
  installed sudo version/grammar. Otherwise the verified release validator
  runs temporarily from root-controlled executable staging (never `/tmp`),
  only for the exact supported sudo 1.9.5p2/grammar48 runtime. It never
  replaces sudo, PAM or plugins and installs no compiler or package-manager
  dependency.
- The installer refuses unsupported bundled-parser configurations: custom
  plugins, plugin search paths, alternate sudoers files and LDAP/SSSD sudoers
  sources are not treated as stock local sudoers. Only bounded trusted
  default/standard configuration is accepted, and emitted parser warnings
  fail closed. The real upstream amd64 checker accepts an unrelated missing
  `@includedir` as empty, matching documented upstream semantics.
- The installer separately requires its own trusted `/etc/sudoers.d`. It
  accepts only native Linux-mode ACL metadata combined with absent or
  unsupported POSIX extended ACLs, and refuses unknown, unsafe or
  inconsistent metadata. No native NAS policy or authentication acceptance
  is claimed.

### The DSM reviewer account

- Reviewer creation uses `expired=1` on the first native call, privilege
  zero and a **public, nonsecret placeholder password**. The installer
  verifies `Expired=true`, native/NSS UID consistency and
  non-admin/non-submitter groups before installing the grant.
- **Do not re-enable this service account:** its placeholder password is
  public. The installer never enables, resets the password of, or repairs an
  existing reviewer. Disabled state is not a claim of share/application ACL
  isolation.
- The fixed `askdo-review` execution group is independent of the native NSS
  primary group (`users`, GID 100).

### DSM installation caveats

- Native role creation/deletion, disabled-account authentication enforcement
  and empty-group behavior still require approved first-install acceptance
  on a real NAS; local native-command adapters test orchestration only, not
  the NAS runtime.
- Ambiguous native failures or changed rollback dependencies retain state
  and a private staging journal for manual inspection; rollback never
  recursively erases a native-created home.
- On DSM, `uninstall.sh --purge --yes` retains native identities and
  `/var/lib/askdo-review`, because name-only deletion cannot prove that a
  previous installer created them.
- Neither install path enables or starts services.

For post-install configuration, see [configuration](configuration.md); for
installing alongside another service, see [clean cutover](clean-cutover.md).