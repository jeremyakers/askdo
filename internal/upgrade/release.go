// Package upgrade implements the release manifest contract that install.sh
// shares with install-manifest.v1. The manifest is data only: it is parsed,
// verified and used to download release assets, but never executed or
// evaluated.
package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repository identity and limits, mirroring install.sh's install-manifest.v1
// handling.
const (
	manifestMagic    = "askdo-install-v1"
	repoName         = "jeremyakers/askdo"
	manifestMaxBytes = 16384
	manifestLineMax  = 512
	assetMaxBytes    = 536870912
	validatorVersion = "1.9.5p2"
	validatorLevel   = "48"

	// Cap for the GitHub release-list API response.
	apiListMaxBytes = 4 << 20
)

// requiredAssets is the closed inventory install.sh demands: every name must
// appear exactly once, nothing outside it may appear. This mirrors
// install.sh's COMMON list plus the binary, helper, checksum and visudo
// entries.
var requiredAssets = map[string]bool{
	"install.sh":                      true,
	"uninstall.sh":                    true,
	"askdo-config.example.json":       true,
	"gateway-config.example.json":     true,
	"host-config.example.json":        true,
	"askdo.service":                   true,
	"askdo-gateway.service":           true,
	"askdo.sudoers":                   true,
	"LICENSE":                         true,
	"askdo-linux-amd64":               true,
	"askdo-launch-linux-amd64":        true,
	"askdo-linux-arm64":               true,
	"askdo-launch-linux-arm64":        true,
	"askdo-linux-amd64.sha256":        true,
	"askdo-launch-linux-amd64.sha256": true,
	"askdo-linux-arm64.sha256":        true,
	"askdo-launch-linux-arm64.sha256": true,
	"visudo-linux-amd64":              true,
	"visudo-linux-arm64":              true,
	"visudo-LICENSE":                  true,
	"visudo-SOURCE":                   true,
}

// Manifest is a parsed install-manifest.v1.
type Manifest struct {
	Tag          string
	SourceCommit string
	// Digest binds the exact parsed bytes, including any trailing newline.
	Digest string
	Assets map[string]Asset
}

// Asset is one verified inventory entry.
type Asset struct {
	Name   string
	SHA256 string
	Size   int64
}

var (
	lineFormatRE   = regexp.MustCompile(`^[!-~]+( [!-~]+)*$`)
	tagFormatRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	digestFormatRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sizeFormatRE   = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

func forbiddenTag(tag string) bool {
	return tag == "latest" || tag == "main" || tag == "master"
}

func isHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ParseManifest parses install-manifest.v1 data with install.sh's exact
// schema: at most 16KiB, whose first line is askdo-install-v1, followed by
// space-separated printable-ASCII lines of 512 bytes or less carrying the
// repository, release, source and validator fields and the complete closed
// asset inventory exactly once each. An empty expectedTag accepts any valid
// tag; a non-empty expectedTag must match the manifest's release tag.
func ParseManifest(r io.Reader, expectedTag string) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, manifestMaxBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read release manifest: %w", err)
	}
	if len(data) > manifestMaxBytes {
		return Manifest{}, fmt.Errorf("release manifest too large: %d bytes exceeds %d", len(data), manifestMaxBytes)
	}
	text := string(data)
	if trimmed, hadNewline := strings.CutSuffix(text, "\n"); hadNewline {
		text = trimmed
	}
	if text == "" {
		return Manifest{}, fmt.Errorf("release manifest: empty")
	}
	if lines := strings.Split(text, "\n"); lines[0] != manifestMagic {
		return Manifest{}, fmt.Errorf("release manifest: first line must be exactly %#v", manifestMagic)
	}
	manifest, err := parseManifestLines(strings.Split(text, "\n"), expectedTag)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(data)
	manifest.Digest = hex.EncodeToString(sum[:])
	return manifest, nil
}

func parseManifestLines(lines []string, expectedTag string) (Manifest, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("invalid release manifest: "+format, args...)
	}
	manifest := Manifest{Assets: make(map[string]Asset, len(requiredAssets))}
	seenRepository, seenRelease, seenSource, seenValidator := false, false, false, false
	seen := make(map[string]bool, len(requiredAssets))

	for i, line := range lines[1:] {
		lineNo := i + 2
		if len(line) > manifestLineMax {
			return Manifest{}, invalid("line %d exceeds %d bytes", lineNo, manifestLineMax)
		}
		if !lineFormatRE.MatchString(line) {
			return Manifest{}, invalid("line %d is not strictly space-separated printable ASCII", lineNo)
		}
		fields := strings.Split(line, " ")
		switch fields[0] {
		case "repository":
			if len(fields) != 2 || fields[1] != repoName || seenRepository {
				return Manifest{}, invalid("line %d: repository must be %s exactly once", lineNo, repoName)
			}
			seenRepository = true
		case "release":
			if len(fields) != 2 || seenRelease {
				return Manifest{}, invalid("line %d: release must be a single tag exactly once", lineNo)
			}
			tag := fields[1]
			if !tagFormatRE.MatchString(tag) || forbiddenTag(tag) {
				return Manifest{}, invalid("line %d: release tag %q is not a valid published release tag", lineNo, tag)
			}
			if expectedTag != "" && tag != expectedTag {
				return Manifest{}, invalid("release tag %q does not match expected tag %q", tag, expectedTag)
			}
			seenRelease = true
			manifest.Tag = tag
		case "source":
			if len(fields) != 2 || seenSource {
				return Manifest{}, invalid("line %d: source must be a 40 hex digit commit exactly once", lineNo)
			}
			if len(fields[1]) != 40 || !isHexDigits(fields[1]) {
				return Manifest{}, invalid("line %d: source commit %q must be exactly 40 lowercase hex digits", lineNo, fields[1])
			}
			seenSource = true
			manifest.SourceCommit = fields[1]
		case "validator":
			if len(fields) != 3 || fields[1] != validatorVersion || fields[2] != validatorLevel || seenValidator {
				return Manifest{}, invalid("line %d: validator must be %q %q exactly once", lineNo, validatorVersion, validatorLevel)
			}
			seenValidator = true
		case "file":
			if len(fields) != 4 {
				return Manifest{}, invalid("line %d: file entry needs exactly 4 fields", lineNo)
			}
			name, sha, sizeText := fields[1], fields[2], fields[3]
			if !requiredAssets[name] {
				return Manifest{}, invalid("line %d: asset %q is not in the required inventory", lineNo, name)
			}
			if seen[name] {
				return Manifest{}, invalid("line %d: asset %q appears more than once", lineNo, name)
			}
			if !digestFormatRE.MatchString(sha) {
				return Manifest{}, invalid("line %d: asset %q digest must be 64 lowercase hex digits", lineNo, name)
			}
			if !sizeFormatRE.MatchString(sizeText) {
				return Manifest{}, invalid("line %d: asset %q size %q must be a positive decimal without leading zeros", lineNo, name, sizeText)
			}
			size, err := strconv.ParseInt(sizeText, 10, 64)
			if err != nil {
				return Manifest{}, invalid("line %d: asset %q size %q is not representable", lineNo, name, sizeText)
			}
			if size > assetMaxBytes {
				return Manifest{}, invalid("line %d: asset %q size %d exceeds %d", lineNo, name, size, assetMaxBytes)
			}
			seen[name] = true
			manifest.Assets[name] = Asset{Name: name, SHA256: sha, Size: size}
		default:
			return Manifest{}, invalid("line %d: unrecognized field %q", lineNo, fields[0])
		}
	}
	for name := range requiredAssets {
		if !seen[name] {
			return Manifest{}, invalid("asset %q is missing from the inventory", name)
		}
	}
	if !seenRepository {
		return Manifest{}, invalid("repository %s is missing", repoName)
	}
	if !seenRelease {
		return Manifest{}, invalid("release tag is missing")
	}
	if !seenSource {
		return Manifest{}, invalid("source commit is missing")
	}
	if !seenValidator {
		return Manifest{}, invalid("validator entry is missing")
	}
	return manifest, nil
}

// VerifyAsset checks that the named asset, on disk at path, has exactly the
// size and SHA-256 digest the manifest declares.
func (m Manifest) VerifyAsset(name, path string) error {
	asset, ok := m.Assets[name]
	if !ok {
		return fmt.Errorf("asset %q is not in the release manifest", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat asset %s: %w", name, err)
	}
	if info.Size() != asset.Size {
		return fmt.Errorf("asset %s is %d bytes, manifest requires %d", name, info.Size(), asset.Size)
	}
	digest, err := sha256HexFile(path)
	if err != nil {
		return fmt.Errorf("hash asset %s: %w", name, err)
	}
	if digest != asset.SHA256 {
		return fmt.Errorf("asset %s digest mismatch: manifest requires %s", name, asset.SHA256)
	}
	return nil
}

// VerifyChecksumRecord requires the checksum record at recordPath for
// binaryName to be exactly "<binary sha256>  <binary name>\n" as its manifest
// entry dictates, with no extra bytes.
func (m Manifest) VerifyChecksumRecord(binaryName, recordPath string) error {
	binary, ok := m.Assets[binaryName]
	if !ok {
		return fmt.Errorf("asset %q is not in the release manifest", binaryName)
	}
	want := binary.SHA256 + "  " + binaryName + "\n"
	f, err := os.Open(recordPath)
	if err != nil {
		return fmt.Errorf("open checksum record for %s: %w", binaryName, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(len(want)+1)))
	if err != nil {
		return fmt.Errorf("read checksum record for %s: %w", binaryName, err)
	}
	if len(data) != len(want) || !bytes.Equal(data, []byte(want)) {
		return fmt.Errorf("checksum record for %s does not match the manifest entry", binaryName)
	}
	return nil
}

// ELF64 little-endian machine numbers for the architectures releases ship.
const (
	elfMachineAMD64  uint16 = 0x3e // EM_X86_64, file bytes 3e 00
	elfMachineARM64  uint16 = 0xb7 // EM_AARCH64, file bytes b7 00
	elfHeaderMinSize        = 20
)

var elfHeaderPrefix = []byte{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01}

// VerifyELF requires the file at path to be an ELF64 little-endian image
// whose CPU machine field matches the name's amd64 or arm64 suffix, exactly
// like install.sh's header check. Nothing is ever executed.
func (m Manifest) VerifyELF(name, path string) error {
	var expected uint16
	switch {
	case strings.HasSuffix(name, "-amd64"):
		expected = elfMachineAMD64
	case strings.HasSuffix(name, "-arm64"):
		expected = elfMachineARM64
	default:
		return fmt.Errorf("asset %q does not name an amd64 or arm64 ELF", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer f.Close()
	header := make([]byte, elfHeaderMinSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return fmt.Errorf("asset %s is not a full ELF header: %w", name, err)
	}
	if !bytes.Equal(header[0:7], elfHeaderPrefix) {
		return fmt.Errorf("asset %s is not an ELF64 little-endian (version 1) image", name)
	}
	if machine := binary.LittleEndian.Uint16(header[18:20]); machine != expected {
		return fmt.Errorf("asset %s ELF architecture mismatch: machine %#04x != expected %#04x", name, machine, expected)
	}
	return nil
}

// DownloadRelease downloads a release from the jeremyakers/askdo GitHub
// repository named by repoBaseURL (a base whose path names the repository,
// e.g. https://github.com/jeremyakers/askdo) into dir. An explicit non-empty
// tag fetches that tag's install-manifest.v1; an empty tag resolves the
// newest published non-draft release (newest stable first, else newest
// prerelease) through the GitHub release-list API once. Only the current
// GOARCH's binary and askdo-launch helper plus their .sha256 records are
// downloaded alongside the raw manifest. Every asset byte stream is bounded
// by its manifest-declared size and verified by digest, size, checksum-record
// content and ELF architecture before an atomic temp-file rename into dir.
// On any failure no partial file remains in dir. Downloads never execute
// anything. The returned Manifest carries the resolved tag and raw digest.
func DownloadRelease(ctx context.Context, client *http.Client, repoBaseURL, tag, dir string) (Manifest, error) {
	if dir == "" {
		return Manifest{}, fmt.Errorf("release download needs a target directory")
	}
	base, err := normalizeRepoBase(repoBaseURL)
	if err != nil {
		return Manifest{}, err
	}
	if tag == "" {
		tag, err = resolveNewestRelease(ctx, scopedClient(base, client), base)
		if err != nil {
			return Manifest{}, err
		}
	} else if !tagFormatRE.MatchString(tag) || forbiddenTag(tag) {
		return Manifest{}, fmt.Errorf("release tag %q is not a valid published release tag", tag)
	}

	manifestURL := base.JoinPath("releases", "download", tag, "install-manifest.v1")
	data, err := getLimited(ctx, scopedClient(base, client), manifestURL, manifestMaxBytes, "")
	if err != nil {
		return Manifest{}, err
	}
	manifest, err := ParseManifest(bytes.NewReader(data), tag)
	if err != nil {
		return Manifest{}, err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("create release directory: %w", err)
	}
	binaries := [2]string{"askdo-linux-" + runtime.GOARCH, "askdo-launch-linux-" + runtime.GOARCH}
	for _, binaryName := range binaries {
		if _, ok := manifest.Assets[binaryName]; !ok {
			return Manifest{}, fmt.Errorf("release manifest has no asset %q for this platform", binaryName)
		}
	}

	// Fetch and verify every stream before anything is committed: bounded by
	// each manifest-declared size, then digest, size and checksum-record
	// checks in memory.
	fetched := make(map[string][]byte, 2)
	for _, binaryName := range binaries {
		for _, assetName := range []string{binaryName, binaryName + ".sha256"} {
			asset := manifest.Assets[assetName]
			data, err := getLimited(ctx, scopedClient(base, client), base.JoinPath("releases", "download", manifest.Tag, assetName), asset.Size, "")
			if err != nil {
				return Manifest{}, fmt.Errorf("download %s: %w", assetName, err)
			}
			if err := verifyAssetBytes(asset, data); err != nil {
				return Manifest{}, err
			}
			fetched[assetName] = data
		}
		recordAsset := manifest.Assets[binaryName]
		wantRecord := recordAsset.SHA256 + "  " + binaryName + "\n"
		if !bytes.Equal(fetched[binaryName+".sha256"], []byte(wantRecord)) {
			return Manifest{}, fmt.Errorf("checksum record for %s does not match the manifest entry", binaryName)
		}
	}

	// Commit stage: temp writes, ELF architecture checks, then atomic
	// renames; any failure removes every staged temp and rolled-back final.
	var staged, committed []string
	fail := func(err error) error {
		for _, temp := range staged {
			os.Remove(temp)
		}
		for _, final := range committed {
			os.Remove(final)
		}
		return err
	}
	manifestTemp, err := writeTemp(dir, "install-manifest.v1", data, 0o644)
	if err != nil {
		return Manifest{}, fail(err)
	}
	staged = append(staged, manifestTemp)
	manifestPath := path.Join(dir, "install-manifest.v1")
	if err := os.Rename(manifestTemp, manifestPath); err != nil {
		return Manifest{}, fail(fmt.Errorf("stage install-manifest.v1: %w", err))
	}
	committed = append(committed, manifestPath)
	for _, binaryName := range binaries {
		recordName := binaryName + ".sha256"
		binaryTemp, err := writeTemp(dir, binaryName, fetched[binaryName], 0o755)
		if err != nil {
			return Manifest{}, fail(err)
		}
		staged = append(staged, binaryTemp)
		recordTemp, err := writeTemp(dir, recordName, fetched[recordName], 0o644)
		if err != nil {
			return Manifest{}, fail(err)
		}
		staged = append(staged, recordTemp)
		if err := manifest.VerifyELF(binaryName, binaryTemp); err != nil {
			return Manifest{}, fail(err)
		}
		binaryPath := path.Join(dir, binaryName)
		if err := os.Rename(binaryTemp, binaryPath); err != nil {
			return Manifest{}, fail(fmt.Errorf("stage %s: %w", binaryName, err))
		}
		committed = append(committed, binaryPath)
		recordPath := path.Join(dir, recordName)
		if err := os.Rename(recordTemp, recordPath); err != nil {
			return Manifest{}, fail(fmt.Errorf("stage %s: %w", recordName, err))
		}
		committed = append(committed, recordPath)
	}
	return manifest, nil
}

func verifyAssetBytes(asset Asset, data []byte) error {
	if int64(len(data)) != asset.Size {
		return fmt.Errorf("asset %s delivered %d bytes, manifest requires %d", asset.Name, len(data), asset.Size)
	}
	sum := sha256.Sum256(data)
	if digest := hex.EncodeToString(sum[:]); digest != asset.SHA256 {
		return fmt.Errorf("asset %s digest mismatch: manifest requires %s", asset.Name, asset.SHA256)
	}
	return nil
}

func writeTemp(dir, name string, data []byte, mode os.FileMode) (string, error) {
	temp, err := os.CreateTemp(dir, "."+name+".temp-*")
	if err != nil {
		return "", fmt.Errorf("stage %s: %w", name, err)
	}
	tempName := temp.Name()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		os.Remove(tempName)
		return "", fmt.Errorf("stage %s: %w", name, err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		os.Remove(tempName)
		return "", fmt.Errorf("stage %s: %w", name, err)
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return "", fmt.Errorf("stage %s: %w", name, err)
	}
	if err := os.Chmod(tempName, mode); err != nil {
		os.Remove(tempName)
		return "", fmt.Errorf("stage %s: %w", name, err)
	}
	return tempName, nil
}

// normalizeRepoBase validates repoBaseURL: a github.com or api.github.com
// host (HTTPS; loopback/localhost HTTP for test servers) whose path names
// the jeremyakers/askdo repository. Any other host is refused before any
// request, even over HTTPS with the correct repository path.
func normalizeRepoBase(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("release repository base %q: %w", raw, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("release repository base %q needs a host", raw)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !loopbackHost(parsed.Hostname()) {
			return nil, fmt.Errorf("release repository base %q must use HTTPS", raw)
		}
	default:
		return nil, fmt.Errorf("release repository base %q must use HTTPS", raw)
	}
	if !allowedRepoHost(parsed) {
		return nil, fmt.Errorf("release repository base %q must be a github.com or api.github.com host", raw)
	}
	trimmed := strings.Trim(parsed.Path, "/")
	if trimmed != repoName && !(parsed.Host == "api.github.com" && trimmed == "repos/"+repoName) {
		return nil, fmt.Errorf("release repository base %q must point at %s", raw, repoName)
	}
	return parsed, nil
}

// allowedRepoHost admits only the real GitHub hosts (port-less github.com and
// api.github.com) or a loopback/localhost host for httptest servers; an
// arbitrary HTTPS host must not serve the release even with the right path.
func allowedRepoHost(parsed *url.URL) bool {
	return parsed.Hostname() == "github.com" && parsed.Port() == "" ||
		parsed.Hostname() == "api.github.com" && parsed.Port() == "" ||
		loopbackHost(parsed.Hostname())
}

func loopbackHost(hostname string) bool {
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}
	return hostname == "localhost"
}

// scopedClient wraps client (or a default) with the redirect policy: a hop
// must be HTTPS and either stay on the repository's host or remain on a
// GitHub-owned release host; HTTP downgrades and foreign hosts are refused.
func scopedClient(base *url.URL, client *http.Client) *http.Client {
	var scoped http.Client
	if client != nil {
		scoped = *client
	}
	scoped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !redirectAllowed(req.URL, base) {
			return fmt.Errorf("release download refused redirect to %s", req.URL.Scheme+"://"+req.URL.Host)
		}
		return nil
	}
	return &scoped
}

func redirectAllowed(target, base *url.URL) bool {
	if target.Host == base.Host {
		// Same-origin: HTTPS, or HTTP only on a loopback test origin.
		return target.Scheme == "https" || (target.Scheme == "http" && base.Scheme == "http" && loopbackHost(base.Hostname()))
	}
	return target.Scheme == "https" && isGitHubHost(target.Hostname())
}

// isGitHubHost admits only GitHub's own release asset and API hosts for a
// cross-host hop: github.com release URLs redirect to the release CDN on
// *.githubusercontent.com, as any real release download does.
func isGitHubHost(hostname string) bool {
	return hostname == "github.com" || hostname == "api.github.com" ||
		strings.HasSuffix(hostname, ".githubusercontent.com")
}

func getLimited(ctx context.Context, client *http.Client, target *url.URL, limit int64, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", target, err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", target, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", target, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: %d bytes exceeds the %d byte limit", target, len(data), limit)
	}
	return data, nil
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
}

// releasesAPIURL derives the GitHub release-list URL for the repository base:
// a github.com base maps to api.github.com, an api.github.com base is used
// as-is, and any other (test) base serves the list alongside release assets.
func releasesAPIURL(base *url.URL) *url.URL {
	api := *base
	api.RawQuery = "per_page=100"
	api.Fragment = ""
	api.RawFragment = ""
	if base.Host == "github.com" {
		api.Host = "api.github.com"
		api.Path = "/repos/" + repoName + "/releases"
	} else {
		api.Path = path.Join(base.Path, "releases")
	}
	return &api
}

// resolveNewestRelease makes exactly one GitHub release-list API call to
// resolve the newest published non-draft release: the newest stable tag when
// one exists, else the newest prerelease. Draft releases are never selected.
func resolveNewestRelease(ctx context.Context, client *http.Client, base *url.URL) (string, error) {
	apiURL := releasesAPIURL(base)
	data, err := getLimited(ctx, client, apiURL, apiListMaxBytes, "application/vnd.github+json")
	if err != nil {
		return "", fmt.Errorf("resolve newest release: %w", err)
	}
	var releases []githubRelease
	if err := json.Unmarshal(data, &releases); err != nil {
		return "", fmt.Errorf("resolve newest release: %w", err)
	}
	var newest, newestStable githubRelease
	for _, release := range releases {
		release := release
		if release.Draft || release.TagName == "" || !tagFormatRE.MatchString(release.TagName) || forbiddenTag(release.TagName) {
			continue
		}
		if newest.TagName == "" || release.PublishedAt.After(newest.PublishedAt) {
			newest = release
		}
		if !release.Prerelease && (newestStable.TagName == "" || release.PublishedAt.After(newestStable.PublishedAt)) {
			newestStable = release
		}
	}
	switch {
	case newestStable.TagName != "":
		return newestStable.TagName, nil
	case newest.TagName != "":
		return newest.TagName, nil
	default:
		return "", fmt.Errorf("resolve newest release: no published release available")
	}
}

func sha256HexFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
