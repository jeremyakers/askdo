package upgrade

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestResolveNewestReleaseUsesPublicationDateNotCommitDate(t *testing.T) {
	for _, prerelease := range []bool{false, true} {
		t.Run(fmt.Sprint(prerelease), func(t *testing.T) {
			// Given: publication order deliberately opposes target-commit creation order.
			older, newer := "v3.2.0", "v3.2.1"
			if prerelease {
				older, newer = "v3.2.1-rc.1", "v3.2.1-rc.2"
			}
			body := fmt.Sprintf(`[{"tag_name":%q,"prerelease":%t,"created_at":"2026-10-26T00:00:00Z","published_at":"2026-10-26T01:00:00Z"},{"tag_name":%q,"prerelease":%t,"created_at":"2025-01-01T00:00:00Z","published_at":"2026-10-27T01:00:00Z"}]`, older, prerelease, newer, prerelease)
			calls := 0
			client := &http.Client{Transport: releaseMemoryTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			base, _ := url.Parse("https://github.com/jeremyakers/askdo")
			// When
			got, err := resolveNewestRelease(t.Context(), client, base)
			// Then: stable priority/prerelease fallback are unchanged; publication date wins.
			if err != nil || got != newer || calls != 1 {
				t.Fatalf("release=%q want=%q calls=%d err=%v", got, newer, calls, err)
			}
		})
	}
}

// rc21Manifest is the verbatim install-manifest.v1 published with
// v1.0.0-rc.21: its schema, digests and sizes must keep parsing.
const rc21Manifest = `askdo-install-v1
repository jeremyakers/askdo
release v1.0.0-rc.21
source 25a64b16e2adcc3ab8eb1a96d27f0509a99af680
validator 1.9.5p2 48
file LICENSE 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986 35149
file askdo-config.example.json 689360826ff21fe23eedf60d0da83bf831cc412b78be3d8380fe163c7a0a8cea 1051
file askdo-gateway.service a13cafc22c0213a27d3402f80bbd0f501e7268c558590ef295aacf99fd2bf5b4 317
file askdo-launch-linux-amd64 6326aa020b5f9eca79c35eed72807afb224ac3f8146722e54ee8805d8a645a8d 5334672
file askdo-launch-linux-amd64.sha256 31a57ec44fa10e93c4b108e51a960edd5ea3d3e788c027f60f15701ca2cf9f38 91
file askdo-launch-linux-arm64 854aef9945fed9c31b2ee5e52ef3f25158c68ce968a8ca2d436876ef45501feb 5067609
file askdo-launch-linux-arm64.sha256 714ebedf6b7cd1f41af569d2be27eb8acaf14a0b952aa2113adbe51ebdb1022c 91
file askdo-linux-amd64 eb138aad2fde7b4bd925215d132a128f252561944a051efdc3c9367e976cb359 22095547
file askdo-linux-amd64.sha256 b2fcddb72e2f6de0c48a579624c61cdba222e586ca1c7fec90e22b00eb1b481b 84
file askdo-linux-arm64 845ef5b4dfe3f854328f541cf7f2a0922e9df8108f2cbd04782edf064d206251 20792563
file askdo-linux-arm64.sha256 1055f62690203675eb3d56d0ddd829ca54cbd08c5e86fc8004d6ac5472ce1f7a 84
file askdo.service 97d226bfc4821da2dd4da9394dc40f64e8743f80615eb91b694f2e338a9d3a41 220
file askdo.sudoers 47a63d1ceeb5fc2607471c9e742c6d03ccc3a03b2026ad5720da98a26bbd49d1 113
file gateway-config.example.json 4ebfa87747cde383c7108d0565ca2c45dbcd28df41d2638ff1d2f37e710616fb 882
file host-config.example.json 147a7a72942189d06314fe7a2ebbe5cb3da01060fc3a3e456b36fb9d64336506 791
file install.sh a1375da11a1bba8e7de166ec315083c2031eede5901b8f30753751d343a42f47 53170
file uninstall.sh 9ee2ef7b7897c6c14e19cf82827de243f349c06b46bd2e0b082c44184dd02168 6929
file visudo-LICENSE 723f36666b47b7c4aa82800611bbac6dcf7821ae29eb9fa14a0c787b55e3b8e7 30047
file visudo-SOURCE d4f85de26da57baadda42dce7f75bd08da0fd1f4748e128c16d2d0aa39a3c317 7696
file visudo-linux-amd64 dc2765868dd971a913fb88bd0cafcbacdeea12b1a05dde0a55f098deb7e15b54 979032
file visudo-linux-arm64 d53eac0749d2436bee2bc84bc96ce9ef5c7a3c7c4f005adb787d45a1d2b34a2b 482824
`

const rc21SourceCommit = "25a64b16e2adcc3ab8eb1a96d27f0509a99af680"

var (
	rc21RepositoryLine = "repository jeremyakers/askdo\n"
	rc21ReleaseLine    = "release v1.0.0-rc.21\n"
	rc21SourceLine     = "source 25a64b16e2adcc3ab8eb1a96d27f0509a99af680\n"
	rc21ValidatorLine  = "validator 1.9.5p2 48\n"
	rc21SudoersLine    = "file askdo.sudoers 47a63d1ceeb5fc2607471c9e742c6d03ccc3a03b2026ad5720da98a26bbd49d1 113\n"
)

func TestParseManifestParsesReleaseManifest(t *testing.T) {
	// Given: the verbatim v1.0.0-rc.21 release manifest.
	// When: it is parsed with a matching, and then with any, expected tag.
	// Then: every header field and the whole closed inventory parses.
	for _, expected := range []string{"", "v1.0.0-rc.21"} {
		manifest, err := ParseManifest(strings.NewReader(rc21Manifest), expected)
		if err != nil {
			t.Fatalf("ParseManifest(..., %q): %v", expected, err)
		}
		if manifest.Tag != "v1.0.0-rc.21" {
			t.Fatalf("tag %q", manifest.Tag)
		}
		if manifest.SourceCommit != rc21SourceCommit {
			t.Fatalf("source commit %q", manifest.SourceCommit)
		}
		if got, want := len(manifest.Assets), len(requiredAssets); got != want {
			t.Fatalf("%d assets, want %d", got, want)
		}
		want := Asset{Name: "askdo-linux-amd64", SHA256: "eb138aad2fde7b4bd925215d132a128f252561944a051efdc3c9367e976cb359", Size: 22095547}
		if got := manifest.Assets["askdo-linux-amd64"]; got != want {
			t.Fatalf("askdo-linux-amd64 = %+v, want %+v", got, want)
		}
	}
}

func TestParseManifestRejectsInvalidManifests(t *testing.T) {
	// Given: the valid rc21 manifest mutated to violate exactly one schema
	// rule per case (plus an unparseable empty/blank manifest).
	// When: each is parsed.
	// Then: parsing fails every time.
	dummyDigest := strings.Repeat("ab", 32)
	insert := func(needle, extra string) string {
		return strings.Replace(rc21Manifest, needle, needle+extra, 1)
	}
	tests := []struct {
		name        string
		manifest    string
		expectedTag string
	}{
		{"empty", "", ""},
		{"only newline", "\n", ""},
		{"header only", "askdo-install-v1\n", ""},
		{"whitespace line", insert("askdo-install-v1\n", " \n"), ""},
		{"wrong magic", strings.Replace(rc21Manifest, "askdo-install-v1", "askdo-install-v2", 1), ""},
		{"magic not first", rc21RepositoryLine + rc21Manifest, ""},
		{"duplicate repository", insert(rc21RepositoryLine, rc21RepositoryLine), ""},
		{"wrong repository", strings.Replace(rc21Manifest, "repository jeremyakers/askdo", "repository jeremyakers/askdo2", 1), ""},
		{"missing repository", strings.Replace(rc21Manifest, rc21RepositoryLine, "", 1), ""},
		{"duplicate release", insert(rc21ReleaseLine, "release v1.0.0-rc.20\n"), ""},
		{"missing release", strings.Replace(rc21Manifest, rc21ReleaseLine, "", 1), ""},
		{"tag latest", strings.Replace(rc21Manifest, rc21ReleaseLine, "release latest\n", 1), ""},
		{"tag main", strings.Replace(rc21Manifest, rc21ReleaseLine, "release main\n", 1), ""},
		{"tag master", strings.Replace(rc21Manifest, rc21ReleaseLine, "release master\n", 1), ""},
		{"tag invalid character", strings.Replace(rc21Manifest, rc21ReleaseLine, "release v1.0.0-rc.21+\n", 1), ""},
		{"tag leading dot", strings.Replace(rc21Manifest, rc21ReleaseLine, "release .v1\n", 1), ""},
		{"tag leading dash", strings.Replace(rc21Manifest, rc21ReleaseLine, "release -v1\n", 1), ""},
		{"release two tags", strings.Replace(rc21Manifest, rc21ReleaseLine, "release v1.0.0-rc.21 extra\n", 1), ""},
		{"release without tag", strings.Replace(rc21Manifest, rc21ReleaseLine, "release\n", 1), ""},
		{"duplicate source", insert(rc21SourceLine, strings.Repeat("2a", 20)+"\n"), ""},
		{"missing source", strings.Replace(rc21Manifest, rc21SourceLine, "", 1), ""},
		{"source short", strings.Replace(rc21Manifest, rc21SourceLine, "source "+rc21SourceCommit[:39]+"\n", 1), ""},
		{"source long", strings.Replace(rc21Manifest, rc21SourceLine, "source "+rc21SourceCommit+"afaf\n", 1), ""},
		{"source uppercase", strings.Replace(rc21Manifest, rc21SourceLine, "source "+strings.ToUpper(rc21SourceCommit)+"\n", 1), ""},
		{"source nonhex", strings.Replace(rc21Manifest, rc21SourceLine, "source 2g64b16e2adcc3ab8eb1a96d27f0509a99af680\n", 1), ""},
		{"duplicate validator", insert(rc21ValidatorLine, rc21ValidatorLine), ""},
		{"missing validator", strings.Replace(rc21Manifest, rc21ValidatorLine, "", 1), ""},
		{"validator wrong version", strings.Replace(rc21Manifest, rc21ValidatorLine, "validator 1.9.5p1 48\n", 1), ""},
		{"validator wrong level", strings.Replace(rc21Manifest, rc21ValidatorLine, "validator 1.9.5p2 47\n", 1), ""},
		{"validator extra field", strings.Replace(rc21Manifest, rc21ValidatorLine, "validator 1.9.5p2 48 x\n", 1), ""},
		{"unrecognized field", insert(rc21ValidatorLine, "notes x\n"), ""},
		{"file unknown asset", insert(rc21ValidatorLine, "file extra.txt "+dummyDigest+" 40\n"), ""},
		{"file traversal name", insert(rc21ValidatorLine, "file ../escapes "+dummyDigest+" 40\n"), ""},
		{"file duplicate asset", insert(rc21SudoersLine, rc21SudoersLine), ""},
		{"file missing asset", strings.Replace(rc21Manifest, rc21SudoersLine, "", 1), ""},
		{"file short digest", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("4", 63)+" 113\n", 1), ""},
		{"file long digest", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("4", 65)+" 113\n", 1), ""},
		{"file uppercase digest", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("A", 64)+" 113\n", 1), ""},
		{"file nonhex digest", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("4", 63)+"g 113\n", 1), ""},
		{"file size zero", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("0", 64)+" 0\n", 1), ""},
		{"file size leading zero", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("0", 64)+" 0113\n", 1), ""},
		{"file size over maximum", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("0", 64)+" 536870913\n", 1), ""},
		{"file size nine digits over maximum", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("0", 64)+" 999999999\n", 1), ""},
		{"file size too long", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("0", 64)+" 12345678901\n", 1), ""},
		{"file three fields", strings.Replace(rc21Manifest, rc21SudoersLine, "file askdo.sudoers "+strings.Repeat("4", 64)+"\n", 1), ""},
		{"file five fields", strings.Replace(rc21Manifest, rc21SudoersLine, strings.TrimSuffix(rc21SudoersLine, "\n")+" 0\n", 1), ""},
		{"repository trailing space", strings.Replace(rc21Manifest, rc21RepositoryLine, "repository jeremyakers/askdo \n", 1), ""},
		{"repository double space", strings.Replace(rc21Manifest, rc21RepositoryLine, "repository  jeremyakers/askdo\n", 1), ""},
		{"tab field", strings.Replace(rc21Manifest, rc21RepositoryLine, "repository\tjeremyakers/askdo\n", 1), ""},
		{"CRLF line", strings.Replace(rc21Manifest, rc21RepositoryLine, "repository jeremyakers/askdo\r\n", 1), ""},
		{"line too long", insert(rc21ValidatorLine, strings.Repeat("x", 513)+"\n"), ""},
		{"manifest too large", rc21Manifest + strings.Repeat(strings.Repeat("y", 511)+"\n"+strings.Repeat("z", 511)+"\n", 40), ""},
		{"wrong expected tag", rc21Manifest, "v9.9.9"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, err := ParseManifest(strings.NewReader(test.manifest), test.expectedTag)
			if err == nil {
				t.Fatalf("accepted invalid manifest: tag=%q assets=%d", manifest.Tag, len(manifest.Assets))
			}
		})
	}
}

func TestParseManifestAcceptsBoundaryValues(t *testing.T) {
	// Given: manifests exercising accepted boundaries — a 512-byte line
	// (via the length-uncapped tag under the line cap), the maximum asset
	// size of 536870912, and uppercase tag characters.
	// When: each is parsed.
	// Then: parsing succeeds.
	longTag := strings.Repeat("v", 504)
	if _, err := ParseManifest(strings.NewReader(strings.Replace(rc21Manifest, rc21ReleaseLine, "release "+longTag+"\n", 1)), longTag); err != nil {
		t.Fatalf("512-byte release line: %v", err)
	}
	overLongTag := strings.Repeat("v", 505)
	if _, err := ParseManifest(strings.NewReader(strings.Replace(rc21Manifest, rc21ReleaseLine, "release "+overLongTag+"\n", 1)), ""); err == nil {
		t.Fatal("513-byte line accepted")
	}
	maxSize := strings.Replace(rc21Manifest, " 35149\n", " 536870912\n", 1)
	if _, err := ParseManifest(strings.NewReader(maxSize), ""); err != nil {
		t.Fatalf("maximum asset size: %v", err)
	}
	uppercaseTag := strings.Replace(rc21Manifest, rc21ReleaseLine, "release v1.0.0-RC.21\n", 1)
	if _, err := ParseManifest(strings.NewReader(uppercaseTag), ""); err != nil {
		t.Fatalf("uppercase tag: %v", err)
	}
}

func hexDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func elfImage(machine byte) []byte {
	image := make([]byte, 64)
	copy(image, []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01})
	image[18] = machine
	return image
}

func recordBytes(digest, name string) []byte {
	return []byte(digest + "  " + name + "\n")
}

func TestVerifyAssetChecksSizeAndDigest(t *testing.T) {
	// Given: a manifest entry and files on disk that match, are shorter,
	// hold different bytes, or are absent.
	// When: VerifyAsset runs.
	// Then: only the exact size and digest pass.
	content := []byte("release asset bytes\n")
	manifest := Manifest{Assets: map[string]Asset{
		"asset-demo": {Name: "asset-demo", SHA256: hexDigest(content), Size: int64(len(content))},
	}}
	root := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := manifest.VerifyAsset("asset-demo", write("good", content)); err != nil {
		t.Fatalf("matching asset rejected: %v", err)
	}
	mutated := append([]byte(nil), content...)
	mutated[0] ^= 0xff
	if err := manifest.VerifyAsset("asset-demo", write("digest", mutated)); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if err := manifest.VerifyAsset("asset-demo", write("short", content[:5])); err == nil {
		t.Fatal("size mismatch accepted")
	}
	if err := manifest.VerifyAsset("unknown.txt", write("unknown", content)); err == nil {
		t.Fatal("unknown asset accepted")
	}
	if err := manifest.VerifyAsset("asset-demo", filepath.Join(root, "absent")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestVerifyChecksumRecordRequiresExactRecord(t *testing.T) {
	// Given: checksum record files that are exact, mutated, or absent.
	// When: VerifyChecksumRecord runs.
	// Then: only "<sha256>  <name>\n" byte-for-byte is accepted.
	manifest := Manifest{Assets: map[string]Asset{
		"askdo-linux-amd64": {Name: "askdo-linux-amd64", SHA256: strings.Repeat("eb", 32), Size: 16},
	}}
	root := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := strings.Repeat("eb", 32) + "  askdo-linux-amd64\n"
	if err := manifest.VerifyChecksumRecord("askdo-linux-amd64", write("good", good)); err != nil {
		t.Fatalf("exact record rejected: %v", err)
	}
	bad := map[string]string{
		"wrong_digest":   strings.Repeat("ab", 32) + "  askdo-linux-amd64\n",
		"wrong_name":     strings.Repeat("eb", 32) + "  askdo-linux-arm64\n",
		"single_space":   strings.Repeat("eb", 32) + " askdo-linux-amd64\n",
		"no_newline":     strings.Repeat("eb", 32) + "  askdo-linux-amd64",
		"extra_line":     strings.Repeat("eb", 32) + "  askdo-linux-amd64\n\n",
		"extra_trailing": strings.Repeat("eb", 32) + "  askdo-linux-amd64\nx",
	}
	for name, content := range bad {
		if err := manifest.VerifyChecksumRecord("askdo-linux-amd64", write(name, content)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := manifest.VerifyChecksumRecord("askdo-linux-arm64", write("unknown", good)); err == nil {
		t.Fatal("binary missing from manifest accepted")
	}
	if err := manifest.VerifyChecksumRecord("askdo-linux-amd64", filepath.Join(root, "absent")); err == nil {
		t.Fatal("missing record file accepted")
	}
}

func TestVerifyELFRequiresELF64LittleEndianMachine(t *testing.T) {
	// Given: ELF64 little-endian images for both machines, and files that are
	// wrong-arch, 32-bit, big-endian, truncated or not ELF at all.
	// When: VerifyELF runs against names with matching amd64/arm64 suffixes.
	// Then: only the correct ELF64 LE image passes, and names without an
	// architecture suffix are refused outright.
	root := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var manifest Manifest
	if err := manifest.VerifyELF("askdo-linux-amd64", write("amd64", elfImage(0x3e))); err != nil {
		t.Fatalf("amd64 ELF rejected: %v", err)
	}
	if err := manifest.VerifyELF("askdo-launch-linux-arm64", write("arm64", elfImage(0xb7))); err != nil {
		t.Fatalf("arm64 ELF rejected: %v", err)
	}
	bad := map[string]func([]byte) []byte{
		"wrong_machine":     func(b []byte) []byte { b[18] = 0xb7; return b },
		"32_bit_class":      func(b []byte) []byte { b[4] = 0x01; return b },
		"big_endian":        func(b []byte) []byte { b[5] = 0x02; return b },
		"wrong_elf_version": func(b []byte) []byte { b[6] = 0x02; return b },
		"not_elf":           func(b []byte) []byte { b[0] = 0x00; return b },
	}
	for name, mutate := range bad {
		if err := manifest.VerifyELF("askdo-linux-amd64", write(name, mutate(append([]byte(nil), elfImage(0x3e)...)))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := manifest.VerifyELF("askdo-linux-amd64", write("truncated", elfImage(0x3e)[:19])); err == nil {
		t.Fatal("truncated ELF accepted")
	}
	if err := manifest.VerifyELF("askdo.service", write("service", elfImage(0x3e))); err == nil {
		t.Fatal("name without architecture suffix accepted")
	}
	if err := manifest.VerifyELF("askdo-linux-amd64", filepath.Join(root, "absent")); err == nil {
		t.Fatal("missing file accepted")
	}
}

type manifestEntry struct {
	sha  string
	size string
}

func assembleManifest(tag, source string, files map[string]manifestEntry) string {
	var builder strings.Builder
	builder.WriteString("askdo-install-v1\n")
	fmt.Fprintf(&builder, "repository %s\n", repoName)
	fmt.Fprintf(&builder, "release %s\n", tag)
	fmt.Fprintf(&builder, "source %s\n", source)
	builder.WriteString("validator 1.9.5p2 48\n")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&builder, "file %s %s %s\n", name, files[name].sha, files[name].size)
	}
	return builder.String()
}

// downloadFixture builds a schema-valid manifest carrying the complete closed
// inventory: real current-GOARCH binary, helper and checksum records backed
// by servable bytes, valid placeholder entries for everything else.
func downloadFixture(t *testing.T, tag, source, goarch string, binary, helper []byte) (string, map[string][]byte) {
	t.Helper()
	binaryName := "askdo-linux-" + goarch
	helperName := "askdo-launch-linux-" + goarch
	assets := map[string][]byte{
		binaryName:             binary,
		helperName:             helper,
		binaryName + ".sha256": recordBytes(hexDigest(binary), binaryName),
		helperName + ".sha256": recordBytes(hexDigest(helper), helperName),
	}
	files := map[string]manifestEntry{}
	for name, data := range assets {
		files[name] = manifestEntry{sha: hexDigest(data), size: fmt.Sprint(len(data))}
	}
	for name := range requiredAssets {
		if _, ok := files[name]; !ok {
			files[name] = manifestEntry{sha: strings.Repeat("cd", 32), size: "16"}
		}
	}
	return assembleManifest(tag, source, files), assets
}

// releaseServer serves manifests, assets and the release-list API from one
// httptest origin, recording every request path.
type releaseServer struct {
	*httptest.Server
	mu        sync.Mutex
	releases  string            // JSON list for the API path; empty means 404
	manifests map[string]string // tag -> manifest text
	assets    map[string][]byte // asset name -> served bytes
	paths     []string
}

func newReleaseServer(t *testing.T, releases string, manifests map[string]string, assets map[string][]byte) *releaseServer {
	t.Helper()
	server := &releaseServer{releases: releases, manifests: manifests, assets: assets}
	server.Server = httptest.NewServer(http.HandlerFunc(server.handle))
	t.Cleanup(server.Server.Close)
	return server
}

func (s *releaseServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/releases") {
		if s.releases == "" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, s.releases)
		return
	}
	const downloadPrefix = "/releases/download/"
	index := strings.LastIndex(r.URL.Path, downloadPrefix)
	if index < 0 {
		http.NotFound(w, r)
		return
	}
	tag, name, found := strings.Cut(r.URL.Path[index+len(downloadPrefix):], "/")
	if !found {
		http.NotFound(w, r)
		return
	}
	if name == "install-manifest.v1" {
		if manifest, ok := s.manifests[tag]; ok {
			fmt.Fprint(w, manifest)
			return
		}
	} else if asset, ok := s.assets[name]; ok {
		w.Write(asset)
		return
	}
	http.NotFound(w, r)
}

func (s *releaseServer) hit(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, recorded := range s.paths {
		if recorded == path {
			count++
		}
	}
	return count
}

func (s *releaseServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.paths)
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []string{}
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestDownloadReleaseDownloadsCurrentArchAssets(t *testing.T) {
	// Given: a server serving the manifest for an explicit tag plus the
	// current-GOARCH binary, helper and checksum records.
	// When: DownloadRelease runs with the explicit tag.
	// Then: the four assets and raw manifest land in dir with verified bytes, the
	// returned manifest carries the tag, and only five requests were made.
	fixtureTag := "v1.2.3"
	name := "askdo-linux-" + runtime.GOARCH
	helperName := "askdo-launch-linux-" + runtime.GOARCH
	manifest, assets := downloadFixture(t, fixtureTag, rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	server := newReleaseServer(t, "", map[string]string{fixtureTag: manifest}, assets)
	base := server.URL + "/jeremyakers/askdo"
	dir := filepath.Join(t.TempDir(), "staging")
	fetched, err := DownloadRelease(context.Background(), nil, base, fixtureTag, dir)
	if err != nil {
		t.Fatalf("DownloadRelease: %v", err)
	}
	if fetched.Tag != fixtureTag || fetched.SourceCommit != rc21SourceCommit {
		t.Fatalf("manifest tag %q source %q", fetched.Tag, fetched.SourceCommit)
	}
	want := []string{helperName, helperName + ".sha256", name, name + ".sha256"}
	wantFiles := append(append([]string(nil), want...), "install-manifest.v1")
	if got := dirNames(t, dir); strings.Join(got, ",") != strings.Join(wantFiles, ",") {
		t.Fatalf("dir contains %v, want %v", got, wantFiles)
	}
	for _, asset := range want {
		got, err := os.ReadFile(filepath.Join(dir, asset))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(assets[asset]) {
			t.Fatalf("%s bytes differ", asset)
		}
	}
	if got := server.requestCount(); got != 5 {
		t.Fatalf("%d requests made, want exactly 5", got)
	}
	prefix := "/jeremyakers/askdo/releases/download/" + fixtureTag + "/"
	if got := server.hit(prefix + "install-manifest.v1"); got != 1 {
		t.Fatalf("manifest fetched %d times", got)
	}
	for _, asset := range want {
		if got := server.hit(prefix + asset); got != 1 {
			t.Fatalf("%s fetched %d times", asset, got)
		}
	}
}

type releaseMemoryTransport func(*http.Request) (*http.Response, error)

func (f releaseMemoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// All responses come from memory; these tests never open a network connection.
func memoryReleaseClient(manifest []byte, assets map[string][]byte) *http.Client {
	return &http.Client{Transport: releaseMemoryTransport(func(r *http.Request) (*http.Response, error) {
		name := filepath.Base(r.URL.Path)
		data, ok := assets[name]
		if name == "install-manifest.v1" {
			data, ok = manifest, true
		}
		status := http.StatusOK
		if !ok {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})}
}

func TestDownloadReleasePersistsRawManifestAndDigest(t *testing.T) {
	for _, newline := range []bool{true, false} {
		t.Run(fmt.Sprint("trailing newline=", newline), func(t *testing.T) {
			// Given: both accepted byte representations, served entirely from memory.
			machine := byte(0x3e)
			if runtime.GOARCH == "arm64" {
				machine = 0xb7
			}
			raw, assets := downloadFixture(t, "v1.2.3", rc21SourceCommit, runtime.GOARCH, elfImage(machine), elfImage(machine))
			if !newline {
				raw = strings.TrimSuffix(raw, "\n")
			}
			dir := t.TempDir()
			// When
			manifest, err := DownloadRelease(t.Context(), memoryReleaseClient([]byte(raw), assets), "https://github.com/jeremyakers/askdo", "v1.2.3", dir)
			// Then: preserve the downloaded bytes, not a reserialized manifest.
			if err != nil {
				t.Fatal(err)
			}
			persisted, readErr := os.ReadFile(filepath.Join(dir, "install-manifest.v1"))
			if readErr != nil || string(persisted) != raw || manifest.Digest != hexDigest([]byte(raw)) {
				t.Fatalf("manifest identity: bytes=%q digest=%s err=%v", persisted, manifest.Digest, readErr)
			}
		})
	}
}

func TestDownloadReleaseRemovesManifestWhenAssetCommitFails(t *testing.T) {
	// Given: a later asset rename fails after the manifest and CLI were published.
	machine := byte(0x3e)
	if runtime.GOARCH == "arm64" {
		machine = 0xb7
	}
	raw, assets := downloadFixture(t, "v1.2.3", rc21SourceCommit, runtime.GOARCH, elfImage(machine), elfImage(machine))
	dir := t.TempDir()
	collision := "askdo-launch-linux-" + runtime.GOARCH
	if err := os.Mkdir(filepath.Join(dir, collision), 0o700); err != nil {
		t.Fatal(err)
	}
	// When
	_, err := DownloadRelease(t.Context(), memoryReleaseClient([]byte(raw), assets), "https://github.com/jeremyakers/askdo", "v1.2.3", dir)
	// Then: remove every file/temp from this attempt, but not the foreign directory.
	if err == nil {
		t.Fatal("asset rename unexpectedly succeeded")
	}
	if names := dirNames(t, dir); len(names) != 1 || names[0] != collision {
		t.Fatalf("rollback left %v", names)
	}
}

func TestDownloadReleaseResolvesNewestStableRelease(t *testing.T) {
	// Given: a release list whose newest entries are prereleases and one
	// older stable release, through the release-list API.
	// When: DownloadRelease runs with an empty tag.
	// Then: the newest stable release is resolved with a single API call and
	// its assets are downloaded.
	prereleaseTag, stableTag := "v1.2.4-rc.1", "v1.2.3"
	manifest, assets := downloadFixture(t, stableTag, rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	prerelease := strings.Replace(manifest, "release "+stableTag+"\n", "release "+prereleaseTag+"\n", 1)
	releases := "[{\"tag_name\":\"" + prereleaseTag + "\",\"prerelease\":true,\"published_at\":\"2026-01-03T00:00:00Z\"}," +
		"{\"tag_name\":\"" + stableTag + "\",\"prerelease\":false,\"published_at\":\"2026-01-01T00:00:00Z\"}]"
	server := newReleaseServer(t, releases, map[string]string{stableTag: manifest, prereleaseTag: prerelease}, assets)
	base := server.URL + "/jeremyakers/askdo"
	dir := filepath.Join(t.TempDir(), "staging")
	fetched, err := DownloadRelease(context.Background(), nil, base, "", dir)
	if err != nil {
		t.Fatalf("DownloadRelease: %v", err)
	}
	if fetched.Tag != stableTag {
		t.Fatalf("resolved tag %q, want %q", fetched.Tag, stableTag)
	}
	if got := server.hit("/jeremyakers/askdo/releases"); got != 1 {
		t.Fatalf("release list API hit %d times, want once", got)
	}
	if got, want := len(dirNames(t, dir)), len(assets)+1; got != want {
		t.Fatalf("dir contains %d entries, want %d", got, want)
	}
	if got := server.hit("/jeremyakers/askdo/releases/download/" + prereleaseTag); got != 0 {
		t.Fatal("prerelease assets were fetched")
	}
}

func TestDownloadReleaseResolvesNewestPrereleaseWhenNoStable(t *testing.T) {
	// Given: only prereleases and drafts are published.
	// When: DownloadRelease runs with an empty tag.
	// Then: the newest non-draft entry (a prerelease) is resolved.
	tag := "v1.3.0-rc.2"
	manifest, assets := downloadFixture(t, tag, rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	releases := "[{\"tag_name\":\"v2.0.0\",\"draft\":true,\"prerelease\":false,\"published_at\":\"2026-02-01T00:00:00Z\"}," +
		"{\"tag_name\":\"" + tag + "\",\"prerelease\":true,\"published_at\":\"2026-01-05T00:00:00Z\"}," +
		"{\"tag_name\":\"v1.3.0-rc.1\",\"prerelease\":true,\"published_at\":\"2026-01-04T00:00:00Z\"}," +
		"{\"tag_name\":\"latest\",\"published_at\":\"2026-01-06T00:00:00Z\"}]"
	server := newReleaseServer(t, releases, map[string]string{tag: manifest}, assets)
	dir := filepath.Join(t.TempDir(), "staging")
	fetched, err := DownloadRelease(context.Background(), nil, server.URL+"/jeremyakers/askdo", "", dir)
	if err != nil {
		t.Fatalf("DownloadRelease: %v", err)
	}
	if fetched.Tag != tag {
		t.Fatalf("resolved tag %q, want %q", fetched.Tag, tag)
	}
}

func TestDownloadReleaseRejectsNoPublishedRelease(t *testing.T) {
	// Given: a release list that contains only drafts, or nothing at all.
	// When: DownloadRelease resolves an empty tag.
	// Then: it fails and never reaches the asset endpoints.
	for _, releases := range []string{
		"[]",
		"[{\"tag_name\":\"v2.0.0\",\"draft\":true,\"published_at\":\"2026-02-01T00:00:00Z\"}]",
	} {
		server := newReleaseServer(t, releases, nil, nil)
		dir := filepath.Join(t.TempDir(), "staging")
		if _, err := DownloadRelease(context.Background(), nil, server.URL+"/jeremyakers/askdo", "", dir); err == nil {
			t.Fatalf("list %q resolved", releases)
		}
		if got := server.requestCount(); got != 1 {
			t.Fatalf("%d requests made, want only the failed release list", got)
		}
	}
}

type countingTransport struct {
	requests int
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.requests++
	return nil, fmt.Errorf("unexpected network request")
}

func TestDownloadReleaseRejectsInsecureOrForeignBase(t *testing.T) {
	// Given: repository bases that are non-loopback HTTP, non-HTTP(S),
	// foreign in repository path, or on an arbitrary HTTPS host even with the
	// correct repository path, and a transport that fails on any dial.
	// When: DownloadRelease is pointed at them.
	// Then: it fails before any network request escapes.
	client := &http.Client{Transport: &countingTransport{}}
	for _, base := range []string{
		"http://example.com/jeremyakers/askdo",
		"ftp://github.com/jeremyakers/askdo",
		"https://github.com/example/other",
		"https://github.com",
		"https://example.com/jeremyakers/askdo",
		"https://mirror.example.test/jeremyakers/askdo",
		"https://github.com:8443/jeremyakers/askdo",
	} {
		dir := filepath.Join(t.TempDir(), "staging")
		if _, err := DownloadRelease(context.Background(), client, base, "v1.2.3", dir); err == nil {
			t.Fatalf("base %q accepted", base)
		}
	}
	if got := client.Transport.(*countingTransport).requests; got != 0 {
		t.Fatalf("%d network requests escaped", got)
	}
}

func TestNormalizeRepoBaseAdmitsGitHubAndLoopbackHosts(t *testing.T) {
	// Given: the real GitHub base spellings, a loopback base for httptest,
	// and an arbitrary HTTPS host carrying the correct repository path.
	// When: normalizeRepoBase parses each.
	// Then: GitHub and loopback forms are accepted and the arbitrary host
	// is refused without any request.
	for _, base := range []string{
		"https://github.com/jeremyakers/askdo",
		"https://github.com/jeremyakers/askdo/",
		"https://api.github.com/repos/jeremyakers/askdo",
		"https://127.0.0.1:8080/jeremyakers/askdo",
		"https://localhost/jeremyakers/askdo",
	} {
		if _, err := normalizeRepoBase(base); err != nil {
			t.Fatalf("base %q rejected: %v", base, err)
		}
	}
	if _, err := normalizeRepoBase("https://mirror.example.test/jeremyakers/askdo"); err == nil {
		t.Fatal("arbitrary HTTPS host accepted")
	}
}

func TestDownloadReleaseRefusesRedirects(t *testing.T) {
	// Given: endpoints redirecting to a foreign host over HTTP, down to plain
	// HTTP from an HTTPS origin, and to a foreign host over HTTPS.
	// When: DownloadRelease follows the first hop.
	// Then: the redirect policy refuses each and no redirect target is
	// reached.
	var targetHits int
	var targetMu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetMu.Lock()
		targetHits++
		targetMu.Unlock()
		fmt.Fprint(w, "hostile payload")
	}))
	t.Cleanup(target.Close)
	targetCount := func() int {
		targetMu.Lock()
		defer targetMu.Unlock()
		return targetHits
	}

	run := func(t *testing.T, server *httptest.Server, client *http.Client) {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "staging")
		if _, err := DownloadRelease(context.Background(), client, server.URL+"/jeremyakers/askdo", "v1.2.3", dir); err == nil {
			t.Fatal("redirect accepted")
		}
		if got := dirNames(t, dir); len(got) != 0 {
			t.Fatalf("failure left %v in dir", got)
		}
	}

	t.Run("cross host http redirect", func(t *testing.T) {
		redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		t.Cleanup(redirecting.Close)
		run(t, redirecting, nil)
	})
	t.Run("https downgrade redirect", func(t *testing.T) {
		insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host, http.StatusFound)
		}))
		t.Cleanup(redirecting.Close)
		run(t, redirecting, insecure)
	})
	t.Run("https foreign host redirect", func(t *testing.T) {
		insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		t.Cleanup(redirecting.Close)
		run(t, redirecting, insecure)
	})
	if got := targetCount(); got != 0 {
		t.Fatalf("redirect target contacted %d times", got)
	}
}

func TestDownloadReleaseFollowsSameOriginRedirect(t *testing.T) {
	// Given: the manifest endpoint redirects to another path on the same
	// loopback origin.
	// When: DownloadRelease follows it.
	// Then: the redirect is allowed and the release still downloads.
	manifest, assets := downloadFixture(t, "v1.2.3", rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	mux := http.NewServeMux()
	mux.HandleFunc("/jeremyakers/askdo/releases/download/v1.2.3/install-manifest.v1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved-manifest", http.StatusFound)
	})
	mux.HandleFunc("/moved-manifest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, manifest)
	})
	for name, data := range assets {
		asset := data
		mux.HandleFunc("/jeremyakers/askdo/releases/download/v1.2.3/"+name, func(w http.ResponseWriter, r *http.Request) {
			w.Write(asset)
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	dir := filepath.Join(t.TempDir(), "staging")
	fetched, err := DownloadRelease(context.Background(), nil, server.URL+"/jeremyakers/askdo", "v1.2.3", dir)
	if err != nil {
		t.Fatalf("DownloadRelease: %v", err)
	}
	if fetched.Tag != "v1.2.3" {
		t.Fatalf("tag %q", fetched.Tag)
	}
	if got, want := len(dirNames(t, dir)), len(assets)+1; got != want {
		t.Fatalf("dir contains %d entries, want %d", got, want)
	}
}

func TestDownloadReleaseCleansUpOnFailure(t *testing.T) {
	// Given: servers whose asset streams violate the declared digest, size or
	// ELF architecture, whose checksum record disagrees, or that drop assets.
	// When: DownloadRelease fails partway.
	// Then: no partial or temporary file remains in dir.
	var tests []struct {
		name    string
		rebuild func() (string, map[string][]byte)
	}
	base := func() (string, map[string][]byte) {
		return downloadFixture(t, "v1.2.3", rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	}
	tests = append(tests,
		struct {
			name    string
			rebuild func() (string, map[string][]byte)
		}{"digest mismatch", func() (string, map[string][]byte) {
			manifest, assets := base()
			name := "askdo-linux-" + runtime.GOARCH
			mutated := append([]byte(nil), assets[name]...)
			mutated[0] ^= 0xff
			assets[name] = mutated
			assets[name+".sha256"] = recordBytes(hexDigest(mutated), name)
			return manifest, assets
		}},
		struct {
			name    string
			rebuild func() (string, map[string][]byte)
		}{"oversized stream", func() (string, map[string][]byte) {
			manifest, assets := base()
			for name, data := range assets {
				assets[name] = append(append([]byte(nil), data...), data...)
			}
			return manifest, assets
		}},
		struct {
			name    string
			rebuild func() (string, map[string][]byte)
		}{"missing asset", func() (string, map[string][]byte) {
			manifest, assets := base()
			delete(assets, "askdo-launch-linux-"+runtime.GOARCH) // 404 although required
			return manifest, assets
		}},
		struct {
			name    string
			rebuild func() (string, map[string][]byte)
		}{"checksum record mismatch", func() (string, map[string][]byte) {
			manifest, assets := base()
			name := "askdo-linux-" + runtime.GOARCH
			assets[name+".sha256"] = []byte(fmt.Sprintf("%s %s\n", strings.Repeat("eb", 32), name))
			return manifest, assets
		}},
		struct {
			name    string
			rebuild func() (string, map[string][]byte)
		}{"wrong ELF architecture", func() (string, map[string][]byte) {
			var machine byte = 0xb7
			helper := elfImage(0x3e)
			if runtime.GOARCH == "arm64" {
				machine = 0x3e
				helper = elfImage(0xb7)
			}
			return downloadFixture(t, "v1.2.3", rc21SourceCommit, runtime.GOARCH, elfImage(machine), helper)
		}},
	)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, assets := test.rebuild()
			server := newReleaseServer(t, "", map[string]string{"v1.2.3": manifest}, assets)
			dir := filepath.Join(t.TempDir(), "staging")
			if _, err := DownloadRelease(context.Background(), nil, server.URL+"/jeremyakers/askdo", "v1.2.3", dir); err == nil {
				t.Fatal("DownloadRelease accepted violating assets")
			}
			if got := dirNames(t, dir); len(got) != 0 {
				t.Fatalf("failure left %v in dir", got)
			}
		})
	}
}

func TestDownloadReleaseRejectsTagAndManifestDisagreement(t *testing.T) {
	// Given: a manifest served for an explicit tag while advertising another,
	// and a manifest longer than the 16KiB ceiling.
	// When: DownloadRelease fetches each.
	// Then: both fail and leave dir empty.
	manifest, assets := downloadFixture(t, "v3.2.1", rc21SourceCommit, runtime.GOARCH, elfImage(0x3e), elfImage(0x3e))
	server := newReleaseServer(t, "", map[string]string{"v1.2.3": manifest}, assets)
	dir := filepath.Join(t.TempDir(), "staging")
	if _, err := DownloadRelease(context.Background(), nil, server.URL+"/jeremyakers/askdo", "v1.2.3", dir); err == nil {
		t.Fatal("tag disagreement accepted")
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Fatalf("failure left %v in dir", got)
	}

	oversized := strings.Repeat(strings.Repeat("q", 410)+"\n", 41)
	bigServer := newReleaseServer(t, "", map[string]string{"v1.2.3": oversized}, nil)
	dir = filepath.Join(t.TempDir(), "staging")
	if _, err := DownloadRelease(context.Background(), nil, bigServer.URL+"/jeremyakers/askdo", "v1.2.3", dir); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Fatalf("failure left %v in dir", got)
	}
}
