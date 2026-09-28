package inspection

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func assertRange(t *testing.T, got RangeResult, status Status) {
	t.Helper()
	if got.Status != status || (status != StatusOK && len(got.Content) != 0) {
		t.Fatalf("range status=%s content=%q err=%v, want %s and no denied bytes", got.Status, got.Content, got.Err, status)
	}
}

func TestReadRangeTextAndEOF(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "notes.txt")
	writeFile(t, path, "abcdef", 0600)
	p := testPolicy(t, root)
	got := p.ReadRange(path, 2, 3, currentIdentity())
	assertRange(t, got, StatusOK)
	if string(got.Content) != "cde" || got.NextOffset != 5 || got.EOF || got.Size != 6 {
		t.Fatalf("read range: %+v", got)
	}
	got = p.ReadRange(path, 5, 4, currentIdentity())
	if got.Status != StatusOK || string(got.Content) != "f" || got.NextOffset != 6 || !got.EOF {
		t.Fatalf("end range: %+v", got)
	}
	got = p.ReadRange(path, 10, 4, currentIdentity())
	if got.Status != StatusOK || len(got.Content) != 0 || got.NextOffset != 10 || !got.EOF || got.Size != 6 {
		t.Fatalf("past EOF: %+v", got)
	}
	if got := p.ReadRange(path, 0, 16384, currentIdentity()); got.Status != StatusOK || string(got.Content) != "abcdef" {
		t.Fatalf("maximum allowed range: %+v", got)
	}
	binary := filepath.Join(root, "raw.bin")
	if err := os.WriteFile(binary, []byte{0xff, 0x00, 'x'}, 0600); err != nil {
		t.Fatal(err)
	}
	got = p.ReadRange(binary, 0, 3, currentIdentity())
	if got.Status != StatusOK || string(got.Content) != string([]byte{0xff, 0x00, 'x'}) || !got.EOF {
		t.Fatalf("raw bytes must be preserved: %+v", got)
	}
	// Executable-looking content is opaque to direct reads: no fingerprinting,
	// hashing, or interpreter sniffing, just the requested bytes.
	elf := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(elf, []byte("\x7fELF\x02\x01\x01\x00payload"), 0755); err != nil {
		t.Fatal(err)
	}
	got = p.ReadRange(elf, 8, 7, currentIdentity())
	if got.Status != StatusOK || string(got.Content) != "payload" || !got.EOF {
		t.Fatalf("binary content must be returned verbatim: %+v", got)
	}
}

func TestReadRangeDenials(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "blocked.txt")
	writeFile(t, path, "secret", 0600)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, outside, "outside", 0600)
	p := testPolicy(t, root, path)
	for _, name := range []string{path, outside, "/etc/askdo/config.json"} {
		assertRange(t, p.ReadRange(name, 0, 16, currentIdentity()), StatusInspectionDenied)
	}
	assertRange(t, p.ReadRange(root, 0, 16, currentIdentity()), StatusInspectionDenied)
	for _, tc := range []struct {
		offset int64
		max    int
	}{{-1, 1}, {0, 0}, {0, 16385}, {math.MaxInt64, 2}} {
		assertRange(t, p.ReadRange(path, tc.offset, tc.max, currentIdentity()), StatusLimitExceeded)
	}
	assertRange(t, p.ReadRange(outside, 0, 16385, currentIdentity()), StatusLimitExceeded)
}

func TestReadRangeConfiguredMaskAndAliases(t *testing.T) {
	root := t.TempDir()
	masked := filepath.Join(root, "token.privmask")
	writeFile(t, masked, "masked secret", 0600)
	alias := filepath.Join(root, "alias.txt")
	if err := os.Symlink(masked, alias); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "plain.txt")
	writeFile(t, plain, "unmasked content", 0600)
	maskedAlias := filepath.Join(root, "alias.privmask")
	if err := os.Symlink(plain, maskedAlias); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	for _, name := range []string{masked, alias, maskedAlias} {
		assertRange(t, p.ReadRange(name, 0, 16, currentIdentity()), StatusWithheld)
	}
	hard := filepath.Join(root, "protected.txt")
	writeFile(t, hard, "protected secret", 0600)
	hardAlias := filepath.Join(root, "hardalias.txt")
	if err := os.Link(hard, hardAlias); err != nil {
		t.Fatal(err)
	}
	protected, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}}, hard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = protected.Close() })
	assertRange(t, protected.ReadRange(hardAlias, 0, 16, currentIdentity()), StatusInspectionDenied)
}

func TestReadRangeRetargetNeverReturnsBytes(t *testing.T) {
	for _, phase := range []string{"beforeRead", "afterRead"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			safe := filepath.Join(root, "safe.txt")
			secret := filepath.Join(root, "secret.privmask")
			link := filepath.Join(root, "link.txt")
			writeFile(t, safe, "safe", 0600)
			writeFile(t, secret, "top secret", 0600)
			if err := os.Symlink(safe, link); err != nil {
				t.Fatal(err)
			}
			p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			retarget := func() {
				newLink := filepath.Join(root, "new-link")
				if err := os.Symlink(secret, newLink); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(newLink, link); err != nil {
					t.Fatal(err)
				}
			}
			hooks := rangeHooks{}
			if phase == "beforeRead" {
				hooks.beforeRead = retarget
			} else {
				hooks.afterRead = retarget
			}
			rangeReadHooks.Store(p, hooks)
			t.Cleanup(func() { rangeReadHooks.Delete(p) })
			assertRange(t, p.ReadRange(link, 0, 16, currentIdentity()), StatusChangedDuringCapture)
		})
	}
}

func TestReadRangeSpecialObject(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	assertRange(t, testPolicy(t, root).ReadRange(path, 0, 1, currentIdentity()), StatusInspectionDenied)
}
