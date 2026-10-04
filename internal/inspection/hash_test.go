package inspection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func assertHashStatus(t *testing.T, got ExecutableHash, status, want Status) {
	t.Helper()
	work := got.WorkBytes
	got.WorkBytes = 0
	if status != want || (want != StatusOK && got != (ExecutableHash{})) {
		t.Fatalf("hash=%+v work=%d status=%s, want %s and no failed evidence", got, work, status, want)
	}
}

func TestHashExecutableBinaryAndBounds(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tool")
	content := bytes.Repeat([]byte{0xff, 0, 0x7f, 'x'}, 5<<20)
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	for _, max := range []int64{int64(len(content)), 32 << 20} {
		got, status := p.HashExecutable(context.Background(), path, max)
		assertHashStatus(t, got, status, StatusOK)
		sum := sha256.Sum256(content)
		meta, ms := p.StatPath(path, true)
		if ms != StatusOK || got.SHA256 != hex.EncodeToString(sum[:]) || got.Size != int64(len(content)) || got.WorkBytes != got.Size || got.RequestedPath != path || got.ResolvedPath != path || got.Mode != meta.Mode || got.UID != meta.UID || got.GID != meta.GID || got.Device != meta.Device || got.Inode != meta.Inode || got.MtimeUnixNS != meta.MtimeUnixNS || got.CtimeUnixNS != meta.CtimeUnixNS {
			t.Fatalf("metadata/digest mismatch: %+v metadata=%+v", got, meta)
		}
	}
	for _, max := range []int64{-1, 0, 8 << 20, int64(len(content)) - 1} {
		got, status := p.HashExecutable(context.Background(), path, max)
		assertHashStatus(t, got, status, StatusLimitExceeded)
		if got.WorkBytes != 0 {
			t.Fatalf("oversized file read %d bytes", got.WorkBytes)
		}
	}
	empty := filepath.Join(root, "empty")
	writeFile(t, empty, "", 0700)
	got, status := p.HashExecutable(context.Background(), empty, 0)
	assertHashStatus(t, got, status, StatusOK)
	if got.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal(got)
	}
}

func TestHashExecutablePolicyGates(t *testing.T) {
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	secret := filepath.Join(root, "token.privmask")
	blocked := filepath.Join(root, "blocked")
	protected := filepath.Join(root, "protected")
	for _, path := range []string{plain, secret, blocked, protected} {
		writeFile(t, path, "payload", 0755)
	}
	nonexec := filepath.Join(root, "nonexec")
	writeFile(t, nonexec, "payload", 0644)
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0755); err != nil {
		t.Fatal(err)
	}
	aliases := map[string]string{"secret-alias": secret, "masked.privmask": plain, "blocked-alias": blocked, "protected-alias": protected, "safe-alias": plain}
	for name, target := range aliases {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	hardAlias := filepath.Join(root, "hard-alias")
	if err := os.Link(protected, hardAlias); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, DenyPaths: []string{blocked}, SensitiveMasks: []string{"*.privmask"}}, protected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	for _, name := range []string{secret, filepath.Join(root, "secret-alias"), filepath.Join(root, "masked.privmask")} {
		got, status := p.HashExecutable(context.Background(), name, 32)
		assertHashStatus(t, got, status, StatusWithheld)
		if got.WorkBytes != 0 {
			t.Fatal("withheld bytes read")
		}
	}
	for _, name := range []string{blocked, filepath.Join(root, "blocked-alias"), protected, filepath.Join(root, "protected-alias"), hardAlias, nonexec, fifo, root, "/etc/askdo/config.json", plain + "\x00", "relative"} {
		got, status := p.HashExecutable(context.Background(), name, 32)
		assertHashStatus(t, got, status, StatusInspectionDenied)
	}
	got, status := p.HashExecutable(context.Background(), filepath.Join(root, "safe-alias"), 32)
	assertHashStatus(t, got, status, StatusOK)
	if got.ResolvedPath != plain {
		t.Fatal(got)
	}
	got, status = p.HashExecutable(context.Background(), filepath.Join(root, "missing"), 32)
	assertHashStatus(t, got, status, StatusNotFound)
}

func TestHashExecutableChangesAndCancellation(t *testing.T) {
	for _, mutation := range []string{"data", "mode", "owner", "retarget", "grow", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tool")
			writeFile(t, path, "payload", 0755)
			p := testPolicy(t, root)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			change := func() {
				var err error
				switch mutation {
				case "data":
					err = os.WriteFile(path, []byte("changed"), 0755)
					if err == nil {
						err = os.Chtimes(path, time.Unix(1, 0), time.Unix(1, 0))
					}
				case "mode":
					err = os.Chmod(path, 0644)
				case "owner":
					if os.Geteuid() != 0 {
						t.Skip("ownership mutation requires root")
					}
					err = os.Chown(path, 1, 1)
				case "retarget":
					other := filepath.Join(root, "other")
					writeFile(t, other, "payload", 0755)
					err = os.Rename(other, path)
				case "grow":
					err = os.WriteFile(path, []byte("payload-too-long"), 0755)
				case "cancel":
					cancel()
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			hooks := rangeHooks{afterRead: change}
			if mutation == "grow" {
				hooks = rangeHooks{beforeRead: change}
			}
			rangeReadHooks.Store(p, hooks)
			t.Cleanup(func() { rangeReadHooks.Delete(p) })
			got, status := p.HashExecutable(ctx, path, 7)
			want := StatusChangedDuringCapture
			if mutation == "grow" {
				want = StatusLimitExceeded
			}
			if mutation == "cancel" {
				want = StatusUnknown
			}
			assertHashStatus(t, got, status, want)
			if got.WorkBytes == 0 || got.WorkBytes > 8 {
				t.Fatalf("work not accounted: %+v", got)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, status := testPolicy(t, t.TempDir()).HashExecutable(ctx, "/missing", 32)
	assertHashStatus(t, got, status, StatusUnknown)
}

func TestVisibleReadRootsConfiguredOnly(t *testing.T) {
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	masked := filepath.Join(root, "private.privmask")
	denied := filepath.Join(root, "denied")
	child := filepath.Join(denied, "exception")
	for _, path := range []string{plain, masked, child} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(masked, alias); err != nil {
		t.Fatal(err)
	}
	plainAlias := filepath.Join(root, "plain-alias")
	if err := os.Symlink(plain, plainAlias); err != nil {
		t.Fatal(err)
	}
	cfg := config.InspectionConfig{ReadRoots: []string{root, masked, alias, denied, child, plainAlias}, DenyPaths: []string{denied}, SensitiveMasks: []string{"*.privmask"}}
	p, err := NewPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	want := []string{root, child, plainAlias}
	got, omitted := p.VisibleReadRoots()
	if omitted != 3 || !reflect.DeepEqual(got, want) {
		t.Fatalf("roots=%q omitted=%d want=%q", got, omitted, want)
	}
	got[0] = "/changed"
	cfg.ReadRoots[0] = "/also-changed"
	again, count := p.VisibleReadRoots()
	if count != omitted || !reflect.DeepEqual(again, want) {
		t.Fatalf("snapshot not independent: %q", again)
	}
}

// A deterministic context exercises the checkpoint after the first chunk,
// without filesystem timing, sleeps or a mutable global test hook.
type hashCheckpointContext struct {
	context.Context
	checks int
}

func (c *hashCheckpointContext) Err() error {
	c.checks++
	if c.checks >= 3 {
		return context.Canceled
	}
	return nil
}

func TestHashExecutableCancellationBetweenChunks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tool")
	writeFile(t, path, string(bytes.Repeat([]byte{0xff}, 64<<10)), 0755)
	ctx := &hashCheckpointContext{Context: context.Background()}
	got, status := testPolicy(t, root).HashExecutable(ctx, path, 64<<10)
	assertHashStatus(t, got, status, StatusUnknown)
	if got.WorkBytes != 32<<10 {
		t.Fatalf("cancellation checkpoint read %d bytes", got.WorkBytes)
	}
}

func TestHashExecutableSymlinkRetarget(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			safe := filepath.Join(root, "safe")
			secret := filepath.Join(root, ".env")
			link := filepath.Join(root, "link")
			writeFile(t, safe, "safe", 0755)
			writeFile(t, secret, "secret", 0755)
			if err := os.Symlink(safe, link); err != nil {
				t.Fatal(err)
			}
			p := testPolicy(t, root)
			retarget := func() {
				replacement := filepath.Join(root, "replacement")
				if err := os.Symlink(secret, replacement); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, link); err != nil {
					t.Fatal(err)
				}
			}
			hooks := rangeHooks{beforeRead: retarget}
			if phase == "after" {
				hooks = rangeHooks{afterRead: retarget}
			}
			rangeReadHooks.Store(p, hooks)
			t.Cleanup(func() { rangeReadHooks.Delete(p) })
			got, status := p.HashExecutable(context.Background(), link, 32)
			assertHashStatus(t, got, status, StatusChangedDuringCapture)
		})
	}
}

func TestVisibleReadRootsRetargetToProtected(t *testing.T) {
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	protected := filepath.Join(root, "protected")
	alias := filepath.Join(root, "alias")
	for _, path := range []string{plain, protected} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(plain, alias); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{alias}}, protected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	got, omitted := p.VisibleReadRoots()
	if len(got) != 0 || omitted != 1 {
		t.Fatalf("protected root disclosed: %q omitted=%d", got, omitted)
	}
}

func TestRootHashExecutableBindAliases(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged container")
	}
	for _, kind := range []string{"masked", "protected"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, ".env")
			alias := filepath.Join(root, "public")
			writeFile(t, source, "synthetic executable sentinel", 0755)
			writeFile(t, alias, "ordinary fixture", 0755)
			if err := unix.Mount(source, alias, "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unix.Unmount(alias, 0); err != nil {
					t.Errorf("unmount: %v", err)
				}
			}()
			var protected []string
			want := StatusWithheld
			if kind == "protected" {
				protected = []string{source}
				want = StatusInspectionDenied
			}
			p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}}, protected...)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			got, status := p.HashExecutable(context.Background(), alias, 32)
			assertHashStatus(t, got, status, want)
			if got.WorkBytes != 0 {
				t.Fatal("private bind alias content read")
			}
		})
	}
}

func TestHashExecutableExact32MiBBoundary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tool")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(32 << 20); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	got, status := p.HashExecutable(context.Background(), path, 32<<20)
	assertHashStatus(t, got, status, StatusOK)
	h := sha256.New()
	var zeros [32 * 1024]byte
	for i := 0; i < 1024; i++ {
		_, _ = h.Write(zeros[:])
	}
	if got.WorkBytes != 32<<20 || got.SHA256 != hex.EncodeToString(h.Sum(nil)) {
		t.Fatalf("boundary hash: %+v", got)
	}
	writeFile(t, filepath.Join(root, "small"), "x", 0755)
	got, status = p.HashExecutable(context.Background(), filepath.Join(root, "small"), math.MaxInt64)
	assertHashStatus(t, got, status, StatusOK)
	raw, err := json.Marshal(ExecutableHash{WorkBytes: 42})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("WorkBytes")) {
		t.Fatal("work counter serialized as evidence")
	}
}

func TestExecutableHashMetadataStability(t *testing.T) {
	before := unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFREG | 0755, Uid: 3, Gid: 4, Nlink: 1, Size: 5,
		Mtim: unix.Timespec{Sec: 6, Nsec: 7}, Ctim: unix.Timespec{Sec: 8, Nsec: 9}}
	if executableHashChanged(before, before) {
		t.Fatal("identical metadata changed")
	}
	for name, mutate := range map[string]func(*unix.Stat_t){
		"device": func(s *unix.Stat_t) { s.Dev++ },
		"inode":  func(s *unix.Stat_t) { s.Ino++ },
		"mode":   func(s *unix.Stat_t) { s.Mode ^= 0100 },
		"uid":    func(s *unix.Stat_t) { s.Uid++ },
		"gid":    func(s *unix.Stat_t) { s.Gid++ },
		"nlink":  func(s *unix.Stat_t) { s.Nlink++ },
		"size":   func(s *unix.Stat_t) { s.Size++ },
		"mtime":  func(s *unix.Stat_t) { s.Mtim.Nsec++ },
		"ctime":  func(s *unix.Stat_t) { s.Ctim.Nsec++ },
	} {
		after := before
		mutate(&after)
		if !executableHashChanged(before, after) {
			t.Errorf("%s mutation accepted", name)
		}
	}
}

func TestVisibleReadRootsMaskedFile(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, ".env")
	alias := filepath.Join(root, "innocent")
	writeFile(t, secret, "synthetic credential", 0755)
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root, secret, alias}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	got, omitted := p.VisibleReadRoots()
	if !reflect.DeepEqual(got, []string{root}) || omitted != 2 {
		t.Fatalf("credential root disclosed: %q omitted=%d", got, omitted)
	}
}
