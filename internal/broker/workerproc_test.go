package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type helperProcessState struct {
	Env    []string          `json:"env"`
	UID    int               `json:"uid"`
	GID    int               `json:"gid"`
	Groups []int             `json:"groups"`
	CapEff string            `json:"cap_eff"`
	FDs    int               `json:"fds"`
	FDList map[string]string `json:"fd_list"`
}

func TestAskdoBrokerDefaults(t *testing.T) {
	if defaultSocketPath != "/run/askdo/request.sock" || defaultStorePath != "/var/lib/askdo/jobs.sqlite3" || defaultSpoolRoot != "/var/lib/askdo/jobs" || defaultWorkerBinary != "/usr/local/bin/askdo" || defaultWorkerHome != "/var/lib/askdo-review" {
		t.Fatalf("unexpected broker defaults: %q %q %q %q %q", defaultSocketPath, defaultStorePath, defaultSpoolRoot, defaultWorkerBinary, defaultWorkerHome)
	}
}

func TestProcessWorkerBoundaryAndSingleActive(t *testing.T) {
	binary := buildWorkerHelper(t)
	openWorkerFDCanary(t) // Keep a private broker descriptor open through both launches.
	home := filepath.Join(t.TempDir(), "review-home")
	targetUID, targetGID := uint32(os.Getuid()), uint32(os.Getgid())
	if os.Geteuid() == 0 {
		// The W6 VM suite executes this test as root. Launching the helper as
		// uid 0 would inherit root's full capability set instead of verifying
		// the reviewer boundary, so target the same non-root askdo-review
		// credential the daemon resolves.
		targetUID, targetGID = reviewerTestCredentials(t)
		// The root-owned temp tree is 0700; let the dropped-credential child
		// traverse it to reach the freshly built helper binary. Stop at
		// os.TempDir() itself: it is already world-traversable (1777) and
		// must not be chmoded system-wide.
		for dir := filepath.Dir(binary); dir != "/" && dir != os.TempDir() && strings.HasPrefix(dir, os.TempDir()); dir = filepath.Dir(dir) {
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(binary, 0755); err != nil {
			t.Fatal(err)
		}
	}
	worker := &processWorker{binary: binary, home: home, uid: targetUID, gid: targetGID}
	session, err := worker.Start(context.Background())
	if err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) && errors.Is(pathErr.Err, os.ErrPermission) && os.Geteuid() != 0 {
			t.Skip("host does not permit an unprivileged process to clear supplementary groups")
		}
		t.Fatal(err)
	}
	if _, err := worker.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("second start error=%v", err)
	}
	data, err := io.ReadAll(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	var state helperProcessState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("helper output=%q: %v", data, err)
	}
	wantEnv := []string{"PATH=/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8"}
	if strings.Join(state.Env, "\x00") != strings.Join(wantEnv, "\x00") {
		t.Fatalf("env=%q want=%q", state.Env, wantEnv)
	}
	if state.UID != int(targetUID) || state.GID != int(targetGID) || len(state.Groups) != 0 {
		t.Fatalf("credentials=%+v", state)
	}
	// Only a non-root target proves the boundary: switching from uid 0 to a
	// non-root uid clears the permitted/effective capability sets. A root
	// target would keep them, so the assertion is gated on the target uid.
	if targetUID != 0 && state.CapEff != "0000000000000000" {
		t.Fatalf("non-root reviewer retains capabilities: %+v", state)
	}
	if err := unexpectedWorkerFD(state); err != nil {
		t.Fatal(err)
	}
	second, err := worker.Start(context.Background())
	if err != nil {
		t.Fatalf("start after reap: %v", err)
	}
	data, err = io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Wait(); err != nil {
		t.Fatal(err)
	}
	state = helperProcessState{}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("second helper output=%q: %v", data, err)
	}
	if err := unexpectedWorkerFD(state); err != nil {
		t.Fatal(err)
	}
}

func unexpectedWorkerFD(state helperProcessState) error {
	// No broker file descriptors may be inherited beyond stdin/stdout/stderr.
	// The child Go runtime may create its own anonymous eventpoll/eventfd
	// fds after exec; those are not inherited and are excluded.
	for name, target := range state.FDList {
		if name == "0" || name == "1" || name == "2" {
			continue
		}
		if target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]" {
			continue
		}
		return fmt.Errorf("inherited broker fd %s -> %s (all: %v)", name, target, state.FDList)
	}
	return nil
}

func openWorkerFDCanary(t *testing.T) *os.File {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "private-broker-canary"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("private broker canary is not close-on-exec")
	}
	return file
}

func TestWorkerHelperFDProbe(t *testing.T) {
	// A runner setting must not override the probe's controlled runtime.
	t.Setenv("GODEBUG", "containermaxprocs=1")
	binary := buildWorkerHelper(t)
	canary := openWorkerFDCanary(t)
	wantEnv := []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "LANG=C.UTF-8"}
	for _, inherit := range []bool{false, true} {
		t.Run(fmt.Sprintf("inherit=%t", inherit), func(t *testing.T) {
			command := exec.Command(binary)
			command.Env = append([]string{}, wantEnv...)
			if inherit {
				command.ExtraFiles = []*os.File{canary}
			}
			data, err := command.Output()
			if err != nil {
				t.Fatal(err)
			}
			var state helperProcessState
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatalf("helper output=%q: %v", data, err)
			}
			if strings.Join(state.Env, "\x00") != strings.Join(wantEnv, "\x00") {
				t.Fatal("direct helper inherited the runner environment")
			}
			err = unexpectedWorkerFD(state)
			if !inherit {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if state.FDList["3"] != canary.Name() {
				t.Fatalf("inherited canary fd=%q want=%q (all: %v)", state.FDList["3"], canary.Name(), state.FDList)
			}
			if err == nil || !strings.Contains(err.Error(), "inherited broker fd 3 -> "+canary.Name()) {
				t.Fatalf("inherited canary validation error=%v", err)
			}
		})
	}
}

// reviewerTestCredentials resolves the non-root reviewer credential for a
// root-run boundary test via the same askdo-review lookup the daemon uses,
// falling back to nobody when the account is not provisioned yet.
func reviewerTestCredentials(t *testing.T) (uint32, uint32) {
	t.Helper()
	if uid, gid, err := resolveReviewCredentials(0, 0); err == nil && uid != 0 {
		return uid, gid
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no non-root reviewer account available: %v", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 {
		t.Skip("no non-root reviewer account available")
	}
	return uint32(uid), uint32(gid)
}

func buildWorkerHelper(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "main.go")
	// Disable the helper runtime's retained cgroup quota FD before the snapshot;
	// it is opened after exec, not inherited from the broker.
	program := `//go:debug containermaxprocs=0

package main
import ("encoding/json"; "os"; "strconv"; "strings")
type state struct { Env []string ` + "`json:\"env\"`" + `; UID int ` + "`json:\"uid\"`" + `; GID int ` + "`json:\"gid\"`" + `; Groups []int ` + "`json:\"groups\"`" + `; CapEff string ` + "`json:\"cap_eff\"`" + `; FDs int ` + "`json:\"fds\"`" + `; FDList map[string]string ` + "`json:\"fd_list\"`" + ` }
func main() { groups:=[]int{}; capEff:=""; f,_:=os.Open("/proc/self/status"); s:=bufio.NewScanner(f); for s.Scan(){ if strings.HasPrefix(s.Text(),"Groups:"){ for _,v:=range strings.Fields(strings.TrimPrefix(s.Text(),"Groups:")){ n,_:=strconv.Atoi(v); groups=append(groups,n) } }; if strings.HasPrefix(s.Text(),"CapEff:"){ capEff=strings.TrimSpace(strings.TrimPrefix(s.Text(),"CapEff:")) } }; f.Close(); entries,_:=os.ReadDir("/proc/self/fd"); fds:=0; fdlist:=map[string]string{}; for _,entry:=range entries { if target,err:=os.Readlink("/proc/self/fd/"+entry.Name()); err==nil { fds++; fdlist[entry.Name()]=target } }; json.NewEncoder(os.Stdout).Encode(state{os.Environ(),os.Getuid(),os.Getgid(),groups,capEff,fds,fdlist}) }
`
	program = strings.Replace(program, `import ("encoding/json";`, `import ("bufio"; "encoding/json";`, 1)
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "review-helper")
	command := exec.Command("go", "build", "-o", binary, source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v: %s", err, output)
	}
	return binary
}

func TestProcessWorkerSerializesConcurrentWrites(t *testing.T) {
	// The framing writer relies on WorkerSession.Write serialization. Exercise
	// the mutex directly without requiring a child process.
	writer := &recordingWriteCloser{}
	session := &processWorkerSession{stdin: writer}
	done := make(chan struct{}, 2)
	for _, value := range []string{"one", "two"} {
		go func(value string) {
			_, _ = session.Write([]byte(value))
			done <- struct{}{}
		}(value)
	}
	<-done
	<-done
	if got := writer.String(); got != "onetwo" && got != "twoone" {
		t.Fatalf("interleaved writes=%q", got)
	}
}

type recordingWriteCloser struct {
	strings.Builder
}

func (w *recordingWriteCloser) Close() error { return nil }
