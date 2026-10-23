package reviewlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

func readIDs(t *testing.T, path string) (ids []string, bad int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			bad++
			continue
		}
		ids = append(ids, e.JobID)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return
}

func mustAppend(t *testing.T, p, id string) {
	t.Helper()
	if err := Append(p, Event{JobID: id}); err != nil {
		t.Fatal(err)
	}
}

func appendRaw(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(errors.Join(err, f.Close()))
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// hooks restores the package test seams even if the test fails.
func hooks(t *testing.T) {
	t.Helper()
	w, b := writeRecord, beforeLock
	t.Cleanup(func() { writeRecord, beforeLock = w, b })
}

func TestAppendAfterPreseededPartialTail(t *testing.T) {
	// Given a journal with a valid record then a crash-truncated fragment
	p := filepath.Join(t.TempDir(), Filename)
	mustAppend(t, p, "a")
	appendRaw(t, p, `{"job_id":"par`)
	// When the next record is appended
	mustAppend(t, p, "b")
	// Then both complete records survive and only the fragment is bad
	ids, bad := readIDs(t, p)
	if !slices.Equal(ids, []string{"a", "b"}) || bad != 1 {
		t.Fatalf("ids=%v bad=%d", ids, bad)
	}
}

func TestAppendAfterInjectedWriteFailures(t *testing.T) {
	cases := map[string]func(*os.File, []byte) (int, error){
		"partial+error": func(f *os.File, b []byte) (int, error) {
			n, err := f.Write(b[:len(b)/2])
			if err != nil {
				return n, err
			}
			return n, errors.New("injected")
		},
		"short no error": func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) },
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			hooks(t)
			// Given a failed append that left a partial record
			p := filepath.Join(t.TempDir(), Filename)
			mustAppend(t, p, "a")
			orig := writeRecord
			writeRecord = w
			err := Append(p, Event{JobID: "lost"})
			writeRecord = orig
			if err == nil {
				t.Fatal("expected failure")
			}
			// When a later append succeeds
			mustAppend(t, p, "b")
			// Then it is independently readable
			ids, bad := readIDs(t, p)
			if !slices.Equal(ids, []string{"a", "b"}) || bad != 1 {
				t.Fatalf("ids=%v bad=%d", ids, bad)
			}
		})
	}
}

// The waiter passes its ownership check (old size observed) before the
// lock holder half-writes; its tail check must still see the fragment.
func TestAppendWaiterUsesTailAfterLock(t *testing.T) {
	hooks(t)
	// Given a journal and appender A holding the lock before writing
	p := filepath.Join(t.TempDir(), Filename)
	mustAppend(t, p, "a")
	inWrite := make(chan struct{})
	release := make(chan struct{})
	waiterReady := make(chan struct{})
	var calls int
	var mu sync.Mutex
	next := func() int { mu.Lock(); defer mu.Unlock(); calls++; return calls }
	beforeLock = func() {
		if next() == 2 { // first call is A, second is waiter B
			close(waiterReady)
		}
	}
	orig := writeRecord
	first := true
	writeRecord = func(f *os.File, b []byte) (int, error) {
		if !first {
			return orig(f, b)
		}
		first = false
		close(inWrite)
		<-release // B has already observed the pre-fragment size
		n, err := f.Write(b[:len(b)/2])
		if err != nil {
			return n, err
		}
		return n, errors.New("injected")
	}
	errA := make(chan error, 1)
	go func() { errA <- Append(p, Event{JobID: "lost"}) }()
	<-inWrite
	errB := make(chan error, 1)
	go func() { errB <- Append(p, Event{JobID: "b"}) }()
	// When B has passed its pre-lock checks and A then fails
	<-waiterReady
	close(release)
	if err := <-errA; err == nil {
		t.Fatal("A should fail")
	}
	if err := <-errB; err != nil {
		t.Fatal(err)
	}
	// Then B's record is separate from A's fragment
	ids, bad := readIDs(t, p)
	if !slices.Equal(ids, []string{"a", "b"}) || bad != 1 {
		t.Fatalf("ids=%v bad=%d", ids, bad)
	}
}

func TestAppendConcurrentRecordsIndependent(t *testing.T) {
	// Given many concurrent appenders
	p := filepath.Join(t.TempDir(), Filename)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Append(p, Event{JobID: fmt.Sprint("j", i)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// Then every record is complete and separate
	ids, bad := readIDs(t, p)
	if len(ids) != 32 || bad != 0 {
		t.Fatalf("ids=%d bad=%d", len(ids), bad)
	}
}

func TestAppendKeepsOwnerOnlyModeAndRejectsSymlink(t *testing.T) {
	// Given a new journal
	p := filepath.Join(t.TempDir(), Filename)
	mustAppend(t, p, "a")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// Then it is 0600
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// When appending through a symlink
	l := filepath.Join(filepath.Dir(p), "link")
	if err := os.Symlink(p, l); err != nil {
		t.Fatal(err)
	}
	// Then it is rejected
	if Append(l, Event{JobID: "x"}) == nil {
		t.Fatal("symlink accepted")
	}
}
