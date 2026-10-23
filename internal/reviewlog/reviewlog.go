// Package reviewlog defines the privacy-limited, local review journal.
package reviewlog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

const Filename = "reviews.jsonl"
const DefaultPath = "/var/lib/askdo/" + Filename

func Path(storePath string) string { return filepath.Join(filepath.Dir(storePath), Filename) }

// Event is an allowlist: never embed manifests, worker operations, inspection
// payloads, or ModelHistoryEntry.Error, all of which may contain private data.
type Event struct {
	Version             int                         `json:"version"`
	Event               string                      `json:"event"`
	Time                time.Time                   `json:"time"`
	JobID               string                      `json:"job_id"`
	Host                string                      `json:"host,omitempty"`
	SubmitterUID        uint32                      `json:"submitter_uid"`
	SubmitterName       string                      `json:"submitter_name,omitempty"`
	TargetUID           uint32                      `json:"target_uid"`
	Mode                string                      `json:"mode,omitempty"`
	Argv                []string                    `json:"argv,omitempty"`
	Entry               string                      `json:"entry,omitempty"`
	Args                []string                    `json:"args,omitempty"`
	CWD                 string                      `json:"cwd,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	Captures            []Capture                   `json:"captures,omitempty"`
	ModelHistory        []Model                     `json:"model_history,omitempty"`
	SuccessfulModel     string                      `json:"successful_model,omitempty"`
	Report              *proto.ReviewReport         `json:"report,omitempty"`
	WithheldRefs        []string                    `json:"withheld_refs,omitempty"`
	WithheldCount       int                         `json:"withheld_count,omitempty"`
	AutoApproval        *proto.AutoApprovalPlan     `json:"auto_approval,omitempty"`
	Inspection          []ObservationCount          `json:"inspection,omitempty"`
	ManifestDigest      string                      `json:"manifest_digest,omitempty"`
	AvailabilityHistory []proto.AvailabilityFailure `json:"availability_history,omitempty"`
	ApprovalReason      string                      `json:"approval_reason,omitempty"`
	State               string                      `json:"state,omitempty"`
	ExitCode            *int                        `json:"exit_code,omitempty"`
	ResultKind          string                      `json:"result_kind,omitempty"`
	Signal              *int                        `json:"signal,omitempty"`
	ApprovalKind        string                      `json:"approval_kind,omitempty"`
	Decision            string                      `json:"decision,omitempty"`
}

type Capture struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Masked bool   `json:"masked"`
}

type Model struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

type ObservationCount struct {
	Operation string `json:"operation"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Count     int    `json:"count"`
}

// Append opens lazily and closes after each record so rename-based rotation
// needs no daemon signal. A record is emitted by exactly one O_APPEND write.
// The daemon runs as root; isolated non-root tests own their own journal.
func Append(path string, event Event) (err error) {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode review log: %w", err)
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return fmt.Errorf("open review log: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("review log must be a regular file owned by the broker UID")
	}
	if err := f.Chmod(0600); err != nil {
		return err
	}
	n, err := f.Write(append(data, '\n'))
	if err != nil {
		return err
	}
	if n != len(data)+1 {
		return io.ErrShortWrite
	}
	return nil
}
