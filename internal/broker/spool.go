package broker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type spoolFiles struct {
	dir          string
	request      string
	stdout       string
	stderr       string
	workerStderr string
	approval     string
	bundle       string
	captureIndex string
}

func createSpool(root string, request []byte) (spoolFiles, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return spoolFiles{}, fmt.Errorf("create spool root: %w", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		return spoolFiles{}, fmt.Errorf("secure spool root: %w", err)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return spoolFiles{}, fmt.Errorf("choose spool name: %w", err)
	}
	dir := filepath.Join(root, hex.EncodeToString(random[:]))
	if err := os.Mkdir(dir, 0700); err != nil {
		return spoolFiles{}, fmt.Errorf("create job spool: %w", err)
	}
	files := spoolFiles{dir: dir, request: filepath.Join(dir, "request.json"), stdout: filepath.Join(dir, "stdout.log"), stderr: filepath.Join(dir, "stderr.log"), workerStderr: filepath.Join(dir, "reviewer-stderr.log"), approval: filepath.Join(dir, "approval.json"), bundle: filepath.Join(dir, "bundle"), captureIndex: filepath.Join(dir, "capture-index.json")}
	for path, data := range map[string][]byte{files.request: request, files.stdout: nil, files.stderr: nil, files.workerStderr: nil, files.approval: nil} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			_ = os.RemoveAll(dir)
			return spoolFiles{}, fmt.Errorf("create spool file: %w", err)
		}
	}
	return files, nil
}
