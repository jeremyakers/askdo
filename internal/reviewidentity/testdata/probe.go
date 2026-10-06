// This standalone synthetic probe is used only in the disposable root lane.
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		panic(err)
	}
	status := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && (key == "Uid" || key == "Gid" || key == "Groups" || key == "CapEff" || key == "CapPrm") {
			status[key] = strings.TrimSpace(value)
		}
	}
	home := os.Getenv("HOME")
	_, credErr := os.ReadFile(filepath.Join(home, "credential"))
	_, broadErr := os.ReadFile(filepath.Join(home, "broad-canary"))
	conn, socketErr := net.Dial("unix", filepath.Join(home, "request.sock"))
	if conn != nil {
		_ = conn.Close()
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Status     map[string]string `json:"status"`
		Credential bool              `json:"credential"`
		Broad      bool              `json:"broad"`
		Socket     bool              `json:"socket"`
	}{status, credErr == nil, broadErr == nil, socketErr == nil})
}
