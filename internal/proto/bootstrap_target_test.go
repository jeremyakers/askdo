package proto

import (
	"encoding/json"
	"testing"
)

func TestBootstrapTargetCredentialWire(t *testing.T) {
	boot := targetBootstrap(1001, "target", nil)
	body, _ := json.Marshal(boot)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields)
	fields["target_gid"] = json.RawMessage(`0`)
	fields["target_groups"] = json.RawMessage(`[0,17]`)
	fields["target_group_names"] = json.RawMessage(`{"0":"root","17":"operators"}`)
	body, _ = json.Marshal(fields)
	if err := StrictUnmarshal(body, &boot); err != nil {
		t.Fatalf("credential bootstrap rejected: %v", err)
	}
	if err := ValidateWorkerMessage(&boot, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(boot)
	var got map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &got)
	for _, key := range []string{"target_gid", "target_groups", "target_group_names"} {
		if string(got[key]) != string(fields[key]) {
			t.Errorf("lost %s: %s", key, encoded)
		}
	}
}

func targetBootstrap(uid uint32, name string, env []string) Bootstrap {
	return Bootstrap{
		Type: "bootstrap", Host: "host", TargetUID: uid, TargetName: name, RequestID: "2026-09-27_#1",
		SubmitterUID: 1000, SubmitterName: "agent",
		Operation:            WorkerOperation{Mode: "argv", Argv: []string{"/usr/bin/id"}, CWD: "/work", Reason: "x"},
		ExecutionEnvironment: env,
		ReviewDeadlineUnixMS: 1,
		ConfigProjection: ConfigProjection{
			Models:   []ProjectedModel{{Name: "model", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", RequestTimeoutMS: 1}},
			Limits:   WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1},
			Telegram: WorkerTelegram{TokenFile: "/key", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 1},
		},
	}
}

func TestBootstrapTargetIdentityAndEnvironmentProjection(t *testing.T) {
	rootEnv := []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "PWD=/work"}
	targetEnv := []string{"PATH=/usr/bin:/bin", "HOME=/home/tyme", "LANG=C.UTF-8", "PWD=/work", "USER=tyme", "LOGNAME=tyme"}
	for name, boot := range map[string]Bootstrap{
		"root":                     targetBootstrap(0, "", rootEnv),
		"named-target":             targetBootstrap(1001, "tyme", targetEnv),
		"unnamed-target-legacy":    targetBootstrap(1, "", []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8", "PWD=/work"}),
		"target-without-env":       targetBootstrap(1001, "tyme", nil),
		"target-empty-home-passwd": targetBootstrap(1001, "tyme", []string{"PATH=/usr/bin:/bin", "HOME=", "LANG=C.UTF-8", "PWD=/work", "USER=tyme", "LOGNAME=tyme"}),
	} {
		t.Run("valid/"+name, func(t *testing.T) {
			if err := ValidateWorkerMessage(&boot, BrokerToWorker); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	for name, boot := range map[string]Bootstrap{
		"root-named":               targetBootstrap(0, "tyme", rootEnv),
		"root-with-user":           targetBootstrap(0, "", append(rootEnv, "USER=root", "LOGNAME=root")),
		"root-foreign-home":        targetBootstrap(0, "", []string{"PATH=/usr/bin:/bin", "HOME=/home/tyme", "LANG=C.UTF-8", "PWD=/work"}),
		"target-missing-user":      targetBootstrap(1001, "tyme", targetEnv[:4]),
		"target-wrong-user":        targetBootstrap(1001, "tyme", []string{"PATH=/usr/bin:/bin", "HOME=/home/tyme", "LANG=C.UTF-8", "PWD=/work", "USER=root", "LOGNAME=tyme"}),
		"target-duplicate-user":    targetBootstrap(1001, "tyme", []string{"PATH=/usr/bin:/bin", "HOME=/home/tyme", "LANG=C.UTF-8", "PWD=/work", "USER=tyme", "USER=tyme"}),
		"target-extra-variable":    targetBootstrap(1001, "tyme", append(targetEnv, "ASKDO_BUNDLE=/private")),
		"unnamed-target-with-user": targetBootstrap(1, "", []string{"PATH=/usr/bin:/bin", "HOME=/x", "LANG=C.UTF-8", "PWD=/work", "USER=x", "LOGNAME=x"}),
		"target-name-nul":          targetBootstrap(1001, "ty\x00me", nil),
	} {
		t.Run("invalid/"+name, func(t *testing.T) {
			if err := ValidateWorkerMessage(&boot, BrokerToWorker); err == nil {
				t.Fatalf("accepted %+v", boot.ExecutionEnvironment)
			}
		})
	}
}
