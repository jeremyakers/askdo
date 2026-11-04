package broker

import "testing"

func TestExecutionNamePreservesOnlyInstalledConfigMulticall(t *testing.T) {
	for _, tc := range []struct{ requested, resolved, want string }{
		{"/usr/local/bin/askdo-config", "/usr/local/bin/askdo", "/usr/local/bin/askdo-config"},
		{"/bin/sh", "/usr/bin/dash", "/usr/bin/dash"},
		{"sh", "/usr/bin/dash", "/usr/bin/dash"},
		{"/tmp/askdo-config", "/usr/local/bin/askdo", "/usr/local/bin/askdo"},
		{"/usr/local/bin/askdo-config", "/other/askdo", "/other/askdo"},
	} {
		if got := executionName(tc.requested, tc.resolved); got != tc.want {
			t.Errorf("%q -> %q: got %q want %q", tc.requested, tc.resolved, got, tc.want)
		}
	}
}
