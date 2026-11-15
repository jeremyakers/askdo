package broker

import "testing"

func TestExecutionNamePreservesSubmittedMulticallName(t *testing.T) {
	for _, tc := range []struct{ requested, resolved, want string }{
		{"/usr/local/bin/askdo-config", "/usr/local/bin/askdo", "/usr/local/bin/askdo-config"},
		{"/bin/sh", "/usr/bin/dash", "/bin/sh"},
		{"sh", "/usr/bin/dash", "sh"},
		{"/tmp/askdo-config", "/usr/local/bin/askdo", "/tmp/askdo-config"},
		{"/usr/local/bin/askdo-config", "/other/askdo", "/usr/local/bin/askdo-config"},
	} {
		if got := executionName(tc.requested, tc.resolved); got != tc.want {
			t.Errorf("%q -> %q: got %q want %q", tc.requested, tc.resolved, got, tc.want)
		}
	}
}
