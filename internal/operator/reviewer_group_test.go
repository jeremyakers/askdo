package operator

import (
	"os/user"
	"testing"
)

func TestCredentialOwnershipRejectsInvalidReviewerGroup(t *testing.T) {
	old := lookupGroup
	t.Cleanup(func() { lookupGroup = old })
	for _, gid := range []string{"0", "bad", "-1", "4294967295", "4294967296"} {
		t.Run(gid, func(t *testing.T) {
			lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: gid}, nil }
			if _, _, _, err := credentialOwnership(CredentialKey); err == nil {
				t.Fatal("invalid reviewer group accepted")
			}
		})
	}
	lookupGroup = func(string) (*user.Group, error) {
		t.Fatal("root-only material must not resolve reviewer group")
		return nil, nil
	}
	for _, kind := range []CredentialKind{CredentialCodexToken, CredentialGatewaySecret, CredentialTrust} {
		if _, uid, gid, err := credentialOwnership(kind); err != nil || uid != 0 || gid != 0 {
			t.Fatalf("kind=%v uid=%d gid=%d err=%v", kind, uid, gid, err)
		}
	}
}
