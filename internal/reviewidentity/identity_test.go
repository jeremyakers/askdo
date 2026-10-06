package reviewidentity

import (
	"errors"
	"os/user"
	"strconv"
	"testing"
)

func TestResolveFixedReviewer(t *testing.T) {
	for _, test := range []struct {
		uid     uint32
		primary string
	}{{7, "100"}, {7, "995"}, {995, "995"}, {7, "not-an-execution-id"}} {
		t.Run(strconv.FormatUint(uint64(test.uid), 10)+":"+test.primary, func(t *testing.T) {
			got, err := resolve(func(name string) (*user.User, error) {
				if name != "askdo-review" {
					t.Fatalf("unexpected account %q", name)
				}
				return &user.User{Uid: strconv.FormatUint(uint64(test.uid), 10), Gid: test.primary}, nil
			}, func(name string) (*user.Group, error) {
				if name != "askdo-review" {
					t.Fatalf("unexpected group %q", name)
				}
				return &user.Group{Gid: "995"}, nil
			})
			if err != nil || got != (Identity{UID: test.uid, GID: 995}) {
				t.Fatalf("identity=%+v err=%v", got, err)
			}
		})
	}
}

func TestResolveRejectsInvalidIdentityWithoutFallback(t *testing.T) {
	for _, role := range []string{"account", "group"} {
		for _, value := range []string{"missing", "nil", "", "bad", "-1", "+7", " 7", "0", "4294967295", "4294967296", "18446744073709551616"} {
			t.Run(role+"/"+value, func(t *testing.T) {
				got, err := resolve(func(name string) (*user.User, error) {
					if name != "askdo-review" {
						t.Fatalf("fallback lookup %q", name)
					}
					uid := "7"
					if role == "account" {
						if value == "nil" {
							return nil, nil
						}
						if value == "missing" {
							return nil, errors.New("missing")
						}
						uid = value
					}
					return &user.User{Uid: uid, Gid: "100"}, nil
				}, func(name string) (*user.Group, error) {
					if name != "askdo-review" {
						t.Fatalf("fallback lookup %q", name)
					}
					gid := "995"
					if role == "group" {
						if value == "nil" {
							return nil, nil
						}
						if value == "missing" {
							return nil, errors.New("missing")
						}
						gid = value
					}
					return &user.Group{Gid: gid}, nil
				})
				if err == nil || got != (Identity{}) {
					t.Fatalf("invalid identity=%+v err=%v", got, err)
				}
			})
		}
	}
}
