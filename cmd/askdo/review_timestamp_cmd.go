package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"sort"
	"strconv"

	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/store"
)

var timestampStorePath = "/var/lib/askdo/jobs.sqlite3"

func clearStoredApprovalTimestamps(configPath, username string) error {
	if timestampStorePath == "/var/lib/askdo/jobs.sqlite3" && configPath != defaultConfigPath {
		return nil
	}
	account, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return err
	}
	jobs, err := store.Open(timestampStorePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer jobs.Close()
	return jobs.ClearApprovalTimestamps(context.Background(), uint32(uid))
}

func reviewTimestamp(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "set" && args[0] != "clear" && args[0] != "list") {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	verb := args[0]
	path, positional, err := reviewFlags("review timestamp "+verb, args[1:], stderr)
	if err != nil {
		return 125
	}
	want := map[string]int{"set": 2, "clear": 1, "list": 0}[verb]
	if len(positional) != want {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	if !requireRoot("review timestamp "+verb, stderr) {
		return 125
	}
	store, err := operator.LoadForReviewPolicyMutation(path)
	if err != nil {
		fmt.Fprintf(stderr, "review timestamp %s: %v\n", verb, err)
		return 1
	}
	review := &store.Config().Review
	if verb == "list" {
		names := make([]string, 0, len(review.ApprovalTimestampUsers))
		for name := range review.ApprovalTimestampUsers {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) == 0 {
			fmt.Fprintln(stdout, "approval timestamps: none (disabled)")
			return 0
		}
		fmt.Fprintln(stdout, "approval timestamps (foreground unreviewed commands only):")
		for _, name := range names {
			fmt.Fprintf(stdout, "  %q: %d seconds\n", name, review.ApprovalTimestampUsers[name])
		}
		return 0
	}
	name := positional[0]
	if verb == "set" {
		seconds, err := strconv.Atoi(positional[1])
		if err != nil || seconds < 30 || seconds > 3600 {
			fmt.Fprintln(stderr, "review timestamp set: duration must be 30 through 3600 integer seconds")
			return 125
		}
		if review.ApprovalTimestampUsers == nil {
			review.ApprovalTimestampUsers = make(map[string]int)
		}
		review.ApprovalTimestampUsers[name] = seconds
	} else {
		if _, exists := review.ApprovalTimestampUsers[name]; !exists {
			fmt.Fprintf(stderr, "review timestamp clear: login %q has no timestamp policy\n", name)
			return 1
		}
		delete(review.ApprovalTimestampUsers, name)
	}
	if err := review.ResolveApprovalTimestampUsers(); err != nil {
		fmt.Fprintf(stderr, "review timestamp %s: config not written: %v\n", verb, err)
		return 1
	}
	if err := store.Save(operator.SectionReview); err != nil {
		fmt.Fprintf(stderr, "review timestamp %s: config not written: %v\n", verb, err)
		return 1
	}
	if verb == "clear" {
		if err := clearStoredApprovalTimestamps(path, name); err != nil {
			fmt.Fprintf(stderr, "review timestamp clear: policy saved, but stored timestamps could not be revoked: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "%s approval timestamp policy for %q\n", verb, name)
	if verb == "set" {
		fmt.Fprintln(stderr, "WARNING: after the first approval, foreground unreviewed commands from this UID and terminal skip Telegram approval until the sliding timestamp expires. Agents need a distinct OS account.")
	}
	return 0
}
