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
	"time"

	"github.com/jeremyakers/askdo/internal/config"
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
	return reviewTimestampTimeout(args, stdout, stderr, true)
}

func reviewTimestampTimeout(args []string, stdout, stderr io.Writer, legacySeconds bool) int {
	if len(args) == 0 || (args[0] != "set" && args[0] != "clear" && args[0] != "list") {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	verb := args[0]
	command := "review timestamp_timeout " + verb
	if legacySeconds {
		command = "review timestamp " + verb
	}
	path, positional, err := reviewFlags(command, args[1:], stderr)
	if err != nil {
		return 125
	}
	want := map[string]int{"set": 2, "clear": 1, "list": 0}[verb]
	if len(positional) != want {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	if !requireRoot(command, stderr) {
		return 125
	}
	store, err := operator.LoadForReviewPolicyMutation(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", command, err)
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
			if legacySeconds {
				fmt.Fprintln(stdout, "approval timestamps: none (disabled)")
			} else {
				fmt.Fprintln(stdout, "timestamp_timeout: none (disabled)")
			}
			return 0
		}
		if legacySeconds {
			fmt.Fprintln(stdout, "approval timestamps (foreground unreviewed commands only):")
		} else {
			fmt.Fprintln(stdout, "timestamp_timeout (minutes; same terminal, per target user; foreground unreviewed commands only):")
		}
		for _, name := range names {
			seconds := review.ApprovalTimestampUsers[name]
			if legacySeconds {
				fmt.Fprintf(stdout, "  %q: %d seconds\n", name, seconds)
			} else {
				fmt.Fprintf(stdout, "  %q: %g minutes (%s; %d seconds)\n", name, float64(seconds)/60, time.Duration(seconds)*time.Second, seconds)
			}
		}
		return 0
	}
	name := positional[0]
	if verb == "set" {
		var seconds int
		var err error
		if legacySeconds {
			seconds, err = strconv.Atoi(positional[1])
		} else {
			seconds, err = config.ParseTimestampTimeout(positional[1])
		}
		if err != nil || seconds < 30 || seconds > 3600 {
			if legacySeconds {
				fmt.Fprintln(stderr, "review timestamp set: duration must be 30 through 3600 integer seconds")
			} else {
				fmt.Fprintln(stderr, "review timestamp_timeout set: value must be 0.5 through 60 minutes or a duration (30s..1h)")
			}
			return 125
		}
		if review.ApprovalTimestampUsers == nil {
			review.ApprovalTimestampUsers = make(map[string]int)
		}
		review.ApprovalTimestampUsers[name] = seconds
	} else {
		if _, exists := review.ApprovalTimestampUsers[name]; !exists {
			fmt.Fprintf(stderr, "%s: login %q has no timestamp policy\n", command, name)
			return 1
		}
		delete(review.ApprovalTimestampUsers, name)
	}
	if err := review.ResolveApprovalTimestampUsers(); err != nil {
		fmt.Fprintf(stderr, "%s: config not written: %v\n", command, err)
		return 1
	}
	if err := store.Save(operator.SectionReview); err != nil {
		fmt.Fprintf(stderr, "%s: config not written: %v\n", command, err)
		return 1
	}
	if verb == "clear" {
		if err := clearStoredApprovalTimestamps(path, name); err != nil {
			fmt.Fprintf(stderr, "%s: policy saved, but stored timestamps could not be revoked: %v\n", command, err)
			return 1
		}
	}
	if legacySeconds {
		fmt.Fprintf(stdout, "%s approval timestamp policy for %q\n", verb, name)
	} else {
		fmt.Fprintf(stdout, "%s timestamp_timeout policy for %q\n", verb, name)
	}
	if verb == "set" {
		fmt.Fprintln(stderr, "WARNING: after the first approval, foreground unreviewed commands from this UID and terminal for the same resolved target UID skip Telegram approval until the sliding timestamp expires. Changing target requires fresh approval. Agents need a distinct OS account.")
	}
	return 0
}
