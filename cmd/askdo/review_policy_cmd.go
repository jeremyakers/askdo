package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/jeremyakers/askdo/internal/operator"
)

const reviewUsage = "usage: askdo review mode [required|approval-only] [--config PATH] | review exempt add|remove <username> [--config PATH] | review exempt list [--config PATH]"

func runReview(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	switch args[0] {
	case "mode":
		return reviewMode(args[1:], stdout, stderr)
	case "exempt":
		return reviewExempt(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
}

func reviewFlags(verb string, args []string, stderr io.Writer) (string, []string, error) {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", defaultConfigPath, "configuration file")
	positional, err := parseInterleaved(fs, args)
	return *path, positional, err
}

func reviewMode(args []string, stdout, stderr io.Writer) int {
	path, positional, err := reviewFlags("review mode", args, stderr)
	if err != nil {
		return 125
	}
	if len(positional) > 1 || (len(positional) == 1 && positional[0] != "required" && positional[0] != "approval-only") {
		fmt.Fprintln(stderr, "usage: askdo review mode [required|approval-only] [--config PATH]")
		return 125
	}
	mutating := len(positional) == 1
	if mutating && !requireRoot("review mode", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(path)
	if err != nil {
		fmt.Fprintln(stderr, "review mode:", err)
		return 1
	}
	review := &store.Config().Review
	if !mutating {
		mode := review.Mode
		if mode == "approval_only" {
			mode = "approval-only"
		}
		fmt.Fprintf(stdout, "review mode: %s\n", mode)
		printExemptUsers(stdout, review.ApprovalOnlyUsers)
		return 0
	}
	review.Mode = positional[0]
	if review.Mode == "approval-only" {
		review.Mode = "approval_only"
	}
	if review.Mode == "required" {
		if err := review.ResolveApprovalOnlyUsers(); err != nil {
			fmt.Fprintln(stderr, "review mode: config not written:", err)
			return 1
		}
	}
	if err := store.Save(operator.SectionReview); err != nil {
		fmt.Fprintln(stderr, "review mode: config not written:", err)
		return 1
	}
	fmt.Fprintf(stdout, "review mode set to %s\n", positional[0])
	if review.Mode == "approval_only" {
		fmt.Fprintln(stderr, "WARNING: EVERY submitting UID in the socket group may request unreviewed root execution; Telegram approval is still mandatory.")
	}
	return 0
}

func reviewExempt(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "add" && args[0] != "remove" && args[0] != "list") {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	verb := args[0]
	path, positional, err := reviewFlags("review exempt "+verb, args[1:], stderr)
	if err != nil {
		return 125
	}
	if (verb == "list" && len(positional) != 0) || (verb != "list" && len(positional) != 1) {
		fmt.Fprintln(stderr, reviewUsage)
		return 125
	}
	if verb != "list" && !requireRoot("review exempt "+verb, stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(path)
	if err != nil {
		fmt.Fprintf(stderr, "review exempt %s: %v\n", verb, err)
		return 1
	}
	review := &store.Config().Review
	if verb == "list" {
		printExemptUsers(stdout, review.ApprovalOnlyUsers)
		return 0
	}
	name := positional[0]
	if verb == "add" {
		if review.Mode == "approval_only" {
			fmt.Fprintln(stderr, "review exempt add: exemptions apply only in required mode; global approval-only already skips model review for every submitting UID")
			return 1
		}
		review.ApprovalOnlyUsers = append(review.ApprovalOnlyUsers, name)
	} else {
		index := -1
		for i, existing := range review.ApprovalOnlyUsers {
			if existing == name {
				index = i
				break
			}
		}
		if index < 0 {
			fmt.Fprintf(stderr, "review exempt remove: login %q is not exempt\n", name)
			return 1
		}
		review.ApprovalOnlyUsers = append(review.ApprovalOnlyUsers[:index], review.ApprovalOnlyUsers[index+1:]...)
	}
	// Validate login existence and UID uniqueness through the same resolver
	// used by daemon startup. Save separately checks the entire review section.
	if err := review.ResolveApprovalOnlyUsers(); err != nil {
		fmt.Fprintf(stderr, "review exempt %s: config not written: %v\n", verb, err)
		return 1
	}
	if err := store.Save(operator.SectionReview); err != nil {
		fmt.Fprintf(stderr, "review exempt %s: config not written: %v\n", verb, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s approval-only exemption for %q\n", verb, name)
	if verb == "add" {
		fmt.Fprintln(stderr, "WARNING: any process sharing the exempt user's UID also skips model review; agents need a distinct OS account. Telegram approval remains mandatory.")
	}
	return 0
}

func printExemptUsers(stdout io.Writer, names []string) {
	if len(names) == 0 {
		fmt.Fprintln(stdout, "approval-only exemptions: none")
		return
	}
	fmt.Fprintln(stdout, "approval-only exemptions:")
	for _, name := range names {
		fmt.Fprintf(stdout, "  %q\n", name)
	}
}
