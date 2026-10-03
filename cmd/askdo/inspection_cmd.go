package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
)

const inspectionCheckScope = "inspection policy decision only; run askdo config check to validate full service configuration"

func runInspection(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(stderr, "usage: askdo inspection check <path> [--config PATH]")
		return 125
	}
	flags := flag.NewFlagSet("inspection check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: askdo inspection check <path> [--config PATH]")
		fmt.Fprintln(stderr, inspectionCheckScope)
		flags.PrintDefaults()
	}
	configPath := flags.String("config", defaultConfigPath, "configuration file")
	paths, err := parseInterleaved(flags, args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil || len(paths) != 1 {
		fmt.Fprintln(stderr, "usage: askdo inspection check <path> [--config PATH]")
		return 125
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "inspection check requires root")
		return 125
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "read config %q: %q\n", *configPath, err.Error())
		return 125
	}
	cfg, err := config.DecodeForFleetMutation(data)
	if err != nil {
		fmt.Fprintf(stderr, "decode config %q: %q\n", *configPath, err.Error())
		return 125
	}
	if err := cfg.ValidateInspection(); err != nil {
		fmt.Fprintf(stderr, "config %q: %q\n", *configPath, err.Error())
		return 125
	}
	p, err := inspection.NewPolicy(cfg.Inspection, append(cfg.CredentialPaths(), *configPath)...)
	if err != nil {
		fmt.Fprintf(stderr, "inspection config %q: %q\n", *configPath, err.Error())
		return 125
	}
	defer p.Close()
	r := p.Check(paths[0])
	fmt.Fprintln(stdout, inspectionCheckScope)
	if r.Allowed {
		fmt.Fprintf(stdout, "ALLOWED requested=%q resolved=%q rule=%q\n", r.Requested, r.Resolved, r.Rule)
		return 0
	}
	fmt.Fprintf(stdout, "DENIED requested=%q resolved=%q reason=%q\n", r.Requested, r.Resolved, r.Rule)
	if r.Err != nil {
		fmt.Fprintf(stderr, "filesystem/mount: %q\n", r.Err.Error())
	}
	return 1
}
