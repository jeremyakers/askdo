package client

import (
	"fmt"
	"io"
)

func commandHelp(args []string, out io.Writer) bool {
	if len(args) == 0 {
		return false
	}
	var help string
	switch args[0] {
	case "status":
		help = "usage: askdo status JOB_ID [--json]\nShow the current job state or result; --json prints the broker response as JSON."
	case "attach":
		help = "usage: askdo attach JOB_ID [--timeout DURATION]\nFollow an existing job's output and result without submitting it again.\n--timeout limits how long to observe (for example 30s or 5m); 0 waits indefinitely."
	case "cancel":
		help = "usage: askdo cancel --handle-file PATH [--force]\nUse the private CANCEL_HANDLE_FILE printed at submission; never paste its contents.\n--force escalates a stop request. Acknowledgement is not proof of exit; check status or attach.\nLegacy pre-dispatch jobs also accept: askdo cancel JOB_ID"
	case "auto-approve":
		help = "usage: askdo auto-approve status | set N (2..5) | off\nstatus shows your preference and effective threshold; set changes your preference; off disables it.\nThe host and gateway policy caps still apply; score 5 always requires human approval."
	default:
		return false
	}
	for _, arg := range args[1:] {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			fmt.Fprintln(out, help)
			return true
		}
	}
	return false
}
