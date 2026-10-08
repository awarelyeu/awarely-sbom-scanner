package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/producer"
)

const syftHelp = `Usage:
  awarely-scan syft --ecosystem java|python|npm|other --path DIR --output FILE
                    [--name NAME] [--allow-download] [--timeout N]

Runs only the managed Syft version pinned to this Awarely release. The selected
directory must already contain built artifacts or installed dependencies.
No project commands are executed and no API credentials are used.
--allow-download explicitly permits a missing pinned tool to be downloaded.
Without this flag, a verified cached archive is required; collection is offline.
--timeout bounds preparation and collection together (1-300 seconds; default 300).
The runner is not an OS sandbox. Isolate untrusted build inputs at the OS level.
Exit codes match local collection, including 3 for a partial inventory.
`

func runSyft(parent context.Context, args []string, errOut io.Writer) int {
	fs := flag.NewFlagSet("syft", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kind := fs.String("ecosystem", "", "ecosystem")
	path := fs.String("path", "", "existing application directory")
	output := fs.String("output", "", "new inventory file")
	name := fs.String("name", "application", "application label")
	allow := fs.Bool("allow-download", false, "approve pinned tool download")
	seconds := fs.Int("timeout", 300, "total deadline")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(errOut, syftHelp)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	validKind := *kind == "java" || *kind == "python" || *kind == "npm" || *kind == "other"
	if !validKind || fs.NArg() != 0 || *path == "" || *output == "" || *output == "-" || *seconds < 1 || *seconds > 300 || !inventory.ValidText(*name, 120) {
		fmt.Fprint(errOut, syftHelp)
		return 2
	}
	// Reject invalid selections before any approved network access.
	target, err := filepath.EvalSymlinks(*path)
	if err == nil {
		target, err = filepath.Abs(target)
	}
	if err != nil || filepath.Clean(target) == "/" {
		fmt.Fprintln(errOut, "Select an existing application directory, not the host root.")
		return 2
	}
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		fmt.Fprintln(errOut, "Select an existing readable application directory.")
		return 2
	}
	cache, err := producer.CachePath()
	if err != nil {
		fmt.Fprintln(errOut, "Tool preparation failed:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(*seconds)*time.Second)
	defer cancel()
	err = producer.Prepare(ctx, cache, *allow)
	var r inventory.Result
	if err == nil {
		r, err = producer.Scan(ctx, cache, target, *kind)
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Scan interrupted or deadline exceeded; no inventory written.")
		return 5
	}
	if err != nil {
		fmt.Fprintln(errOut, "Managed collection failed:", err)
		return 2
	}
	return publishInventory(ctx, r, *name, *output, errOut)
}
