package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

var version = "dev"

const help = `Awarely Scan — local SBOM generator

Usage:
  awarely-scan app --path DIR --output FILE [--name NAME]
  awarely-scan host --output FILE [--select 'nginx*,openssl'] [--name NAME]
  awarely-scan host --all-packages --output FILE
  awarely-scan version

app: npm lockfile v2/v3, package.json, requirements.txt in the selected directory.
host: Debian/Ubuntu installed package metadata; focused selection by default.

Options:
  --output FILE     New CycloneDX 1.6 JSON file (required; never overwrites)
  --name NAME       Explicit application label (default: application/linux-host)
  --timeout N       Deadline in seconds, 1–300 (default: 60)
  --root DIR        Host root filesystem (default: /; also accepts offline roots)
  --select LIST     Comma-separated DEB names or trailing * selectors
  --all-packages    Include all installed DEB packages (explicit opt-in)

Exit codes: 0 selected inputs processed; 2 invalid input/error; 3 partial coverage;
            4 output error; 5 interrupted/deadline; 6 API mode not available.
No network, installation, project execution, credentials or telemetry.
This preview exports inventory only. API check/sync and Jenkins are planned.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(parent context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(out, help)
		return 0
	}
	if args[0] == "version" {
		fmt.Fprintln(out, "awarely-scan", version)
		return 0
	}
	if args[0] == "check" || args[0] == "sync" {
		fmt.Fprintln(errOut, "API check/sync are not available in this local preview. Nothing was sent.")
		return 6
	}
	mode := args[0]
	if mode != "app" && mode != "host" {
		fmt.Fprint(errOut, help)
		return 2
	}
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "output")
	name := fs.String("name", "", "name")
	timeout := fs.Int("timeout", 60, "deadline")
	var path, selection string
	var all bool
	if mode == "app" {
		fs.StringVar(&path, "path", ".", "application directory")
	} else {
		fs.StringVar(&path, "root", "/", "Linux root")
		fs.StringVar(&selection, "select", inventory.DefaultSelection, "package selection")
		fs.BoolVar(&all, "all-packages", false, "all packages")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, help)
			return 0
		}
		fmt.Fprintln(errOut, "Invalid arguments. Run awarely-scan help.")
		return 2
	}
	if fs.NArg() != 0 || *output == "" || *output == "-" || *timeout < 1 || *timeout > 300 {
		fmt.Fprintln(errOut, "Provide --output FILE and a timeout between 1 and 300 seconds; positional arguments are not accepted.")
		return 2
	}
	if all {
		selectedExplicitly := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "select" {
				selectedExplicitly = true
			}
		})
		if selectedExplicitly {
			fmt.Fprintln(errOut, "Choose either --select or --all-packages.")
			return 2
		}
	}
	if *name == "" {
		*name = "application"
		if mode == "host" {
			*name = "linux-host"
		}
	}
	if !inventory.ValidText(*name, 120) {
		fmt.Fprintln(errOut, "Invalid application name.")
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(*timeout)*time.Second)
	defer cancel()
	var r inventory.Result
	var err error
	if mode == "app" {
		r, err = inventory.App(ctx, path)
	} else {
		r, err = inventory.Host(ctx, path, selection, all)
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Scan interrupted or deadline exceeded; no inventory written.")
		return 5
	}
	if err != nil {
		fmt.Fprintln(errOut, "Scan failed:", err)
		return 2
	}
	b, err := inventory.Marshal(r, *name, version, time.Now())
	if err != nil {
		fmt.Fprintln(errOut, "Cannot generate inventory:", err)
		return 2
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Deadline exceeded; no inventory written.")
		return 5
	}
	if err = safeio.WriteNew(*output, b); err != nil {
		fmt.Fprintln(errOut, "Cannot publish output; choose a new file in a writable directory.")
		return 4
	}
	fmt.Fprintf(errOut, "Wrote %d unique components from %d selected inputs. No data was sent.\n", len(r.Components), len(r.Inputs))
	if len(r.Warnings) > 0 {
		for _, w := range r.Warnings {
			fmt.Fprintln(errOut, "Coverage warning:", w)
		}
		fmt.Fprintln(errOut, "Partial inventory: review coverage before importing. This is not a vulnerability check.")
		return 3
	}
	fmt.Fprintln(errOut, "Coverage applies only to the selected inputs, not to the complete host or application. This is not a vulnerability check.")
	return 0
}
