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

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/guided"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

var version = "dev"

const help = `Awarely Scan — SBOM inventory, API check and source sync

Usage:
  awarely-scan                      Guided setup when run in a terminal
  awarely-scan guided               Guided Linux/npm/Python/Java workflow
  awarely-scan app --path DIR --output FILE [--name NAME]
  awarely-scan host --output FILE [--select 'nginx*,openssl'] [--name NAME]
  awarely-scan host --all-packages --output FILE
  awarely-scan import --input FILE --output FILE [--name NAME]
  awarely-scan version
  awarely-scan check --input FILE --credentials FILE --output REPORT.json
  awarely-scan sync --input FILE --credentials FILE --output RECEIPT.json

app: npm lockfile v2/v3, package.json, requirements.txt in the selected directory.
import: CycloneDX JSON from Syft or another producer; application packages only.
host: auto-detected Debian/Ubuntu (DEB), Rocky/AlmaLinux/Amazon Linux (RPM); focused selection.

Options:
  --output FILE     New CycloneDX 1.6 JSON file (required; never overwrites)
  --name NAME       Explicit application label (default: application/linux-host)
  --timeout N       Deadline in seconds, 1–300 (default: 60)
  --root DIR        Host root filesystem (default: /; also accepts offline roots)
  --select LIST     Comma-separated package names or trailing * selectors
  --all-packages    Include all installed packages (explicit opt-in)

Exit codes: 0 selected inputs processed; 2 invalid input/error; 3 partial coverage;
            4 output error; 5 interrupted/deadline; 6 API operation failed.
Native host/app/import: no network, installation, project execution, credentials or telemetry.
Guided mode: optional verified Syft preparation/execution after explicit consent.
Local collection never uses network or credentials. API operations are explicit.
check does not change saved inventory. sync replaces only the credential's source.
Credentials: protected JSON file (chmod 600), or --credentials - for stdin.
sync options: --expected-revision REV --idempotency-key KEY --allow-empty
Remote operations return 6 on failure; a successful check is not an all-clear.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	args := os.Args[1:]
	if len(args) == 0 {
		if stdinTerminal() {
			args = []string{"guided"}
		}
	}
	os.Exit(run(ctx, args, os.Stdout, os.Stderr))
}

func run(parent context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(out, help)
		return 0
	}
	if args[0] == "guided" {
		if len(args) != 1 {
			fmt.Fprintln(errOut, "Guided mode accepts no arguments. Use host/app/import/check/sync for automation.")
			return 2
		}
		_, noColor := os.LookupEnv("NO_COLOR")
		color := false
		if f, ok := out.(*os.File); ok {
			color = fileTerminal(f) && !noColor && os.Getenv("TERM") != "dumb"
		}
		return guided.RunWithColor(parent, os.Stdin, out, errOut, version, color)
	}
	if args[0] == "version" {
		fmt.Fprintln(out, "awarely-scan", version)
		return 0
	}
	if args[0] == "check" || args[0] == "sync" {
		return runRemote(parent, args, out, errOut)
	}
	mode := args[0]
	if mode != "app" && mode != "host" && mode != "import" {
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
	} else if mode == "import" {
		fs.StringVar(&path, "input", "", "selected CycloneDX SBOM")
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
	if (mode == "import" && path == "") || fs.NArg() != 0 || *output == "" || *output == "-" || *timeout < 1 || *timeout > 300 {
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
	} else if mode == "import" {
		r, err = inventory.Import(ctx, path)
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
	for _, notice := range r.Notices {
		fmt.Fprintln(errOut, "Notice:", notice)
	}
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

func runRemote(parent context.Context, args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	input := fs.String("input", "", "SBOM")
	credentials := fs.String("credentials", "", "protected credentials")
	output := fs.String("output", "", "result")
	revision := fs.String("expected-revision", "", "revision")
	key := fs.String("idempotency-key", "", "retry key")
	empty := fs.Bool("allow-empty", false, "confirm empty source")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, help)
			return 0
		}
		fmt.Fprintln(errOut, "Invalid remote arguments. Run awarely-scan help.")
		return 2
	}
	if fs.NArg() != 0 || *input == "" || *credentials == "" || *output == "" || *output == "-" {
		fmt.Fprintln(errOut, "Remote commands require --input, --credentials and a new --output file.")
		return 2
	}
	if args[0] == "check" && (*revision != "" || *key != "" || *empty) {
		fmt.Fprintln(errOut, "Revision, idempotency and empty confirmation options apply only to sync.")
		return 2
	}
	if _, err := os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(errOut, "Choose a new output file before contacting the API.")
		return 4
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	snapshot, err := api.ReadSnapshot(ctx, *input)
	if err != nil {
		fmt.Fprintln(errOut, "Invalid local inventory:", err)
		return 2
	}
	snapshot.CollectorVersion = version
	c, err := api.ReadCredentials(ctx, *credentials, os.Stdin)
	if err != nil {
		fmt.Fprintln(errOut, "Credentials rejected:", err)
		return 2
	}
	client := api.NewClient(c)
	var result []byte
	if args[0] == "check" {
		result, err = client.Check(ctx, snapshot)
	} else {
		result, err = client.Sync(ctx, snapshot, *revision, *key, *empty)
	}
	if err != nil {
		fmt.Fprintln(errOut, "Remote operation failed:", err)
		if ctx.Err() != nil {
			return 5
		}
		return 6
	}
	if err = safeio.WriteNew(*output, append(result, '\n')); err != nil {
		fmt.Fprintln(errOut, "The API operation completed, but its result could not be saved. Check destination permissions; a sync may already be committed.")
		return 4
	}
	if args[0] == "check" {
		fmt.Fprintln(errOut, "Complete check report saved. Review matches and unevaluated components. Saved inventory was not changed.")
	} else {
		fmt.Fprintln(errOut, "Source inventory synchronized. Commit receipt saved. Other sources were preserved.")
	}
	return 0
}
