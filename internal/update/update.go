package update

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const Help = `Usage:
  awarely-scan update --check             Show the eligible release; do not install
  awarely-scan update                     Verify and install after confirmation
  awarely-scan update --version TAG       Select an exact newer published release
  awarely-scan update --prerelease        Explicitly include prereleases
  awarely-scan update --yes               Approve a noninteractive update
  awarely-scan update --rollback          Restore the previous binary after confirmation

Stable installations stay on stable releases. Existing prereleases also see
prereleases. Update never downgrades; rollback restores only the local backup.
Network access is explicit. No account/token, sudo or system gh is required.
Syft remains pinned to the tested version in each Awarely release.
Update failures return exit code 7. No update runs during ordinary scans.
`

func approved(in io.Reader, out io.Writer, yes bool) bool {
	if yes {
		return true
	}
	fmt.Fprint(out, "Continue (yes/no) [no]: ")
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024), 1024)
	return scanner.Scan() && strings.TrimSpace(scanner.Text()) == "yes"
}
func Run(parent context.Context, args []string, current string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	check := fs.Bool("check", false, "check only")
	target := fs.String("version", "", "exact tag")
	pre := fs.Bool("prerelease", false, "include prereleases")
	yes := fs.Bool("yes", false, "approve")
	rollback := fs.Bool("rollback", false, "restore previous")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			fmt.Fprint(out, Help)
			return 0
		}
		fmt.Fprint(errOut, Help)
		return 2
	}
	if fs.NArg() != 0 || (*rollback && (*check || *target != "" || *pre)) || (*check && *yes) || (*target != "" && !validVersion(*target)) {
		fmt.Fprint(errOut, Help)
		return 2
	}
	fail := func(e error) int { fmt.Fprintln(errOut, "Update stopped:", e); return 7 }
	if runtime.GOOS != "linux" || verifierPins[runtime.GOARCH] == "" || os.Geteuid() == 0 {
		return fail(errors.New("updates require Linux amd64/arm64 as a regular user, without sudo"))
	}
	if !validVersion(current) {
		return fail(errors.New("development builds cannot self-update; install an official release"))
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	if *rollback {
		exe, e := executablePath()
		if e != nil {
			return fail(e)
		}
		i, e := openInstallation(exe)
		if e != nil {
			return fail(e)
		}
		defer i.close()
		old, e := i.read(i.name, maxBinary)
		if e != nil {
			return fail(e)
		}
		b, e := i.previous(old)
		if e != nil {
			return fail(e)
		}
		fmt.Fprintf(out, "Rollback: %s -> %s\nRestores the previous CLI and its pinned Syft version. Inventories and credentials are unchanged.\n", current, b.Version)
		if !approved(in, out, *yes) {
			fmt.Fprintln(out, "Rollback cancelled. Installed binary unchanged.")
			return 0
		}
		if e = i.replace(ctx, old, b.Binary, current, b.Version, false); e != nil {
			return fail(e)
		}
		fmt.Fprintf(out, "Restored %s. Run awarely-scan version to confirm.\n", b.Version)
		return 0
	}
	c := client()
	defer c.CloseIdleConnections()
	tag, e := discover(ctx, c, current, *target, *pre || strings.Contains(current, "-"))
	if e != nil {
		return fail(e)
	}
	fmt.Fprintf(out, "Installed: %s\nEligible release: %s\n", current, tag)
	if tag == current {
		fmt.Fprintln(out, "Already on this release. Nothing changed.")
		return 0
	}
	if *check {
		fmt.Fprintln(out, "No files changed. Run awarely-scan update to install after verification.")
		return 0
	}
	exe, e := executablePath()
	if e != nil {
		return fail(e)
	}
	i, e := openInstallation(exe)
	if e != nil {
		return fail(e)
	}
	defer i.close()
	old, e := i.read(i.name, maxBinary)
	if e != nil {
		return fail(e)
	}
	fmt.Fprintln(out, "This downloads the release and a temporary pinned GitHub verifier from GitHub, verifies provenance, and keeps a private rollback backup. No account or system gh is needed.")
	fmt.Fprintln(out, "Syft follows the tested pin in the selected Awarely release; its next use may request a verified download.")
	if !approved(in, out, *yes) {
		fmt.Fprintln(out, "Update cancelled. Installed binary unchanged.")
		return 0
	}
	temp, e := os.MkdirTemp(i.state, "download-")
	if e != nil {
		return fail(e)
	}
	defer os.RemoveAll(temp)
	fmt.Fprintln(out, "Downloading and verifying the release...")
	next, e := verifiedBinary(ctx, c, temp, tag)
	if e != nil {
		return fail(e)
	}
	if e = i.replace(ctx, old, next, current, tag, true); e != nil {
		return fail(e)
	}
	fmt.Fprintf(out, "Updated to %s. Rollback: awarely-scan update --rollback\n", tag)
	return 0
}

// Install is the second stage of the official installer, which verifies this
// executable's archive before invoking it. It does not fetch or run a script.
func Install(ctx context.Context, current string, in io.Reader, out, errOut io.Writer) int {
	fail := func(e error) int { fmt.Fprintln(errOut, "Installation stopped:", e); return 7 }
	if runtime.GOOS != "linux" || os.Geteuid() == 0 || !validVersion(current) {
		return fail(errors.New("install an official Linux release as a regular user"))
	}
	home, e := os.UserHomeDir()
	if e != nil || !filepath.IsAbs(home) {
		return fail(errors.New("valid home directory required"))
	}
	dest := filepath.Join(home, ".local/bin/awarely-scan")
	i, e := openInstallation(dest)
	if e != nil {
		return fail(e)
	}
	defer i.close()
	old, e := i.read(i.name, maxBinary)
	if e != nil {
		return fail(e)
	}
	temp, e := os.MkdirTemp(i.state, "install-")
	if e != nil {
		return fail(e)
	}
	defer os.RemoveAll(temp)
	previous, e := binaryVersion(ctx, dest, temp)
	if e != nil {
		return fail(e)
	}
	if compare(current, previous) <= 0 {
		return fail(errors.New("installer upgrade requires a newer version; use update --rollback for a saved backup"))
	}
	fmt.Fprintf(out, "Verified installer upgrade: %s -> %s\nThe existing binary is preserved for rollback.\n", previous, current)
	if !approved(in, out, false) {
		fmt.Fprintln(out, "Installation cancelled. Existing binary unchanged.")
		return 0
	}
	exe, e := executablePath()
	if e != nil {
		return fail(e)
	}
	// The verified installer has extracted its candidate into a private directory.
	f, e := os.Open(exe)
	if e != nil {
		return fail(e)
	}
	defer f.Close()
	next, e := io.ReadAll(io.LimitReader(f, maxBinary+1))
	if e != nil || len(next) > maxBinary {
		return fail(errors.New("installer binary exceeds size limit"))
	}
	if e = i.replace(ctx, old, next, previous, current, true); e != nil {
		return fail(e)
	}
	fmt.Fprintf(out, "READY: %s\nInstalled %s. Rollback: awarely-scan update --rollback\n", dest, current)
	return 0
}
