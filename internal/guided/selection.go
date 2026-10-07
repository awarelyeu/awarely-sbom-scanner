package guided

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/producer"
)

var declined = errors.New("declined")

func readableDirectory(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return errors.New("directory does not exist; check its spelling and enter another path")
	}
	if err != nil {
		return errors.New("cannot access this directory; check permissions or choose another path")
	}
	if !info.IsDir() {
		return errors.New("this is a file; enter the directory containing your application")
	}
	// Recheck the type atomically on open: a replaced path must not block on a FIFO.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		return errors.New("directory cannot be read; check permissions or choose another path")
	}
	defer f.Close()
	if _, err = f.Readdirnames(1); err != nil && err != io.EOF {
		return errors.New("directory cannot be listed; check permissions")
	}
	return nil
}

func (s *session) resultsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("home directory unavailable")
	}
	fmt.Fprintln(s.out, "Choose where to save results. Enter uses your home directory. A new private folder is created; existing files are never overwritten.")
	for {
		raw, err := s.ask("Parent directory for results", home)
		if err != nil {
			return "", err
		}
		base, err := selectedPath(raw)
		if err == nil {
			err = readableDirectory(base)
		}
		if err != nil {
			s.issue(err)
			continue
		}
		dir, err := os.MkdirTemp(base, "awarely-results-")
		if err != nil {
			s.issue(errors.New("cannot create results folder here; select a writable existing directory"))
			continue
		}
		return dir, nil
	}
}

// Navigation changes configuration only. Collectors run after validated choices;
// going back cannot trigger an upload or grant download consent.
func (s *session) collect() (inventory.Result, string, string, bool, string, error) {
	var result inventory.Result
	kind, target, resume := "", "", ""
	syft, all := false, false
	stage := "mode"
	for {
		switch stage {
		case "mode":
			s.heading("Step 1 of 3 - Choose what to scan")
			fmt.Fprintln(s.out, "1. Linux host - focused installed packages\n2. npm / Node.js application\n3. Python application\n4. Java application (Syft)\n5. Other application ecosystems (Syft)\n6. Use an existing Awarely SBOM - check or sync without rescanning")
			mode, err := s.choice("Scan type", "", "1", "2", "3", "4", "5", "6")
			if errors.Is(err, back) {
				continue
			}
			if err != nil {
				return result, kind, target, syft, resume, err
			}
			if mode == "6" {
				stage = "resume"
				continue
			}
			kind = map[string]string{"1": "linux", "2": "npm", "3": "python", "4": "java", "5": "other"}[mode]
			target, syft, all = "", kind == "java" || kind == "other", false
			if kind == "linux" {
				stage = "scope"
			} else {
				stage = "path"
			}
		case "resume":
			raw, err := s.ask("Existing Awarely inventory.cdx.json file", "")
			if errors.Is(err, back) {
				stage = "mode"
				continue
			}
			if err != nil {
				return result, kind, target, syft, resume, err
			}
			path, err := selectedPath(raw)
			if err == nil {
				_, err = api.ReadSnapshot(s.ctx, path)
			}
			if err != nil {
				s.issue(err)
				continue
			}
			return result, kind, target, syft, path, nil
		case "scope":
			fmt.Fprintln(s.out, "The distribution is detected automatically. No package manager or root access is needed.\n1. Focused server packages and installed dependencies (recommended)\n2. All installed packages (larger inventory; account limits still apply)\nFocused means common server software such as web servers, SSH, TLS libraries and their installed dependencies. It is not a complete host inventory.")
			profile, err := s.choice("Linux scope", "1", "1", "2")
			if errors.Is(err, back) {
				stage = "mode"
				continue
			}
			if err != nil {
				return result, kind, target, syft, resume, err
			}
			all, stage = profile == "2", "scan"
		case "path":
			fmt.Fprintln(s.out, "Enter your application's directory, for example /srv/my-app or ~/my-app. The example must be replaced with a directory that exists on this machine.")
			raw, err := s.ask("Application directory", target)
			if errors.Is(err, back) {
				stage = "mode"
				continue
			}
			if err != nil {
				return result, kind, target, syft, resume, err
			}
			path, err := selectedPath(raw)
			if err == nil {
				err = readableDirectory(path)
			}
			if err != nil {
				s.issue(err)
				continue
			}
			target = path
			if kind == "npm" || kind == "python" {
				stage = "collection"
			} else {
				stage = "scan"
			}
		case "collection":
			label := "npm collection"
			if kind == "npm" {
				fmt.Fprintln(s.out, "1. Read npm lockfile (recommended; no Node.js/npm installation needed)\n2. Inspect application files with Syft (optional download)")
			} else {
				label = "Python collection"
				fmt.Fprintln(s.out, "1. Read requirements.txt (no Python installation needed; partial inventory)\n2. Inspect an existing virtual environment with Syft (includes installed dependencies)")
			}
			value, err := s.choice(label, "1", "1", "2")
			if errors.Is(err, back) {
				stage = "path"
				continue
			}
			if err != nil {
				return result, kind, target, syft, resume, err
			}
			syft, stage = value == "2", "scan"
		case "scan":
			if kind != "linux" {
				if err := preflight(s.ctx, target, kind, syft); err != nil {
					s.issue(err)
					stage = "path"
					continue
				}
			}
			var err error
			if syft {
				if !producer.Supported() {
					return result, kind, target, syft, resume, errors.New("managed Syft supports Linux amd64/arm64; use import for an externally generated SBOM")
				}
				if kind == "other" {
					fmt.Fprintln(s.out, "NuGet, Go, Composer, RubyGems and Cargo can be inventoried/synced. Their CVE assessment is currently unevaluated.")
				}
				cache, e := producer.CachePath()
				if e != nil {
					return result, kind, target, syft, resume, e
				}
				ready, e := producer.Cached(s.ctx, cache)
				// Integrity errors are fatal: never turn a tampered cache into an implicit download.
				if e != nil {
					return result, kind, target, syft, resume, e
				}
				fmt.Fprintf(s.out, "Syft %s will inspect only the selected application directory.\nIt will not build the project or install its dependencies.\n", producer.Version)
				if !ready {
					fmt.Fprintln(s.out, "Syft is missing from the verified cache. Awarely can download about 30 MB from GitHub, verify the pinned SHA-256 and run it without root. No GitHub account, gh or Cosign is needed.")
				}
				fmt.Fprintln(s.out, "Third-party parsing uses a fixed offline configuration and an environment without your credentials. This is not an OS sandbox; scan only authorized inputs.")
				approved, e := s.confirm("Prepare and run verified Syft")
				if errors.Is(e, back) {
					if kind == "npm" || kind == "python" {
						stage = "collection"
					} else {
						stage = "path"
					}
					continue
				}
				if e != nil {
					return result, kind, target, syft, resume, e
				}
				if !approved {
					fmt.Fprintln(s.out, "Cancelled. No tool was downloaded and no scan was run.")
					return result, kind, target, syft, resume, declined
				}
				if e := producer.Prepare(s.ctx, cache, !ready); e != nil {
					return result, kind, target, syft, resume, e
				}
				fmt.Fprintln(s.out, "Scanning with verified Syft...")
				result, err = producer.Scan(s.ctx, cache, target, kind)
			} else {
				fmt.Fprintln(s.out, "Scanning selected inputs locally...")
				ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
				if kind == "linux" {
					result, err = inventory.Host(ctx, "/", inventory.DefaultSelection, all)
				} else {
					result, err = inventory.AppFor(ctx, target, kind)
				}
				cancel()
			}
			if err == nil {
				return result, kind, target, syft, resume, nil
			}
			if s.ctx.Err() != nil {
				return result, kind, target, syft, resume, cancelled
			}
			s.issue(err)
			fmt.Fprintln(s.out, "No inventory was exported. Choose a different input or correct the files before retrying.")
			retry, e := s.choice("1. Choose inputs again / 2. Quit", "2", "1", "2")
			if errors.Is(e, back) || (e == nil && retry == "1") {
				if kind == "linux" {
					stage = "scope"
				} else {
					stage = "path"
				}
				continue
			}
			if e != nil {
				return result, kind, target, syft, resume, e
			}
			return result, kind, target, syft, resume, err
		}
	}
}
