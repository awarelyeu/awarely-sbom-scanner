// Package guided orchestrates explicit user choices. It never discovers API
// credentials, silently installs tools or sends a local inventory by default.
package guided

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

type session struct {
	ctx         context.Context
	reader      *bufio.Scanner
	out, errOut io.Writer
	version     string
	color       bool
	remote      func(context.Context, api.Credentials, api.Snapshot, string) ([]byte, error)
}

func Run(ctx context.Context, input io.Reader, out, errOut io.Writer, version string) int {
	return RunWithColor(ctx, input, out, errOut, version, false)
}

// The caller enables color only for a real terminal. Redirected output stays plain.
func RunWithColor(ctx context.Context, input io.Reader, out, errOut io.Writer, version string, color bool) int {
	s := &session{ctx: ctx, reader: bufio.NewScanner(input), out: out, errOut: errOut, version: version, color: color}
	s.reader.Buffer(make([]byte, 4096), 4096)
	s.remote = func(ctx context.Context, credentials api.Credentials, snapshot api.Snapshot, action string) ([]byte, error) {
		client := api.NewClient(credentials)
		if action == "check" {
			return client.Check(ctx, snapshot)
		}
		return client.Sync(ctx, snapshot, "", "", false)
	}
	return s.run()
}

var cancelled = errors.New("cancelled; any completed local export was preserved")
var back = errors.New("back")

func (s *session) heading(text string) {
	if s.color {
		fmt.Fprintf(s.out, "\n\x1b[1;36m%s\x1b[0m\n", text)
	} else {
		fmt.Fprintln(s.out, "\n"+text)
	}
}
func (s *session) issue(err error) {
	// Neither producer errors nor user-controlled paths may emit terminal controls.
	text := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, err.Error())
	if s.color {
		fmt.Fprint(s.out, "\x1b[33m")
	}
	fmt.Fprint(s.out, "Please review: ")
	if s.color {
		fmt.Fprint(s.out, "\x1b[0m")
	}
	fmt.Fprintln(s.out, text)
}

func (s *session) ask(label, fallback string) (string, error) {
	for {
		if s.ctx.Err() != nil {
			return "", cancelled
		}
		fmt.Fprint(s.out, label)
		if fallback != "" {
			fmt.Fprintf(s.out, " [%s]", fallback)
		}
		fmt.Fprint(s.out, ": ")
		ready := make(chan bool, 1)
		go func() { ready <- s.reader.Scan() }()
		select {
		case ok := <-ready:
			if !ok {
				return "", cancelled
			}
		case <-s.ctx.Done():
			return "", cancelled
		}
		value := strings.TrimSpace(s.reader.Text())
		if value == "q" || value == "quit" || s.ctx.Err() != nil {
			return "", cancelled
		}
		if value == "b" || value == "back" {
			return "", back
		}
		if value == "" {
			value = fallback
		}
		if value != "" && !inventory.ValidText(value, 4095) {
			s.issue(errors.New("input contains unsupported characters; enter it again"))
			continue
		}
		return value, nil
	}
}
func (s *session) choice(label, fallback string, choices ...string) (string, error) {
	for {
		v, e := s.ask(label, fallback)
		if e != nil {
			return "", e
		}
		for _, option := range choices {
			if v == option {
				return v, nil
			}
		}
		fmt.Fprintln(s.out, "Choose one of:", strings.Join(choices, ", "), "(or q to quit).")
	}
}
func (s *session) confirm(label string) (bool, error) {
	v, e := s.choice(label+" (yes/no)", "no", "yes", "no")
	return v == "yes", e
}
func (s *session) fail(err error) int {
	fmt.Fprintln(s.errOut, "STOP:", err)
	if errors.Is(err, cancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || s.ctx.Err() != nil {
		return 5
	}
	return 2
}
func selectedPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
		raw = raw[1 : len(raw)-1]
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", errors.New("home directory is unavailable")
		}
		raw = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(raw, "~"), "/"))
	}
	if raw == "" {
		return "", errors.New("enter a file or directory path, not a shell command")
	}
	p, e := filepath.Abs(raw)
	if e != nil {
		return "", errors.New("invalid path")
	}
	return p, nil
}

func (s *session) run() int {
	s.heading("Awarely Scan - guided setup")
	fmt.Fprintln(s.out, "Nothing is uploaded by default. Enter accepts [defaults]. Type b to go back, q to quit.\nPaths may be relative, start with ~/ or be enclosed in quotes; shell commands are never executed.")
	for {
		result, kind, target, syft, resume, err := s.collect()
		if err != nil {
			if errors.Is(err, declined) {
				return 0
			}
			return s.fail(err)
		}
		if resume != "" {
			snapshot, e := api.ReadSnapshot(s.ctx, resume)
			if e != nil {
				s.issue(e)
				continue
			}
			fmt.Fprintf(s.out, "Using existing inventory: %q (%d components). No scan is repeated.\n", resume, len(snapshot.Components))
			dir, e := s.resultsDir()
			if errors.Is(e, back) {
				continue
			}
			if e != nil {
				return s.fail(e)
			}
			return s.afterExport(resume, dir, snapshot.Coverage != "complete")
		}
		s.heading("Step 2 of 3 - Save your local inventory")
		fmt.Fprintf(s.out, "Found %d unique components. No inventory was sent.\n", len(result.Components))
		for _, n := range result.Notices {
			fmt.Fprintln(s.out, "Notice:", n)
		}
		for _, w := range result.Warnings {
			fmt.Fprintln(s.out, "Coverage warning:", w)
		}
		if len(result.Warnings) > 0 {
			fmt.Fprintln(s.out, "This is a partial inventory. Local export and API check are available; synchronization is disabled.")
		}
		if !syft && kind == "python" {
			fmt.Fprintln(s.out, "requirements.txt lists declarations, not a complete installed environment. Choose Python > 2 next time to inspect an existing virtual environment with Syft.")
		}
		if !syft && kind == "npm" && len(result.Warnings) > 0 {
			fmt.Fprintln(s.out, "Prefer package-lock.json or npm-shrinkwrap.json v2/v3 from a trusted build. Awarely does not run npm install or project scripts. Ranges/workspaces may remain partial.")
		}
		fmt.Fprintln(s.out, "Coverage is limited to selected inputs. This is not yet a vulnerability check.")
		label := "application"
		if kind == "linux" {
			label = "linux-host"
		}
		if kind != "linux" && inventory.ValidText(filepath.Base(target), 120) {
			label = filepath.Base(target)
		}
		var name, dir string
		for {
			name, err = s.ask("Application label", label)
			if err != nil {
				break
			}
			if !inventory.ValidText(name, 120) {
				s.issue(errors.New("application label must be 1-120 bytes without control characters"))
				continue
			}
			fmt.Fprintln(s.out, "This label identifies the local SBOM. API synchronization uses the application/source configured in your credential.")
			dir, err = s.resultsDir()
			if errors.Is(err, back) {
				continue
			}
			break
		}
		if errors.Is(err, back) {
			continue
		}
		if err != nil {
			return s.fail(err)
		}
		blob, e := inventory.Marshal(result, name, s.version, time.Now())
		if e != nil {
			os.Remove(dir)
			return s.fail(e)
		}
		path := filepath.Join(dir, "inventory.cdx.json")
		if e = safeio.WriteNew(path, blob); e != nil {
			os.Remove(dir)
			return s.fail(e)
		}
		fmt.Fprintf(s.out, "Saved local SBOM: %q\n", path)
		return s.afterExport(path, dir, len(result.Warnings) > 0)
	}
}

func preflight(ctx context.Context, path, kind string, syft bool) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "/" {
		return errors.New("select a readable application directory, not the host root")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if kind == "npm" && !syft {
		for _, n := range []string{"npm-shrinkwrap.json", "package-lock.json", "package.json"} {
			if _, e := os.Lstat(filepath.Join(path, n)); e == nil {
				return nil
			}
		}
		return errors.New("no npm manifest found; select the project root containing package-lock.json (v2/v3), npm-shrinkwrap.json or package.json; Node.js/npm is not needed by the scanner")
	}
	if kind == "python" && !syft {
		if _, e := os.Lstat(filepath.Join(path, "requirements.txt")); e == nil {
			return nil
		}
		return errors.New("requirements.txt is missing; choose the project root or Python > 2 for an existing virtual environment")
	}
	count := 0
	found := false
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count++
		if count > 50000 {
			return errors.New("too many entries")
		}
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".awarely-scan-tools") {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Type().IsRegular() {
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if kind == "java" {
				found = ext == ".jar" || ext == ".war" || ext == ".ear"
			} else if kind == "python" {
				found = (d.Name() == "METADATA" && strings.HasSuffix(filepath.Base(filepath.Dir(p)), ".dist-info")) || d.Name() == "PKG-INFO"
			} else {
				found = true
			}
			if found {
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return errors.New("cannot inspect selected files; check permissions or choose a smaller directory")
	}
	if found {
		return nil
	}
	if kind == "java" {
		return errors.New("no JAR/WAR/EAR found; provide artifacts from your trusted Maven/Gradle build in this directory. Awarely does not install Java or build/run your project")
	}
	if kind == "python" {
		return errors.New("no installed Python metadata found; select a directory containing an existing virtual environment. Awarely does not install Python or packages; use Python > 1 for requirements.txt")
	}
	return errors.New("no application files found; choose a project or build output directory")
}
