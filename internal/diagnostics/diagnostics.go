// Package diagnostics exposes only fixed, bounded operational messages. It never
// accepts credentials, URLs, package names, child output or remote message text.
package diagnostics

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sync"
	"time"
)

//go:embed catalog.json
var catalogJSON []byte

type entry struct {
	Message  string `json:"message"`
	Detailed bool   `json:"detailed"`
}

var catalog struct {
	Events map[string]entry  `json:"events"`
	Errors map[string]string `json:"errors"`
}

func init() {
	if err := json.Unmarshal(catalogJSON, &catalog); err != nil {
		panic("invalid built-in diagnostics")
	}
}

type Options struct {
	Verbose bool
	Format  string
}

func (o *Options) Flags(fs *flag.FlagSet) {
	fs.BoolVar(&o.Verbose, "verbose", false, "additional safe operational details")
	fs.StringVar(&o.Format, "log-format", "text", "text or events (fixed diagnostic codes on stderr)")
}
func (o Options) Valid() bool { return o.Format == "text" || o.Format == "events" }

type key struct{}
type reporter struct {
	sync.Mutex
	out     io.Writer
	options Options
}

func With(ctx context.Context, out io.Writer, options Options) context.Context {
	return context.WithValue(ctx, key{}, &reporter{out: out, options: options})
}
func emit(ctx context.Context, kind, code, message string, detailed bool) {
	r, _ := ctx.Value(key{}).(*reporter)
	if r == nil || (detailed && !r.options.Verbose) {
		return
	}
	r.Lock()
	defer r.Unlock()
	if r.options.Format == "events" {
		fmt.Fprintf(r.out, "AWARELY_%s_V1 %s\n", kind, code)
	} else {
		fmt.Fprintf(r.out, "[Awarely] %s: %s\n", code, message)
	}
}
func Event(ctx context.Context, code string) {
	if e, ok := catalog.Events[code]; ok {
		emit(ctx, "EVENT", code, e.Message, e.Detailed)
	}
}
func KnownError(code string) bool { _, ok := catalog.Errors[code]; return ok }
func Failure(ctx context.Context, code string) {
	if !KnownError(code) {
		code = "REMOTE_FAILED"
	}
	emit(ctx, "ERROR", code, catalog.Errors[code], false)
}

// Step keeps long operations visible without extra network requests. Stop always
// joins the heartbeat before the caller resumes writing prompts or summaries.
func Step(ctx context.Context, code string) func() {
	Event(ctx, code)
	if ctx.Value(key{}) == nil {
		return func() {}
	}
	return heartbeat(ctx, 15*time.Second)
}
func heartbeat(ctx context.Context, interval time.Duration) func() {
	done, ended := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(ended)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				Event(ctx, "STILL_WORKING")
			}
		}
	}()
	return func() { once.Do(func() { close(done); <-ended }) }
}

// Duration and summary deliberately contain only local numbers and fixed labels.
// Machine consumers get fixed event codes; they read counts from validated files.
func Duration(ctx context.Context, started time.Time) {
	r, _ := ctx.Value(key{}).(*reporter)
	if r == nil || r.options.Format == "events" {
		return
	}
	r.Lock()
	defer r.Unlock()
	fmt.Fprintf(r.out, "[Awarely] Elapsed: %.1fs\n", time.Since(started).Seconds())
}
func Summary(ctx context.Context, report []byte) {
	r, _ := ctx.Value(key{}).(*reporter)
	if r == nil || r.options.Format == "events" {
		return
	}
	var v struct {
		Summary struct {
			CVEs    int `json:"matchedCves"`
			Matches int `json:"componentMatches"`
		} `json:"summary"`
		Coverage struct {
			Inventory   string            `json:"inventoryCoverage"`
			Unevaluated []json.RawMessage `json:"unevaluated"`
		} `json:"coverage"`
	}
	if json.Unmarshal(report, &v) != nil {
		return
	}
	coverage := "partial"
	if v.Coverage.Inventory == "complete" {
		coverage = "complete for selected inputs"
	}
	r.Lock()
	defer r.Unlock()
	fmt.Fprintf(r.out, "[Awarely] Matched CVEs: %d | Component matches: %d | Unevaluated: %d | Inventory: %s\n", v.Summary.CVEs, v.Summary.Matches, len(v.Coverage.Unevaluated), coverage)
	fmt.Fprintln(r.out, "[Awarely] No matches is not an all-clear. Review coverage and the complete report.")
}

func Runtime(ctx context.Context, version, syft, platform string) {
	r, _ := ctx.Value(key{}).(*reporter)
	if r == nil || r.options.Format == "events" {
		return
	}
	r.Lock()
	defer r.Unlock()
	fmt.Fprintf(r.out, "[Awarely] CLI %q | %s | managed Syft %q (release-pinned)\n", version, platform, syft)
}
