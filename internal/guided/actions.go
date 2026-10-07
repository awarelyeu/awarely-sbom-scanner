package guided

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

func (s *session) afterExport(path, dir string, partial bool) int {
	localCode := 0
	if partial {
		localCode = 3
	}
	snapshot, err := api.ReadSnapshot(s.ctx, path)
	if err != nil {
		return s.fail(err)
	}
	snapshot.CollectorVersion = s.version
	// Coverage is read from the file as well: resume never upgrades partial input.
	partial = partial || snapshot.Coverage != "complete"
	if partial {
		localCode = 3
	}
	action, stage := "", "action"
	var credentials api.Credentials
	for {
		switch stage {
		case "action":
			s.heading("Step 3 of 3 - Choose what happens next")
			fmt.Fprintln(s.out, "1. Keep local file / upload it manually in Settings > Assets\n2. Check CVEs through the API (does not save inventory or send alerts)")
			choices := []string{"1", "2"}
			if !partial && len(snapshot.Components) > 0 {
				fmt.Fprintln(s.out, "3. Synchronize inventory through the API (replaces one configured source)")
				choices = append(choices, "3")
			}
			if len(snapshot.Components) == 0 {
				fmt.Fprintln(s.out, "Empty inventory: guided synchronization is disabled to prevent accidental deletion.")
			}
			answer, e := s.choice("Next action", "1", choices...)
			if errors.Is(e, back) {
				fmt.Fprintf(s.out, "Your local file is already saved: %q. Choose an action or q to finish.\n", path)
				continue
			}
			if e != nil {
				return s.fail(e)
			}
			if answer == "1" {
				fmt.Fprintf(s.out, "Done. Your local SBOM is %q\nFor manual upload: Settings > Assets > Import, review the changes, then Save.\nRun guided again and choose 6 to check or sync this file later.\n", path)
				return localCode
			}
			action = "check"
			if answer == "3" {
				action = "sync"
			}
			fmt.Fprintln(s.out, "In Awarely Monitor: Settings > Assets > Awarely Scan CLI.\nWith Pro access and MFA, create a credential for the intended application/source.\nUse Check only for checks, or Sync only / Check and sync for synchronization.\nDownload the credential JSON, transfer it securely to this machine outside the project, and run: chmod 600 /path/to/awarely-credentials.json\nEnter its file path below. Never paste the token into this prompt. Type b to change the action.")
			stage = "credentials"
		case "credentials":
			raw, e := s.ask("Credential JSON file", "")
			if errors.Is(e, back) {
				stage = "action"
				continue
			}
			if e != nil {
				return s.fail(e)
			}
			credentialPath, e := selectedPath(raw)
			if e == nil {
				credentials, e = api.ReadCredentials(s.ctx, credentialPath, strings.NewReader(""))
			}
			if e != nil {
				s.issue(e)
				fmt.Fprintln(s.out, "Enter another credential file path, or b to keep the inventory locally. Permissions are not changed automatically.")
				continue
			}
			stage = "confirm"
		case "confirm":
			fmt.Fprintf(s.out, "Destination: %q\nApplication ID: %s\nSource ID: %s\nComponents: %d\n", credentials.APIURL, credentials.ApplicationID, credentials.SourceID, len(snapshot.Components))
			fmt.Fprintln(s.out, "Only normalized package identities, versions and evidence are sent; credentials authenticate the request.")
			if action == "sync" {
				fmt.Fprintln(s.out, "SYNC replaces this source immediately. Other sources are preserved. Future alerts follow saved preferences; this does not send retrospective emails.")
			} else {
				fmt.Fprintln(s.out, "CHECK returns a local report. Saved inventory and alert settings remain unchanged.")
			}
			approved, e := s.confirm("Send inventory for " + action)
			if errors.Is(e, back) {
				stage = "credentials"
				continue
			}
			if e != nil {
				return s.fail(e)
			}
			if !approved {
				fmt.Fprintln(s.out, "No API request was sent. Your local SBOM is ready.")
				return localCode
			}
			fmt.Fprintln(s.out, "Waiting for the API result...")
			ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
			report, e := s.remote(ctx, credentials, snapshot, action)
			cancel()
			if e != nil {
				s.issue(e)
				fmt.Fprintf(s.out, "Your local inventory is preserved: %q\n", path)
				if s.ctx.Err() != nil {
					return s.fail(cancelled)
				}
				if action == "sync" {
					fmt.Fprintln(s.errOut, "Synchronization was not confirmed. A request may already have committed. Check this source in Settings > Assets before starting a new sync. No automatic retry was made. Use guided option 6 to reopen the saved inventory.")
					return 6
				}
				fmt.Fprintln(s.out, "Check failed; saved inventory is unchanged. Check the credential's expiry/scope and your connection. If the API reports a catalog problem, try later.")
				answer, err := s.choice("1. Retry check / 2. Choose another credential / 3. Finish with local file", "3", "1", "2", "3")
				if errors.Is(err, back) {
					stage = "action"
					continue
				}
				if err != nil {
					return s.fail(err)
				}
				if answer == "3" {
					return 6
				}
				if answer == "2" {
					stage = "credentials"
				}
				continue // A retry still requires explicit transmission confirmation.
			}
			reportPath := filepath.Join(dir, action+"-result.json")
			// Saving can be retried independently without ever repeating a remote mutation.
			for {
				e = safeio.WriteNew(reportPath, append(report, '\n'))
				if e == nil {
					break
				}
				fmt.Fprintln(s.out, "The API completed, but its report could not be saved. A sync is already committed. Choose another results directory; the API request will not be repeated.")
				next, err := s.resultsDir()
				if errors.Is(err, back) {
					continue
				}
				if err != nil {
					fmt.Fprintln(s.errOut, "Report was not saved. A sync may already be committed; inspect Settings > Assets.")
					return 4
				}
				dir, reportPath = next, filepath.Join(next, action+"-result.json")
			}
			s.heading("Completed - review your results")
			fmt.Fprintf(s.out, "Saved complete %s report: %q\n", action, reportPath)
			if action == "check" {
				text := summaryText(report, 0)
				summaryPath := filepath.Join(dir, "check-summary.txt")
				if e := safeio.WriteNew(summaryPath, []byte(text)); e == nil {
					fmt.Fprintf(s.out, "Readable summary: %q\n", summaryPath)
				} else {
					fmt.Fprintln(s.out, "The optional text summary could not be saved. The complete JSON report above is available.")
				}
				fmt.Fprint(s.out, summaryText(report, 10))
			} else {
				fmt.Fprintln(s.out, "Source synchronized. View the saved inventory in Settings > Assets.")
			}
			return localCode
		}
	}
}
