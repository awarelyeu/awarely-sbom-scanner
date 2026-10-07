package guided

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
)

// All remote strings are quoted, so even malformed/untrusted text cannot inject
// terminal escapes, newlines, OSC links or bidirectional formatting into output.
// limit applies only to the terminal preview; the private text report is complete.
func summaryText(report []byte, limit int) string {
	var r struct {
		Components []api.Component `json:"components"`
		Summary    struct {
			CVEs       int `json:"matchedCves"`
			Components int `json:"componentMatches"`
		} `json:"summary"`
		Coverage struct {
			From        string `json:"from"`
			To          string `json:"to"`
			Inventory   string `json:"inventoryCoverage"`
			Unevaluated []struct {
				Index  int    `json:"componentIndex"`
				Reason string `json:"reason"`
			} `json:"unevaluated"`
		} `json:"coverage"`
		Matches []struct {
			ID         string `json:"cveId"`
			Severity   string `json:"severity"`
			Components []struct {
				Index     int    `json:"componentIndex"`
				Precision string `json:"precision"`
				Products  []struct {
					Version string `json:"version"`
				} `json:"products"`
				Distribution []struct {
					Source       string `json:"source"`
					Status       string `json:"status"`
					Fixed        string `json:"fixedVersion"`
					Availability string `json:"availability"`
					URL          string `json:"url"`
				} `json:"distributionEvidence"`
			} `json:"components"`
		} `json:"matches"`
	}
	if json.Unmarshal(report, &r) != nil {
		return "Read the complete JSON report for results.\n"
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Matched CVEs: %d | Component matches: %d | Unevaluated: %d\n", r.Summary.CVEs, r.Summary.Components, len(r.Coverage.Unevaluated))
	fmt.Fprintf(&out, "Inventory coverage: %q | Period: %q to %q\n", r.Coverage.Inventory, r.Coverage.From, r.Coverage.To)
	rows := 0
	for _, match := range r.Matches {
		for _, hit := range match.Components {
			if hit.Index < 0 || hit.Index >= len(r.Components) {
				continue
			}
			if limit > 0 && rows >= limit {
				break
			}
			c := r.Components[hit.Index]
			fmt.Fprintf(&out, "- %q %q | %q %q@%q | precision: %q\n", match.Severity, match.ID, c.Ecosystem, c.Name, c.Version, hit.Precision)
			if limit == 0 {
				for _, p := range hit.Products {
					if p.Version != "" {
						fmt.Fprintf(&out, "  Affected range (source): %q\n", p.Version)
					}
				}
				if len(hit.Distribution) > 0 {
					for _, evidence := range hit.Distribution {
						fmt.Fprintf(&out, "  Distribution: %q | status: %q | fixed version: %q\n", evidence.Source, evidence.Status, evidence.Fixed)
						if evidence.Availability != "" {
							fmt.Fprintf(&out, "  Fix availability: %q\n", evidence.Availability)
						}
						fmt.Fprintf(&out, "  Advisory: %q\n", evidence.URL)
					}
				}
			}
			rows++
		}
	}
	if limit > 0 && r.Summary.Components > rows {
		fmt.Fprintln(&out, "Preview only. The text summary and JSON report contain all matches.")
	}
	if len(r.Coverage.Unevaluated) > 0 {
		counts := map[string]int{}
		for _, item := range r.Coverage.Unevaluated {
			counts[item.Reason]++
		}
		reasons := make([]string, 0, len(counts))
		for reason := range counts {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			fmt.Fprintf(&out, "Not fully evaluated: %q (%d components)\n", reason, counts[reason])
		}
		if limit == 0 {
			for _, item := range r.Coverage.Unevaluated {
				if item.Index >= 0 && item.Index < len(r.Components) {
					c := r.Components[item.Index]
					fmt.Fprintf(&out, "  %q %q@%q: %q\n", c.Ecosystem, c.Name, c.Version, item.Reason)
				}
			}
		}
	}
	fmt.Fprintln(&out, "No matches does not mean the application is secure. Review unevaluated components, coverage and the full JSON evidence.")
	return out.String()
}
