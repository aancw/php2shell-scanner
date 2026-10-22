// Package report holds the shared finding model and its renderers.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

var rank = map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}

// Rank returns a sortable weight for a severity (lower = worse).
func Rank(s Severity) int {
	if r, ok := rank[s]; ok {
		return r
	}
	return len(rank)
}

// ParseSeverity maps a user supplied string to a severity.
func ParseSeverity(s string) (Severity, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, v := range []Severity{Critical, High, Medium, Low, Info} {
		if string(v) == s {
			return v, true
		}
	}
	return "", false
}

type Finding struct {
	ID         string   `json:"id"`
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Evidence   string   `json:"evidence,omitempty"`
	Mitigation string   `json:"mitigation,omitempty"`
	CVE        []string `json:"cve,omitempty"`
}

type Report struct {
	Target   string            `json:"target"`
	Mode     string            `json:"mode"`
	Time     time.Time         `json:"time"`
	Summary  map[string]int    `json:"summary"`
	Findings []Finding         `json:"findings"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// Add appends a finding.
func (r *Report) Add(f Finding) { r.Findings = append(r.Findings, f) }

// Sort orders findings worst-first, stable inside a severity.
func (r *Report) Sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return Rank(r.Findings[i].Severity) < Rank(r.Findings[j].Severity)
	})
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() map[string]int {
	c := map[string]int{}
	for _, f := range r.Findings {
		c[string(f.Severity)]++
	}
	return c
}

// Worst returns the highest severity present, or "" when there is none.
func (r *Report) Worst() Severity {
	var worst Severity
	for _, f := range r.Findings {
		if worst == "" || Rank(f.Severity) < Rank(worst) {
			worst = f.Severity
		}
	}
	return worst
}

// WriteJSON renders the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Bundle is the result of a scan that covered several targets.
type Bundle struct {
	Time    time.Time      `json:"time"`
	Summary map[string]int `json:"summary"`
	Reports []Report       `json:"reports"`
}

// NewBundle wraps the per target reports and counts them.
func NewBundle(reports []Report) *Bundle {
	b := &Bundle{Time: time.Now(), Reports: reports}
	b.Summary = map[string]int{}
	for _, r := range reports {
		for sev, n := range r.Counts() {
			b.Summary[sev] += n
		}
	}
	return b
}

// Worst returns the highest severity across all targets.
func (b *Bundle) Worst() Severity {
	worst := Severity("")
	for _, r := range b.Reports {
		if w := r.Worst(); w != "" && (worst == "" || Rank(w) < Rank(worst)) {
			worst = w
		}
	}
	return worst
}

// WriteJSON renders the bundle as indented JSON.
func (b *Bundle) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// WriteText renders every target report and a combined summary.
func (b *Bundle) WriteText(w io.Writer) {
	for i := range b.Reports {
		if i > 0 {
			fmt.Fprintln(w)
		}
		b.Reports[i].WriteText(w)
	}
	fmt.Fprintf(w, "Targets: %d | critical %d, high %d, medium %d, low %d, info %d\n",
		len(b.Reports),
		b.Summary[string(Critical)], b.Summary[string(High)], b.Summary[string(Medium)],
		b.Summary[string(Low)], b.Summary[string(Info)])
}

// WriteText renders the report for humans.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "Target: %s\nMode:   %s\nTime:   %s\n\n", r.Target, r.Mode, r.Time.Format(time.RFC3339))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "%-8s %s\n", strings.ToUpper(string(f.Severity)), f.Title)
		fmt.Fprintf(w, "         id: %s\n", f.ID)
		if f.Detail != "" {
			fmt.Fprintf(w, "         %s\n", f.Detail)
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "         evidence: %s\n", f.Evidence)
		}
		if f.Mitigation != "" {
			fmt.Fprintf(w, "         fix: %s\n", f.Mitigation)
		}
		if len(f.CVE) > 0 {
			fmt.Fprintf(w, "         cve: %s\n", strings.Join(f.CVE, ", "))
		}
		fmt.Fprintln(w)
	}
	c := r.Counts()
	fmt.Fprintf(w, "Summary: %d critical, %d high, %d medium, %d low, %d info\n",
		c[string(Critical)], c[string(High)], c[string(Medium)], c[string(Low)], c[string(Info)])
}
