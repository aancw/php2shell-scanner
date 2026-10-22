// Package phpver parses PHP versions and decides whether a build is affected by
// the PHP2Shell core RCEs (CVE-2026-109618 / CVE-2026-109619, published 2026-10-21).
package phpver

import (
	"fmt"
	"regexp"
	"strconv"
)

// Version is a major.minor.patch PHP release.
type Version struct {
	Major int
	Minor int
	Patch int
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Less reports whether v is older than o.
func (v Version) Less(o Version) bool {
	switch {
	case v.Major != o.Major:
		return v.Major < o.Major
	case v.Minor != o.Minor:
		return v.Minor < o.Minor
	default:
		return v.Patch < o.Patch
	}
}

var verRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// Parse extracts a version from a string such as "PHP 8.3.35 (cli)".
func Parse(s string) (Version, bool) {
	m := verRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	ma, _ := strconv.Atoi(m[1])
	mi, _ := strconv.Atoi(m[2])
	pa, _ := strconv.Atoi(m[3])
	return Version{Major: ma, Minor: mi, Patch: pa}, true
}

// fixedIn maps a branch to the first release that carries the fixes.
// 8.2.35, 8.3.36, 8.4.27, 8.5.12 per the PHP advisories of 2026-10-21.
var fixedIn = map[int]map[int]int{
	8: {2: 35, 3: 36, 4: 27, 5: 12},
}

// State describes the exposure of a PHP build.
type State string

const (
	StateVulnerable State = "vulnerable" // below the fix for its branch
	StatePatched    State = "patched"    // at or above the fix for its branch
	StateEOL        State = "eol"        // branch out of support, needs a vendor patch / backport
	StateUnknown    State = "unknown"    // branch not covered by the advisories
)

// Status is the verdict for one PHP build.
type Status struct {
	State   State
	Version Version
	FixedIn string // first patched release of the branch, when known
	Reason  string
}

// Assess decides whether a version is affected.
func Assess(v Version) Status {
	if v.Major < 8 || (v.Major == 8 && v.Minor <= 1) {
		return Status{
			State:   StateEOL,
			Version: v,
			Reason:  fmt.Sprintf("PHP %s is an end-of-life branch; it gets no routine upstream updates, so it needs a vendor package or the 7.4/8.0/8.1 source backports. Confirm the range against php.net", v),
		}
	}
	branches, ok := fixedIn[v.Major]
	if !ok {
		return Status{
			State:   StateUnknown,
			Version: v,
			Reason:  fmt.Sprintf("PHP %s is outside the branches covered by the 2026-10-21 advisories; verify against php.net", v),
		}
	}
	fix, ok := branches[v.Minor]
	if !ok {
		return Status{
			State:   StateUnknown,
			Version: v,
			Reason:  fmt.Sprintf("PHP %s branch is newer than the known fixed releases; verify against php.net", v),
		}
	}
	fixed := Version{v.Major, v.Minor, fix}
	if v.Less(fixed) {
		return Status{
			State:   StateVulnerable,
			Version: v,
			FixedIn: fixed.String(),
			Reason:  fmt.Sprintf("PHP %s releases before %s are affected by CVE-2026-109618 and CVE-2026-109619", v, fixed),
		}
	}
	return Status{
		State:   StatePatched,
		Version: v,
		FixedIn: fixed.String(),
		Reason:  fmt.Sprintf("PHP %s is at or above the %s fix for the branch", v, fixed),
	}
}

// AssessString parses a version string and assesses it.
func AssessString(s string) (Status, bool) {
	v, ok := Parse(s)
	if !ok {
		return Status{}, false
	}
	return Assess(v), true
}
