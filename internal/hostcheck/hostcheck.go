// Package hostcheck runs the host-side checks of the PHP2Shell scanner against a
// machine that is reachable through a Prober (local shell or SSH).
//
// The checks follow the PHP advisories of 2026-10-21 for CVE-2026-109618
// (memory corruption during OOM handling) and CVE-2026-109619 (use after free
// of stale per-request state), plus the session.upload_progress primitives
// documented by the php2shell-lab project.
package hostcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aancw/php2shell-scanner/internal/phpver"
	"github.com/aancw/php2shell-scanner/internal/report"
)

// Prober runs a shell script on a host and returns its combined output.
type Prober interface {
	Run(ctx context.Context, script string) (string, error)
	Target() string
}

// Options tune the host scan.
type Options struct {
	Webroot string        // optional document root to scan for exploit artifacts
	Timeout time.Duration // per-command timeout
}

// phpInfo is the JSON the PHP probe script prints for every interpreter.
type phpInfo struct {
	Binary           string `json:"binary"`
	Version          string `json:"version"`
	SAPI             string `json:"sapi"`
	HasIni           bool   `json:"has_ini"`
	UploadProgress   string `json:"upload_progress"`
	UPName           string `json:"up_name"`
	UPCleanup        string `json:"up_cleanup"`
	SerializeHandler string `json:"serialize_handler"`
	SavePath         string `json:"save_path"`
	MemoryLimit      string `json:"memory_limit"`
	PostMax          string `json:"post_max"`
	UploadMax        string `json:"upload_max"`
	FatalBacktraces  string `json:"fatal_backtraces"`
	UseCookies       string `json:"use_cookies"`
	UseOnlyCookies   string `json:"use_only_cookies"`
	UseStrict        string `json:"use_strict"`
	IniFile          string `json:"ini_file"`
	ScanFiles        string `json:"scan_files"`
}

const scriptPHP = `
for b in php php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 php7.3 php7.2 php7.1 php7.0 php5.6; do
  p=$(command -v "$b" 2>/dev/null) || continue
  echo "BIN $p"
  "$b" -r 'echo "PHPINFO ".json_encode(array("binary"=>PHP_BINARY,"version"=>PHP_VERSION,"sapi"=>PHP_SAPI,"has_ini"=>true,"upload_progress"=>(string)ini_get("session.upload_progress.enabled"),"up_name"=>(string)ini_get("session.upload_progress.name"),"up_cleanup"=>(string)ini_get("session.upload_progress.cleanup"),"serialize_handler"=>(string)ini_get("session.serialize_handler"),"save_path"=>(string)ini_get("session.save_path"),"memory_limit"=>(string)ini_get("memory_limit"),"post_max"=>(string)ini_get("post_max_size"),"upload_max"=>(string)ini_get("upload_max_filesize"),"fatal_backtraces"=>(string)ini_get("fatal_error_backtraces"),"use_cookies"=>(string)ini_get("session.use_cookies"),"use_only_cookies"=>(string)ini_get("session.use_only_cookies"),"use_strict"=>(string)ini_get("session.use_strict_mode"),"ini_file"=>(string)php_ini_loaded_file(),"scan_files"=>(string)php_ini_scanned_files()))."\n";' 2>/dev/null
done
for f in php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0; do
  p=$(command -v "$f" 2>/dev/null) || continue
  echo "FPMBIN $p"
  "$f" -v 2>&1 | head -1 | sed 's/^/FPMVER /'
done
for m in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/local/apache2/modules/libphp*.so /usr/local/httpd/modules/libphp*.so; do
  [ -e "$m" ] && echo "MODPHP $m"
done
for c in apache2ctl httpd apachectl; do
  command -v "$c" >/dev/null 2>&1 || continue
  "$c" -M 2>/dev/null | grep -i php | sed 's/^/MODPHP /'
done
`

const scriptConfig = `
for d in /etc/php /usr/local/etc/php /etc/php-fpm.d /usr/local/etc/php-fpm.d /etc/php5 /etc/php7 /usr/local/php /opt/php /etc/apache2 /etc/httpd /usr/local/apache2/conf /etc/nginx /etc/php.ini; do
  [ -e "$d" ] || continue
  if [ -d "$d" ]; then
    find "$d" -maxdepth 5 -type f \( -name 'php.ini' -o -name '*.ini' -o -name '*.conf' -o -name '.htaccess' \) 2>/dev/null
  else
    echo "$d"
  fi
done | sort -u | while read -r f; do
  grep -Hn -E '(session\.upload_progress\.(enabled|name|cleanup)|session\.serialize_handler|session\.save_path|memory_limit|fatal_error_backtraces|post_max_size|upload_max_filesize)[[:space:]]*=|php_(admin_)?value' "$f" 2>/dev/null
done
`

const scriptProcs = `
ps -eo pid=,ppid=,args= 2>/dev/null | head -300
`

// scriptSessions scans the given session directories for files poisoned through
// the session.upload_progress content injection primitive.
func scriptSessions(dirs []string) string {
	var b strings.Builder
	b.WriteString("for d in")
	for _, d := range dirs {
		fmt.Fprintf(&b, " %q", d)
	}
	b.WriteString(`; do
  [ -d "$d" ] || continue
  echo "SESSDIR $d"
  for f in "$d"/sess_*; do
    [ -f "$f" ] || continue
    grep -q -F 'upload_progress_' "$f" 2>/dev/null || continue
    echo "MARKER $f"
    if grep -q -F '<?php' "$f" 2>/dev/null || grep -q -F '<?=' "$f" 2>/dev/null; then
      echo "POISON $f"
    fi
    seg=$(grep -o -m1 'upload_progress_[^|]*|[^|]*' "$f" 2>/dev/null)
    [ -n "$seg" ] && echo "SNIPPET $f $seg"
  done
done
`)
	return b.String()
}

// scriptRoots prints the document roots the web server configuration points at.
const scriptRoots = `
for d in /etc/apache2 /etc/httpd /usr/local/apache2/conf /etc/nginx /usr/local/etc/nginx /usr/local/etc/httpd; do
  [ -d "$d" ] || continue
  grep -rh -E '^[[:space:]]*(DocumentRoot|root)[[:space:]]+' "$d" 2>/dev/null
done | sed -E 's/^[[:space:]]*(DocumentRoot|root)[[:space:]]+//; s/;[[:space:]]*$//' | tr -d '"' | sort -u
`

// defaultRoots are used when the web server configuration names none.
var defaultRoots = []string{"/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/www", "/var/www/public"}

// parseRoots keeps the usable paths from the scriptRoots output.
func parseRoots(out string) []string {
	var roots []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.ContainsAny(line, "${}") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			continue
		}
		roots = append(roots, line)
	}
	return dedupe(roots)
}

// scriptWebroot looks for exploit artifacts and PHP configuration inside a
// document root.
func scriptWebroot(root string) string {
	return fmt.Sprintf(`if [ -d %q ]; then
  grep -rl -F 'upload_progress_' %q 2>/dev/null | head -100 | while read -r f; do echo "ARTIFACT $f"; done
  find %q -maxdepth 4 -type f \( -name '.htaccess' -o -name '*.ini' -o -name '*.conf' \) 2>/dev/null | head -100 | while read -r f; do
    grep -Hn -E '(session\.upload_progress\.(enabled|name|cleanup)|session\.serialize_handler|session\.save_path|memory_limit|fatal_error_backtraces|post_max_size|upload_max_filesize)[[:space:]]*=|php_(admin_)?value' "$f" 2>/dev/null
  done
fi
`, root, root, root)
}

// Scan runs every host check and returns the findings plus metadata.
func Scan(ctx context.Context, p Prober, opts Options) ([]report.Finding, map[string]string, error) {
	var findings []report.Finding
	meta := map[string]string{}
	seen := map[string]bool{}

	add := func(f report.Finding) {
		key := f.ID + "|" + f.Title
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, f)
	}

	// ---- PHP interpreters -------------------------------------------------
	phpOut, err := p.Run(ctx, scriptPHP)
	if err != nil && strings.TrimSpace(phpOut) == "" {
		return nil, meta, fmt.Errorf("php probe failed: %w", err)
	}
	installs, modphp := parsePHPOutput(phpOut)
	if modphp != "" {
		add(report.Finding{
			ID:         "SAPI_MOD_PHP_IN_USE",
			Severity:   report.High,
			Title:      "mod_php is in use",
			Detail:     "mod_php runs request cleanup even when request startup failed, so the CVE-2026-109618 exploit can land before any application code runs. Application-level authentication cannot block it.",
			Evidence:   modphp,
			Mitigation: "Patch PHP and prefer PHP-FPM behind a reverse proxy.",
			CVE:        []string{"CVE-2026-109618"},
		})
	}
	var savePaths []string
	for _, pi := range installs {
		if pi.SavePath != "" {
			savePaths = append(savePaths, pi.SavePath)
		}
		reportInstall(add, pi, meta)
	}
	if len(installs) == 0 {
		add(report.Finding{
			ID:       "PHP_NOT_FOUND",
			Severity: report.Info,
			Title:    "No PHP interpreter found on this host",
			Detail:   "The probe did not find a php binary in PATH. Nothing to assess here; check the path or the target host.",
		})
	}

	// ---- configuration files ----------------------------------------------
	cfgOut, _ := p.Run(ctx, scriptConfig)
	cfgs := parseConfigOutput(cfgOut)

	// ---- document root artefacts and configuration -------------------------
	roots := []string{}
	if opts.Webroot != "" {
		roots = append(roots, opts.Webroot)
	}
	rootList, _ := p.Run(ctx, scriptRoots)
	roots = append(roots, parseRoots(rootList)...)
	if len(roots) == 0 {
		roots = append(roots, defaultRoots...)
	}
	roots = dedupe(roots)
	meta["web_roots"] = strings.Join(roots, ", ")
	for _, root := range roots {
		rootOut, _ := p.Run(ctx, scriptWebroot(root))
		for _, line := range strings.Split(rootOut, "\n") {
			if strings.HasPrefix(line, "ARTIFACT ") {
				add(report.Finding{
					ID:       "EXPLOIT_ARTIFACT_IN_WEBROOT",
					Severity: report.High,
					Title:    "File in the document root carries the upload_progress marker",
					Detail:   "A file below the document root contains 'upload_progress_'. That marker only shows up when the session.upload_progress primitive was used against this host.",
					Evidence: strings.TrimPrefix(line, "ARTIFACT "),
					CVE:      []string{"CVE-2026-109618", "CVE-2026-109619"},
				})
			}
		}
		cfgs = append(cfgs, parseConfigOutput(rootOut)...)
	}
	reportConfig(add, cfgs, meta)
	for _, c := range cfgs {
		if c.name == "session.save_path" && c.value != "" {
			savePaths = append(savePaths, c.value)
		}
	}

	// ---- session artefacts --------------------------------------------------
	dirs := dedupe(append(savePaths, []string{
		"/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php5/sessions",
		"/var/lib/php7/sessions", "/tmp",
	}...))
	sessOut, _ := p.Run(ctx, scriptSessions(dirs))
	reportSessions(add, sessOut)

	// ---- session artefacts --------------------------------------------------
	procOut, _ := p.Run(ctx, scriptProcs)
	reportProcesses(add, procOut)

	return findings, meta, nil
}

func reportInstall(add func(report.Finding), pi phpInfo, meta map[string]string) {
	meta["php_version"] = pi.Version
	meta["php_sapi"] = pi.SAPI

	st, ok := phpver.AssessString(pi.Version)
	ver := pi.Version
	if ok {
		ver = st.Version.String()
	}
	if ok {
		switch st.State {
		case phpver.StateVulnerable:
			add(report.Finding{
				ID:         "PHP_VERSION_AFFECTED",
				Severity:   report.Critical,
				Title:      fmt.Sprintf("PHP %s is affected by CVE-2026-109618 / CVE-2026-109619", ver),
				Detail:     st.Reason + ". Both are unauthenticated RCE in PHP core; exploitation needs no application-level authentication.",
				Evidence:   fmt.Sprintf("%s (sapi %s, ini %s)", pi.Binary, pi.SAPI, pi.IniFile),
				Mitigation: fmt.Sprintf("Update PHP to %s or later (or a vendor package carrying both patches).", st.FixedIn),
				CVE:        []string{"CVE-2026-109618", "CVE-2026-109619"},
			})
		case phpver.StateEOL:
			add(report.Finding{
				ID:         "PHP_VERSION_EOL_UNPATCHED",
				Severity:   report.Critical,
				Title:      fmt.Sprintf("PHP %s is an end-of-life branch with no routine upstream fixes", ver),
				Detail:     st.Reason,
				Evidence:   fmt.Sprintf("%s (sapi %s)", pi.Binary, pi.SAPI),
				Mitigation: "Upgrade to a supported branch, or apply the 7.4/8.0/8.1 source backports or a vendor security package.",
				CVE:        []string{"CVE-2026-109618", "CVE-2026-109619"},
			})
		case phpver.StatePatched:
			add(report.Finding{
				ID:       "PHP_VERSION_PATCHED",
				Severity: report.Info,
				Title:    fmt.Sprintf("PHP %s carries the upstream fixes", ver),
				Detail:   st.Reason,
				Evidence: fmt.Sprintf("%s (sapi %s)", pi.Binary, pi.SAPI),
			})
		default:
			add(report.Finding{
				ID:       "PHP_VERSION_UNKNOWN",
				Severity: report.Medium,
				Title:    fmt.Sprintf("PHP %s could not be matched to a known fixed release", ver),
				Detail:   st.Reason,
				Evidence: fmt.Sprintf("%s (sapi %s)", pi.Binary, pi.SAPI),
			})
		}
	}

	if !pi.HasIni {
		return
	}

	switch onOff(pi.UploadProgress) {
	case "on":
		add(report.Finding{
			ID:         "SESSION_UPLOAD_PROGRESS_ENABLED",
			Severity:   report.High,
			Title:      "session.upload_progress.enabled is on",
			Detail:     "Session upload progress is the early consumer of stale session state used by the session lifecycle path of CVE-2026-109619. It is on by default and does not need an application session_start() to be reached.",
			Evidence:   fmt.Sprintf("%s: session.upload_progress.enabled=%s", pi.Binary, pi.UploadProgress),
			Mitigation: "Set session.upload_progress.enabled=0 in php.ini, the FPM pool or server config that applies before request parsing, then restart every worker. ini_set() and .user.ini are applied too late.",
			CVE:        []string{"CVE-2026-109619"},
		})
	case "unknown":
		add(report.Finding{
			ID:       "SESSION_UPLOAD_PROGRESS_UNKNOWN",
			Severity: report.Medium,
			Title:    "session.upload_progress.enabled could not be read",
			Detail:   "The interpreter did not report the directive. Treat the feature as enabled until the deployed configuration proves otherwise.",
			Evidence: fmt.Sprintf("%s: ini file %s", pi.Binary, pi.IniFile),
			CVE:      []string{"CVE-2026-109619"},
		})
	}

	switch onOff(pi.UPCleanup) {
	case "off":
		add(report.Finding{
			ID:       "SESSION_UPLOAD_PROGRESS_CLEANUP_OFF",
			Severity: report.Medium,
			Title:    "session.upload_progress.cleanup is off",
			Detail:   "The upload progress entry stays in the session file after the request. Arming attempts therefore leave a persistent artefact on disk, and the stale entry keeps the session state alive between requests.",
			Evidence: fmt.Sprintf("%s: session.upload_progress.cleanup=%s", pi.Binary, pi.UPCleanup),
			CVE:      []string{"CVE-2026-109619"},
		})
	case "on":
		add(report.Finding{
			ID:       "SESSION_UPLOAD_PROGRESS_CLEANUP_ON",
			Severity: report.Info,
			Title:    "session.upload_progress.cleanup is on",
			Detail:   "The progress entry is removed when the request ends, so a session directory scan can miss earlier attempts. Use the request logs or the network detections instead.",
			Evidence: fmt.Sprintf("%s: session.upload_progress.cleanup=%s", pi.Binary, pi.UPCleanup),
			CVE:      []string{"CVE-2026-109619"},
		})
	}

	switch pi.MemoryLimit {
	case "-1":
		add(report.Finding{
			ID:       "MEMORY_LIMIT_DISABLED",
			Severity: report.Info,
			Title:    "memory_limit is -1 for this interpreter",
			Detail:   "The per-request memory cap is disabled, so the predictable PHP-limit OOM failure used by the CVE-2026-109618 exploit does not trigger.",
			Evidence: fmt.Sprintf("%s: memory_limit=-1", pi.Binary),
		})
	case "":
		// nothing to say
	default:
		add(report.Finding{
			ID:         "MEMORY_LIMIT_FINITE",
			Severity:   report.High,
			Title:      fmt.Sprintf("memory_limit is %s, leaving the OOM corruption path reachable", pi.MemoryLimit),
			Detail:     "CVE-2026-109618 is reached by exhausting the memory limit during request handling. A finite limit makes that failure predictable and reproducible.",
			Evidence:   fmt.Sprintf("%s: memory_limit=%s", pi.Binary, pi.MemoryLimit),
			Mitigation: "Enforce memory_limit=-1 administratively (FPM pool or Apache config the application cannot override) and keep independent request-size limits.",
			CVE:        []string{"CVE-2026-109618"},
		})
	}

	if onOff(pi.FatalBacktraces) == "on" && strings.HasPrefix(pi.Version, "8.5") {
		add(report.Finding{
			ID:         "FATAL_ERROR_BACKTRACES_ENABLED",
			Severity:   report.High,
			Title:      "fatal_error_backtraces is enabled on PHP 8.5",
			Detail:     "On 8.5 the fatal error backtrace feature is the confirmed path where a later request reads stale backtrace state from an earlier request (CVE-2026-109619).",
			Evidence:   fmt.Sprintf("%s: fatal_error_backtraces=%s", pi.Binary, pi.FatalBacktraces),
			Mitigation: "Set fatal_error_backtraces=0 administratively and restart every worker.",
			CVE:        []string{"CVE-2026-109619"},
		})
	}

	if pi.SerializeHandler == "php_serialize" {
		add(report.Finding{
			ID:         "SESSION_SERIALIZE_HANDLER_NON_DEFAULT",
			Severity:   report.Medium,
			Title:      "session.serialize_handler is php_serialize",
			Detail:     "Apps that share one session.save_path but disagree on the serialize handler produce a decode failure when the session is read back with the default 'php' handler. That mismatch is one half of the session primitive.",
			Evidence:   fmt.Sprintf("%s: session.serialize_handler=%s save_path=%s", pi.Binary, pi.SerializeHandler, pi.SavePath),
			Mitigation: "Use one handler for every app that shares a session.save_path, or give each app its own save_path.",
		})
	}

	if onOff(pi.UseOnlyCookies) == "off" {
		add(report.Finding{
			ID:         "SESSION_ID_FROM_BODY_ACCEPTED",
			Severity:   report.Medium,
			Title:      "session.use_only_cookies is off",
			Detail:     "A session id supplied in the request body is accepted. Attackers arm session.upload_progress with a body field and no cookie, which is the request shape the network detections key on.",
			Evidence:   fmt.Sprintf("%s: session.use_only_cookies=%s", pi.Binary, pi.UseOnlyCookies),
			Mitigation: "Set session.use_only_cookies=1 and session.use_strict_mode=1.",
			CVE:        []string{"CVE-2026-109619"},
		})
	}
}

// configEntry is one directive found in a configuration file.
type configEntry struct {
	file  string
	line  string
	name  string
	value string
}

var directiveRe = regexp.MustCompile(`(session\.upload_progress\.(enabled|name|cleanup)|session\.serialize_handler|session\.save_path|memory_limit|fatal_error_backtraces|post_max_size|upload_max_filesize)`)

// knownDirectives are the ini directives the scanner reasons about.
var knownDirectives = []string{
	"session.upload_progress.enabled",
	"session.upload_progress.name",
	"session.upload_progress.cleanup",
	"session.serialize_handler",
	"session.save_path",
	"memory_limit",
	"fatal_error_backtraces",
	"post_max_size",
	"upload_max_filesize",
}

var (
	phpAdminValueRe = regexp.MustCompile(`(?i)^php_admin_value\[([a-z0-9_.]+)\]\s*=\s*(.+)$`)
	phpValueRe      = regexp.MustCompile(`(?i)^php_value\s+([a-z0-9_.]+)(?:\s*=\s*|\s+)(.+)$`)
)

// parseDirective reads one directive out of a configuration line.
func parseDirective(content string) (name, value string) {
	content = strings.TrimSpace(content)
	if content == "" || strings.HasPrefix(content, ";") || strings.HasPrefix(content, "#") {
		return "", ""
	}
	if m := phpAdminValueRe.FindStringSubmatch(content); m != nil {
		return strings.ToLower(m[1]), strings.Trim(strings.TrimSpace(m[2]), `"'`)
	}
	if m := phpValueRe.FindStringSubmatch(content); m != nil {
		return strings.ToLower(m[1]), strings.Trim(strings.TrimSpace(m[2]), `"'`)
	}
	for _, d := range knownDirectives {
		if !strings.HasPrefix(content, d) {
			continue
		}
		rest := strings.TrimSpace(content[len(d):])
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		return d, strings.Trim(strings.TrimSpace(rest[1:]), `"'`)
	}
	return "", ""
}

// parseConfigOutput turns "file:line:content" lines into directive entries.
func parseConfigOutput(out string) []configEntry {
	var entries []configEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		file, lineno, content := parts[0], parts[1], parts[2]
		name, value := parseDirective(content)
		if name == "" {
			continue
		}
		entries = append(entries, configEntry{file: file, line: lineno, name: name, value: value})
	}
	return entries
}

func reportConfig(add func(report.Finding), entries []configEntry, meta map[string]string) {
	handlers := map[string]string{}
	for _, e := range entries {
		switch e.name {
		case "session.upload_progress.enabled":
			switch onOff(e.value) {
			case "off":
				sev := report.Info
				note := "The directive is disabled in this file."
				if strings.HasSuffix(e.file, ".user.ini") {
					sev = report.Medium
					note = "The directive is disabled in a .user.ini file. Per the advisory, .user.ini is applied after request parsing starts, so it does not close the window."
				}
				add(report.Finding{
					ID:         "SESSION_UPLOAD_PROGRESS_DISABLED_IN_CONFIG",
					Severity:   sev,
					Title:      "session.upload_progress.enabled is disabled in " + e.file,
					Detail:     note + " The session lifecycle path of CVE-2026-109619 needs this feature.",
					Evidence:   e.file + ":" + e.line,
					Mitigation: "Make sure the value is applied by the config that runs before request parsing and that every worker was restarted.",
					CVE:        []string{"CVE-2026-109619"},
				})
			case "on":
				add(report.Finding{
					ID:         "SESSION_UPLOAD_PROGRESS_ENABLED_IN_CONFIG",
					Severity:   report.High,
					Title:      "session.upload_progress.enabled is on in " + e.file,
					Detail:     "The web SAPI keeps the session.upload_progress feature enabled, which is the confirmed session path of CVE-2026-109619.",
					Evidence:   e.file + ":" + e.line,
					Mitigation: "Set session.upload_progress.enabled=0 in this file and restart every worker.",
					CVE:        []string{"CVE-2026-109619"},
				})
			}
		case "memory_limit":
			if e.value == "-1" {
				add(report.Finding{
					ID:       "MEMORY_LIMIT_DISABLED_IN_CONFIG",
					Severity: report.Info,
					Title:    "memory_limit is -1 in " + e.file,
					Detail:   "This configuration removes the predictable memory-limit failure used by the CVE-2026-109618 exploit.",
					Evidence: e.file + ":" + e.line,
					CVE:      []string{"CVE-2026-109618"},
				})
			} else {
				add(report.Finding{
					ID:         "MEMORY_LIMIT_FINITE_IN_CONFIG",
					Severity:   report.High,
					Title:      fmt.Sprintf("memory_limit is %s in %s", e.value, e.file),
					Detail:     "A finite memory limit in the web configuration keeps the OOM corruption path of CVE-2026-109618 reachable.",
					Evidence:   e.file + ":" + e.line,
					Mitigation: "Enforce memory_limit=-1 in a place the application cannot override, then restart every worker.",
					CVE:        []string{"CVE-2026-109618"},
				})
			}
		case "fatal_error_backtraces":
			if onOff(e.value) == "off" {
				add(report.Finding{
					ID:       "FATAL_ERROR_BACKTRACES_DISABLED_IN_CONFIG",
					Severity: report.Info,
					Title:    "fatal_error_backtraces is disabled in " + e.file,
					Detail:   "This closes the confirmed 8.5 backtrace path of CVE-2026-109619.",
					Evidence: e.file + ":" + e.line,
					CVE:      []string{"CVE-2026-109619"},
				})
			}
		case "session.serialize_handler":
			if e.value != "" {
				handlers[e.value] = e.file
			}
		}
	}
	if len(handlers) > 1 {
		files := make([]string, 0, len(handlers))
		for h, f := range handlers {
			files = append(files, h+" ("+f+")")
		}
		add(report.Finding{
			ID:         "SESSION_SERIALIZE_HANDLER_MISMATCH",
			Severity:   report.High,
			Title:      "session.serialize_handler differs between configuration files",
			Detail:     "Apps that share one session.save_path but write and read with different serialize handlers produce a decode failure when the session is read back. That mismatch is one half of the session primitive used for CVE-2026-109619.",
			Evidence:   strings.Join(files, ", "),
			Mitigation: "Use one handler for every app sharing a session.save_path, or give each app its own save_path.",
			CVE:        []string{"CVE-2026-109619"},
		})
	}
	if len(handlers) == 1 {
		for h, f := range handlers {
			meta["session_serialize_handler"] = h + " (" + f + ")"
		}
	}
}

func reportSessions(add func(report.Finding), out string) {
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "POISON "):
			path := strings.TrimPrefix(line, "POISON ")
			add(report.Finding{
				ID:         "SESSION_FILE_POISONED",
				Severity:   report.Critical,
				Title:      "Session file poisoned through session.upload_progress",
				Detail:     "The session file carries the upload_progress key together with a PHP open tag. That is the content injection artefact of the primitive; a webshell or RCE payload can be delivered through it.",
				Evidence:   path,
				Mitigation: "Delete the session file, patch PHP, rotate credentials and hunt for the request that created it.",
				CVE:        []string{"CVE-2026-109618", "CVE-2026-109619"},
			})
		case strings.HasPrefix(line, "SNIPPET "):
			rest := strings.TrimPrefix(line, "SNIPPET ")
			path, seg, _ := strings.Cut(rest, " ")
			if abortedSerialization(seg) {
				add(report.Finding{
					ID:       "SESSION_FILE_WRITE_DENIAL",
					Severity: report.Medium,
					Title:    "Session file shows the write-denial primitive",
					Detail:   "The upload_progress key is followed by something that is not a serialized value, which means the session serializer aborted and the write was denied. That is a denial of service against session handling.",
					Evidence: path + " -> " + seg,
					CVE:      []string{"CVE-2026-109619"},
				})
			}
		case strings.HasPrefix(line, "MARKER "):
			add(report.Finding{
				ID:       "SESSION_FILE_UPLOAD_PROGRESS_MARKER",
				Severity: report.Medium,
				Title:    "Session file contains the upload_progress marker",
				Detail:   "The session was written through the session.upload_progress feature. Legitimate uploads also produce this marker, so treat it as an attempt indicator until the request source is known.",
				Evidence: strings.TrimPrefix(line, "MARKER "),
				CVE:      []string{"CVE-2026-109619"},
			})
		}
	}
}

var (
	// phpExeRe matches the binary name of a PHP interpreter.
	phpExeRe = regexp.MustCompile(`(?i)^php(-fpm|-cgi)?(\d+(\.\d+)*)?$`)
	// webExeRe matches the web servers that can run PHP in-process (mod_php).
	webExeRe = regexp.MustCompile(`(?i)^(apache2|httpd|nginx)$`)
	shellRe  = regexp.MustCompile(`(^|/)(sh|bash|dash|zsh|ksh|ash)\b`)
)

// isPHPProcess reports whether the command line belongs to a process that can
// run PHP code: an interpreter, or a web server that embeds it (mod_php).
func isPHPProcess(args string) bool {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return false
	}
	base := fields[0]
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return phpExeRe.MatchString(base) || webExeRe.MatchString(base)
}

// reportProcesses looks for the post-exploitation tell and identifies the SAPI.
// abortedSerialization reports whether a serialized session record is broken,
// which is what the write-denial primitive leaves behind.
func abortedSerialization(seg string) bool {
	_, after, ok := strings.Cut(seg, "|")
	if !ok {
		return true
	}
	for _, prefix := range []string{"s:", "i:", "d:", "b:", "a:", "O:", "N:", "C:", "E:", "R:", "r:"} {
		if strings.HasPrefix(after, prefix) {
			return false
		}
	}
	return true
}

func reportProcesses(add func(report.Finding), out string) {
	type proc struct {
		ppid int
		args string
	}
	procs := map[int]proc{}
	fpmSeen := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err1 := parseInt(fields[0])
		ppid, err2 := parseInt(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		args := strings.Join(fields[2:], " ")
		procs[pid] = proc{ppid: ppid, args: args}
		lower := strings.ToLower(args)
		if strings.Contains(lower, "php-fpm") && !strings.Contains(lower, "grep") {
			fpmSeen = true
		}
	}
	for pid, p := range procs {
		if !isPHPProcess(p.args) {
			continue
		}
		for child, c := range procs {
			if c.ppid != pid {
				continue
			}
			if shellRe.MatchString(c.args) {
				add(report.Finding{
					ID:         "PHP_PROCESS_SPAWNED_SHELL",
					Severity:   report.Critical,
					Title:      "PHP worker spawned a shell",
					Detail:     "A PHP process has a shell as child process. Legitimate applications do this rarely; together with the session artefacts it is the post-exploitation tell.",
					Evidence:   fmt.Sprintf("pid %d: %s -> pid %d: %s", pid, p.args, child, c.args),
					Mitigation: "Treat the host as compromised: isolate it, preserve evidence, rotate secrets and rebuild from a patched image.",
					CVE:        []string{"CVE-2026-109618", "CVE-2026-109619"},
				})
			}
		}
	}
	if fpmSeen {
		add(report.Finding{
			ID:       "SAPI_FPM_IN_USE",
			Severity: report.Info,
			Title:    "PHP-FPM is the serving SAPI",
			Detail:   "With PHP-FPM the OOM corruption path of CVE-2026-109618 needs a request that survives startup, and the session path of CVE-2026-109619 needs two requests to reach the same worker. Worker recycling lowers the hit rate but does not remove the condition.",
			CVE:      []string{"CVE-2026-109618", "CVE-2026-109619"},
		})
	}
}

func parseInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number: %s", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// onOff normalises an ini value into on/off/unknown.
func onOff(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return "on"
	case "0", "off", "false", "no", "":
		if strings.TrimSpace(v) == "" {
			return "unknown"
		}
		return "off"
	default:
		return "unknown"
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// parsePHPOutput parses the machine readable output of scriptPHP. It returns
// the interpreters it found and the mod_php evidence, if any.
func parsePHPOutput(out string) ([]phpInfo, string) {
	var installs []phpInfo
	modphp := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PHPINFO "):
			var pi phpInfo
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "PHPINFO ")), &pi); err == nil {
				installs = append(installs, pi)
			}
		case strings.HasPrefix(line, "FPMVER "):
			ver := strings.TrimPrefix(line, "FPMVER ")
			installs = append(installs, phpInfo{Binary: "php-fpm", Version: ver, SAPI: "fpm-fcgi"})
		case strings.HasPrefix(line, "MODPHP "):
			if modphp == "" {
				modphp = strings.TrimPrefix(line, "MODPHP ")
			}
		}
	}
	return installs, modphp
}
