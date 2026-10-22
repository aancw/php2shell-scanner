// Package blackbox scans a web target for PHP2Shell exposure (CVE-2026-109618 /
// CVE-2026-109619) over HTTP only, without shell access to the host.
package blackbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/aancw/php2shell-scanner/internal/phpver"
	"github.com/aancw/php2shell-scanner/internal/report"
)

// Options configure a blackbox scan.
type Options struct {
	URL       string
	Timeout   time.Duration
	Insecure  bool
	UserAgent string
	Probe     bool // send the session.upload_progress arming probe
	Canary    bool // arming probe carries an inert PHP comment (Suricata/YARA validation)
	Crawl     bool // look for exposed phpinfo pages
	Paths     []string
}

// phpinfoEgg is the phpinfo() easter egg query. It only renders when the
// script actually calls phpinfo(), so a hit means a phpinfo page is exposed.
const phpinfoEgg = "PHPB8B5F2A0-3C92-11d3-a3c9-0004fbf49f1e"

var defaultPaths = []string{
	"index.php", "info.php", "phpinfo.php", "test.php", "pi.php",
	"i.php", "php.php", "status.php", "phpversion.php", "version.php",
}

var (
	poweredByRe = regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`)
	versionRe   = regexp.MustCompile(`PHP Version (\d+\.\d+\.\d+)`)
	phpinfoRow  = regexp.MustCompile(`(?s)<td[^>]*class="e"[^>]*>(.*?)</td>\s*<td[^>]*class="v"[^>]*>(.*?)</td>`)
	tagRe       = regexp.MustCompile(`(?s)<[^>]+>`)
)

// Scan runs the blackbox checks and returns findings plus metadata.
func Scan(ctx context.Context, opts Options) ([]report.Finding, map[string]string, error) {
	base, err := normalizeURL(opts.URL)
	if err != nil {
		return nil, nil, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "php2shell-scanner/1.0"
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure},
		},
	}

	var findings []report.Finding
	meta := map[string]string{"target": base}

	// ---- first GET ---------------------------------------------------------
	resp, body, err := get(ctx, client, base, opts.UserAgent)
	if err != nil {
		return nil, meta, fmt.Errorf("request %s: %w", base, err)
	}
	meta["http_status"] = fmt.Sprint(resp.StatusCode)
	meta["server"] = resp.Header.Get("Server")

	// ---- endpoint collection -----------------------------------------------
	version, source, phpinfoURL, ini, phpEndpoint := collect(ctx, client, base, resp, body, opts)
	if phpinfoURL != "" {
		meta["phpinfo_url"] = phpinfoURL
		findings = append(findings, report.Finding{
			ID:         "PHPINFO_EXPOSED",
			Severity:   report.Medium,
			Title:      "phpinfo() output is reachable",
			Detail:     "A phpinfo page is exposed. It leaks the full configuration, the save paths and the installed modules, and it lets anyone read the values this scanner checks.",
			Evidence:   phpinfoURL,
			Mitigation: "Remove or restrict the phpinfo page.",
		})
	}
	if version == "" {
		findings = append(findings, report.Finding{
			ID:       "PHP_NOT_CONFIRMED",
			Severity: report.Info,
			Title:    "No PHP signature found",
			Detail:   "The response carries no X-Powered-By header and no version string in the body. Either the target is not PHP, or it hides its version (expose_php=Off) and exposes no phpinfo page.",
			Evidence: fmt.Sprintf("HTTP %d, Server: %s", resp.StatusCode, resp.Header.Get("Server")),
		})
	}

	// ---- version verdict ---------------------------------------------------
	if version != "" {
		st, ok := phpver.AssessString(version)
		meta["php_version"] = version
		meta["php_version_source"] = source
		if ok {
			switch st.State {
			case phpver.StateVulnerable:
				findings = append(findings, report.Finding{
					ID:         "PHP_VERSION_AFFECTED",
					Severity:   report.Critical,
					Title:      fmt.Sprintf("PHP %s is affected by CVE-2026-109618 / CVE-2026-109619", version),
					Detail:     st.Reason + ". Both are unauthenticated RCE in PHP core and application-level authentication cannot block them.",
					Evidence:   version + " (" + source + ")",
					Mitigation: fmt.Sprintf("Update PHP to %s or later, or to a vendor package that carries both patches.", st.FixedIn),
					CVE:        []string{"CVE-2026-109618", "CVE-2026-109619"},
				})
			case phpver.StateEOL:
				findings = append(findings, report.Finding{
					ID:         "PHP_VERSION_EOL_UNPATCHED",
					Severity:   report.Critical,
					Title:      fmt.Sprintf("PHP %s is an end-of-life branch with no routine upstream fixes", version),
					Detail:     st.Reason,
					Evidence:   version + " (" + source + ")",
					Mitigation: "Upgrade to a supported branch, or apply the 7.4/8.0/8.1 source backports or a vendor security package.",
					CVE:        []string{"CVE-2026-109618", "CVE-2026-109619"},
				})
			case phpver.StatePatched:
				findings = append(findings, report.Finding{
					ID:       "PHP_VERSION_PATCHED",
					Severity: report.Info,
					Title:    fmt.Sprintf("PHP %s carries the upstream fixes", version),
					Detail:   st.Reason,
					Evidence: version + " (" + source + ")",
				})
			default:
				findings = append(findings, report.Finding{
					ID:       "PHP_VERSION_UNKNOWN",
					Severity: report.Medium,
					Title:    fmt.Sprintf("PHP %s could not be matched to a known fixed release", version),
					Detail:   st.Reason,
					Evidence: version + " (" + source + ")",
				})
			}
		}
	}

	// ---- SAPI --------------------------------------------------------------
	sapi := detectSAPI(resp.Header, ini)
	if sapi != "" {
		meta["sapi"] = sapi
		switch {
		case strings.Contains(sapi, "Apache 2.0 Handler"):
			findings = append(findings, report.Finding{
				ID:         "SAPI_MOD_PHP",
				Severity:   report.High,
				Title:      "mod_php is the serving SAPI",
				Detail:     "mod_php runs cleanup even when request startup failed, so the CVE-2026-109618 exploit can land before any application code runs. Application-level authentication cannot block it.",
				Evidence:   "Server API: " + sapi,
				Mitigation: "Patch PHP and prefer PHP-FPM behind a reverse proxy.",
				CVE:        []string{"CVE-2026-109618"},
			})
		case strings.Contains(sapi, "FPM"):
			findings = append(findings, report.Finding{
				ID:       "SAPI_FPM",
				Severity: report.Info,
				Title:    "PHP-FPM is the serving SAPI",
				Detail:   "With PHP-FPM the OOM path needs a request that survives startup and the session path needs two requests to reach the same worker. Worker recycling lowers the hit rate but does not remove the condition.",
				Evidence: "Server API: " + sapi,
				CVE:      []string{"CVE-2026-109618", "CVE-2026-109619"},
			})
		}
	}

	// ---- ini values --------------------------------------------------------
	findings = append(findings, iniFindings(version, ini)...)
	if phpinfoURL != "" && !hasKnownDirective(ini) {
		findings = append(findings, report.Finding{
			ID:       "PHPINFO_WITHOUT_CONFIG",
			Severity: report.Info,
			Title:    "phpinfo does not expose the configuration section",
			Detail:   "The page renders the general section only, so session.upload_progress.enabled, memory_limit and fatal_error_backtraces could not be read over HTTP. Use the local or ssh mode for those values.",
			Evidence: phpinfoURL,
		})
	}

	// ---- active probe ------------------------------------------------------
	if opts.Probe {
		target := base
		if phpEndpoint != "" {
			target = phpEndpoint
		}
		probeFindings, err := probe(ctx, client, target, opts)
		if err != nil {
			findings = append(findings, report.Finding{
				ID:       "PROBE_FAILED",
				Severity: report.Low,
				Title:    "Session arming probe could not be completed",
				Detail:   "The probe request failed, so the session behaviour of this target is unknown.",
				Evidence: err.Error(),
			})
		} else {
			findings = append(findings, probeFindings...)
		}
	}

	return findings, meta, nil
}

// hasKnownDirective reports whether a phpinfo page carries the configuration
// section the scanner reads.
func hasKnownDirective(ini map[string]string) bool {
	for _, key := range []string{
		"session.upload_progress.enabled",
		"session.serialize_handler",
		"session.save_path",
		"memory_limit",
		"fatal_error_backtraces",
	} {
		if _, ok := ini[key]; ok {
			return true
		}
	}
	return false
}

// iniFindings turns phpinfo values into findings.
func iniFindings(version string, ini map[string]string) []report.Finding {
	var out []report.Finding
	if v := ini["session.upload_progress.enabled"]; v != "" {
		if isOn(v) {
			out = append(out, report.Finding{
				ID:         "SESSION_UPLOAD_PROGRESS_ENABLED",
				Severity:   report.High,
				Title:      "session.upload_progress.enabled is on",
				Detail:     "Session upload progress is the early consumer of stale session state in the session lifecycle path of CVE-2026-109619. It is on by default and needs no application session_start() to be reached.",
				Evidence:   "session.upload_progress.enabled = " + v,
				Mitigation: "Set session.upload_progress.enabled=0 in the config that applies before request parsing and restart every worker.",
				CVE:        []string{"CVE-2026-109619"},
			})
		} else {
			out = append(out, report.Finding{
				ID:       "SESSION_UPLOAD_PROGRESS_DISABLED",
				Severity: report.Info,
				Title:    "session.upload_progress.enabled is disabled",
				Detail:   "The session lifecycle path of CVE-2026-109619 depends on this feature, so the phpinfo value points at it being closed for this vhost.",
				Evidence: "session.upload_progress.enabled = " + v,
				CVE:      []string{"CVE-2026-109619"},
			})
		}
	}
	if v := ini["session.upload_progress.cleanup"]; v != "" {
		if isOn(v) {
			out = append(out, report.Finding{
				ID:       "SESSION_UPLOAD_PROGRESS_CLEANUP_ON",
				Severity: report.Info,
				Title:    "session.upload_progress.cleanup is on",
				Detail:   "The progress entry is removed when the request ends, so a session directory scan can miss earlier attempts. Use the request logs or the network detections instead.",
				Evidence: "session.upload_progress.cleanup = " + v,
				CVE:      []string{"CVE-2026-109619"},
			})
		} else {
			out = append(out, report.Finding{
				ID:       "SESSION_UPLOAD_PROGRESS_CLEANUP_OFF",
				Severity: report.Medium,
				Title:    "session.upload_progress.cleanup is off",
				Detail:   "The upload progress entry stays in the session file after the request, so arming attempts leave a persistent artefact on disk and the stale entry keeps session state alive between requests.",
				Evidence: "session.upload_progress.cleanup = " + v,
				CVE:      []string{"CVE-2026-109619"},
			})
		}
	}
	if v := ini["memory_limit"]; v != "" && v != "-1" {
		out = append(out, report.Finding{
			ID:         "MEMORY_LIMIT_FINITE",
			Severity:   report.High,
			Title:      fmt.Sprintf("memory_limit is %s, leaving the OOM corruption path reachable", v),
			Detail:     "CVE-2026-109618 is reached by exhausting the memory limit while a request is handled. A finite limit makes that failure predictable.",
			Evidence:   "memory_limit = " + v,
			Mitigation: "Enforce memory_limit=-1 administratively and keep independent request size limits.",
			CVE:        []string{"CVE-2026-109618"},
		})
	}
	if v := ini["fatal_error_backtraces"]; v != "" && isOn(v) && strings.HasPrefix(version, "8.5") {
		out = append(out, report.Finding{
			ID:         "FATAL_ERROR_BACKTRACES_ENABLED",
			Severity:   report.High,
			Title:      "fatal_error_backtraces is enabled on PHP 8.5",
			Detail:     "On 8.5 the fatal error backtrace feature is the confirmed path where a later request reads stale backtrace state from an earlier request.",
			Evidence:   "fatal_error_backtraces = " + v,
			Mitigation: "Set fatal_error_backtraces=0 administratively and restart every worker.",
			CVE:        []string{"CVE-2026-109619"},
		})
	}
	if v := ini["session.use_only_cookies"]; v != "" && !isOn(v) {
		out = append(out, report.Finding{
			ID:         "SESSION_ID_FROM_BODY_ACCEPTED",
			Severity:   report.Medium,
			Title:      "session.use_only_cookies is off",
			Detail:     "A session id supplied in the request body is accepted. The session.upload_progress arming request uses exactly that shape, with the session id in the body and no cookie.",
			Evidence:   "session.use_only_cookies = " + v,
			Mitigation: "Set session.use_only_cookies=1 and session.use_strict_mode=1.",
			CVE:        []string{"CVE-2026-109619"},
		})
	}
	if v := ini["session.serialize_handler"]; v == "php_serialize" {
		out = append(out, report.Finding{
			ID:         "SESSION_SERIALIZE_HANDLER_NON_DEFAULT",
			Severity:   report.Medium,
			Title:      "session.serialize_handler is php_serialize",
			Detail:     "Apps that share one session.save_path but disagree on the serialize handler produce a decode failure when the session is read back with the default handler. That mismatch is one half of the session primitive.",
			Evidence:   "session.serialize_handler = " + v,
			Mitigation: "Use one handler for every app that shares a session.save_path.",
		})
	}
	return out
}

// probe sends the session.upload_progress arming request and reads the answer.
func probe(ctx context.Context, client *http.Client, base string, opts Options) ([]report.Finding, error) {
	sid := "p2s" + randomHex(12)
	marker := "php2shell-scanner " + randomHex(6)
	filename := "p2s-probe.txt"
	if opts.Canary {
		canary := fmt.Sprintf("<?php /* php2shell-scanner inert canary %s - not a shell */ ?>", randomHex(6))
		marker = canary
		filename = "p2s" + canary + ".txt"
	}
	boundary := "----php2shellscanner" + randomHex(8)
	body := buildProbeBody(boundary, sid, marker, filename)

	target := base
	resp, respBody, err := post(ctx, client, target, boundary, body, opts.UserAgent)
	if err != nil {
		return nil, err
	}
	cookies := resp.Cookies()
	var findings []report.Finding

	evidence := fmt.Sprintf("POST %s -> HTTP %d", target, resp.StatusCode)
	findings = append(findings, report.Finding{
		ID:       "SESSION_ARMING_PROBE_SENT",
		Severity: report.Info,
		Title:    "session.upload_progress arming request sent",
		Detail:   "The probe posted a multipart body with a PHPSESSID field and a PHP_SESSION_UPLOAD_PROGRESS field, no cookie. This is the request shape the network detections key on, so correlate it with the Suricata rules in php2shell-lab.",
		Evidence: evidence,
	})

	for _, c := range cookies {
		if c.Name != "PHPSESSID" {
			continue
		}
		if c.Value == sid {
			findings = append(findings, report.Finding{
				ID:         "SESSION_FIXATION_VIA_BODY",
				Severity:   report.Medium,
				Title:      "Session id supplied in the request body was accepted",
				Detail:     "The server continued the session id that was sent in the POST body. An attacker can therefore pick the session id that the upload_progress primitive writes into.",
				Evidence:   "Set-Cookie: PHPSESSID=" + c.Value,
				Mitigation: "Set session.use_only_cookies=1 and session.use_strict_mode=1.",
				CVE:        []string{"CVE-2026-109619"},
			})
		} else {
			findings = append(findings, report.Finding{
				ID:       "SESSION_ID_FROM_BODY_NOT_REUSED",
				Severity: report.Info,
				Title:    "Application issued its own session id",
				Detail:   "The response carried a different session id than the one in the request body, so session_start() honoured session.use_only_cookies. The upload_progress feature still writes to the injected id before the application runs, so the arming can take effect anyway. A host-side scan of the session directory confirms it.",
				Evidence: "Set-Cookie: PHPSESSID=" + c.Value,
				CVE:      []string{"CVE-2026-109619"},
			})
		}
	}

	if strings.Contains(respBody, "Failed to decode session object") {
		findings = append(findings, report.Finding{
			ID:         "SESSION_HANDLER_MISMATCH_CONFIRMED",
			Severity:   report.High,
			Title:      "Session decode failed because of a serialize handler mismatch",
			Detail:     "The server reported that it could not decode the session object. Two apps share one session.save_path but write and read it with different serialize handlers, which is the configuration half of the session primitive.",
			Evidence:   "Failed to decode session object. Session has been destroyed.",
			Mitigation: "Use one handler for every app that shares a session.save_path, or give each app its own save_path.",
			CVE:        []string{"CVE-2026-109619"},
		})
	}
	return findings, nil
}

// buildProbeBody builds the multipart body of the arming probe.
func buildProbeBody(boundary, sid, marker, filename string) []byte {
	var b bytes.Buffer
	part := func(disposition, value string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; %s\r\n\r\n%s\r\n", boundary, disposition, value)
	}
	part(`name="PHPSESSID"`, sid)
	part(`name="PHP_SESSION_UPLOAD_PROGRESS"`, marker)
	fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, filename)
	b.WriteString("PROBEDATA\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// collect walks the target endpoints, reads the PHP version and picks up an
// exposed phpinfo page. It returns the version, where it came from, the
// phpinfo url, the ini values and the endpoint that serves PHP.
func collect(ctx context.Context, client *http.Client, base string, baseResp *http.Response, baseBody string, opts Options) (string, string, string, map[string]string, string) {
	version, source := "", ""
	ini := map[string]string{}
	phpinfoURL, phpEndpoint := "", ""

	consider := func(u string, h http.Header, body string) bool {
		if v, s := detectVersion(h, body); v != "" {
			if version == "" {
				version, source = v, s+" of "+u
			}
			if phpEndpoint == "" {
				phpEndpoint = u
			}
		}
		if strings.Contains(body, "PHP Version") {
			phpinfoURL = u
			ini = parsePhpinfo(body)
			return true
		}
		return false
	}

	if consider(base, baseResp.Header, baseBody) {
		return version, source, phpinfoURL, ini, phpEndpoint
	}

	for _, candidate := range candidateURLs(base, opts) {
		u, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		u.RawQuery = "=" + phpinfoEgg
		probeURL := u.String()
		resp, body, err := get(ctx, client, probeURL, opts.UserAgent)
		if err != nil {
			continue
		}
		if consider(probeURL, resp.Header, body) {
			return version, source, phpinfoURL, ini, phpEndpoint
		}
	}
	return version, source, phpinfoURL, ini, phpEndpoint
}

// candidateURLs lists the endpoints to walk.
func candidateURLs(base string, opts Options) []string {
	b, err := url.Parse(base)
	if err != nil {
		return nil
	}
	var out []string
	if strings.HasSuffix(strings.ToLower(b.Path), ".php") {
		out = append(out, b.String())
	}
	add := func(c string) {
		if c == "" {
			return
		}
		cu, err := url.Parse(c)
		if err != nil {
			return
		}
		if cu.Scheme != "" && cu.Host != "" {
			out = append(out, cu.String())
			return
		}
		nb := *b
		nb.Path = path.Join(b.Path, c)
		nb.RawQuery = ""
		out = append(out, nb.String())
	}
	for _, c := range opts.Paths {
		add(c)
	}
	if opts.Crawl {
		for _, c := range defaultPaths {
			add(c)
		}
	}
	return out
}

// parsePhpinfo extracts the directive values from a phpinfo page.
func parsePhpinfo(body string) map[string]string {
	ini := map[string]string{}
	for _, m := range phpinfoRow.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(strings.TrimSpace(tagRe.ReplaceAllString(m[1], "")))
		value := strings.TrimSpace(tagRe.ReplaceAllString(m[2], ""))
		if name != "" {
			ini[name] = value
		}
	}
	if v := versionRe.FindStringSubmatch(body); v != nil {
		ini["php version"] = v[1]
	}
	return ini
}

// detectVersion reads the PHP version from the headers or the body.
func detectVersion(h http.Header, body string) (string, string) {
	if v := poweredByRe.FindStringSubmatch(h.Get("X-Powered-By")); v != nil {
		return v[1], "X-Powered-By"
	}
	if v := poweredByRe.FindStringSubmatch(h.Get("Server")); v != nil {
		return v[1], "Server"
	}
	if v := versionRe.FindStringSubmatch(body); v != nil {
		return v[1], "body"
	}
	if v := poweredByRe.FindStringSubmatch(body); v != nil {
		return v[1], "body"
	}
	return "", ""
}

// detectSAPI guesses the serving SAPI from the headers and the phpinfo values.
func detectSAPI(h http.Header, ini map[string]string) string {
	if v := ini["server api"]; v != "" {
		return v
	}
	server := strings.ToLower(h.Get("Server"))
	powered := strings.ToLower(h.Get("X-Powered-By"))
	switch {
	case strings.Contains(server, "apache") && powered != "":
		return "Apache 2.0 Handler (inferred)"
	case strings.Contains(server, "nginx") && powered != "":
		return "FPM/FastCGI (inferred from nginx + PHP)"
	case strings.Contains(server, "nginx"):
		return "FPM/FastCGI (inferred from nginx)"
	}
	return ""
}

func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("no url given")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("bad url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("bad url %q: no host", raw)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func get(ctx context.Context, client *http.Client, target, ua string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp, string(body), err
}

func post(ctx context.Context, client *http.Client, target, boundary string, body []byte, ua string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(respBody), err
}

func isOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}
