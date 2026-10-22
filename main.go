// Command php2shell-scanner detects PHP2Shell exposure (CVE-2026-109618 and
// CVE-2026-109619) against web targets, the local machine or remote hosts
// reachable over SSH.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aancw/php2shell-scanner/internal/blackbox"
	"github.com/aancw/php2shell-scanner/internal/hostcheck"
	"github.com/aancw/php2shell-scanner/internal/report"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `php2shell-scanner - detect PHP2Shell exposure (CVE-2026-109618, CVE-2026-109619)

usage:
  php2shell-scanner url   -u <url>       blackbox scan over HTTP (repeatable)
  php2shell-scanner local                 scan this machine
  php2shell-scanner ssh   -H <host>       scan hosts over SSH (repeatable)

run "php2shell-scanner <command> -h" for the flags of a command.
`

func usageText() string {
	return fmt.Sprintf("php2shell-scanner %s\n\n%s", version, usage)
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText())
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "url":
		code = runURL(os.Args[2:])
	case "local":
		code = runLocal(os.Args[2:])
	case "ssh":
		code = runSSH(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usageText())
		code = 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usageText())
		code = 2
	}
	os.Exit(code)
}

func runURL(args []string) int {
	fs := flag.NewFlagSet("url", flag.ExitOnError)
	targets := stringList{}
	fs.Var(&targets, "u", "target url, repeatable (http://target/index.php)")
	timeout := fs.Duration("timeout", 20*time.Second, "http timeout")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	probe := fs.Bool("probe", true, "send the session.upload_progress arming probe")
	canary := fs.Bool("canary", false, "arming probe carries an inert PHP comment (lets Suricata/YARA rules fire)")
	crawl := fs.Bool("crawl", true, "look for exposed phpinfo pages")
	ua := fs.String("user-agent", "php2shell-scanner/1.0", "user agent header")
	workers := fs.Int("concurrency", 5, "targets to scan in parallel")
	paths := stringList{}
	fs.Var(&paths, "path", "extra path to probe, repeatable")
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	failOn := fs.String("fail-on", "high", "exit non-zero at this severity or worse (critical, high, medium, low, info, none)")
	fs.Parse(args)

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "url: -u <url> is required")
		return 2
	}
	severity, ok := report.ParseSeverity(*failOn)
	if !ok && *failOn != "none" {
		fmt.Fprintf(os.Stderr, "url: unknown severity %q\n", *failOn)
		return 2
	}

	ctx := context.Background()
	opts := blackbox.Options{
		Timeout:   *timeout,
		Insecure:  *insecure,
		UserAgent: *ua,
		Probe:     *probe,
		Canary:    *canary,
		Crawl:     *crawl,
		Paths:     paths,
	}
	reports := parallel(len(targets), *workers, func(i int) report.Report {
		o := opts
		o.URL = targets[i]
		findings, meta, err := blackbox.Scan(ctx, o)
		rep := report.Report{Mode: "blackbox", Time: time.Now()}
		if err != nil {
			rep.Target = targets[i]
			rep.Findings = []report.Finding{{
				ID:       "SCAN_FAILED",
				Severity: report.High,
				Title:    "Scan failed",
				Detail:   err.Error(),
			}}
			return rep
		}
		rep.Target = meta["target"]
		rep.Findings = findings
		rep.Meta = meta
		return rep
	})
	return emit(reports, *jsonOut, severity, *failOn == "none")
}

func runLocal(args []string) int {
	fs := flag.NewFlagSet("local", flag.ExitOnError)
	webroot := fs.String("webroot", "", "extra document root to scan (the web server document roots are detected automatically)")
	timeout := fs.Duration("timeout", 90*time.Second, "per command timeout")
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	failOn := fs.String("fail-on", "high", "exit non-zero at this severity or worse (critical, high, medium, low, info, none)")
	fs.Parse(args)

	severity, ok := report.ParseSeverity(*failOn)
	if !ok && *failOn != "none" {
		fmt.Fprintf(os.Stderr, "local: unknown severity %q\n", *failOn)
		return 2
	}

	prober := &hostcheck.LocalProber{Timeout: *timeout}
	findings, meta, err := hostcheck.Scan(context.Background(), prober, hostcheck.Options{Webroot: *webroot, Timeout: *timeout})
	rep := report.Report{Target: "local", Mode: "host", Time: time.Now(), Findings: findings, Meta: meta}
	if err != nil {
		rep.Findings = append(rep.Findings, report.Finding{
			ID:       "SCAN_FAILED",
			Severity: report.High,
			Title:    "Scan failed",
			Detail:   err.Error(),
		})
	}
	return emit([]report.Report{rep}, *jsonOut, severity, *failOn == "none")
}

func runSSH(args []string) int {
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	hosts := stringList{}
	fs.Var(&hosts, "H", "host to scan, repeatable (host, host:port or user@host:port)")
	port := fs.Int("p", 22, "default ssh port")
	user := fs.String("U", os.Getenv("USER"), "ssh user")
	password := fs.String("password", os.Getenv("SSH_PASSWORD"), "ssh password (or set SSH_PASSWORD)")
	passphrase := fs.String("passphrase", "", "passphrase of the private key")
	knownHosts := fs.String("known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	insecureHostKey := fs.Bool("insecure-host-key", false, "do not verify the host key")
	useAgent := fs.Bool("agent", false, "use the ssh agent from SSH_AUTH_SOCK")
	webroot := fs.String("webroot", "", "extra document root to scan (the web server document roots are detected automatically)")
	timeout := fs.Duration("timeout", 90*time.Second, "per command timeout")
	workers := fs.Int("concurrency", 5, "hosts to scan in parallel")
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	failOn := fs.String("fail-on", "high", "exit non-zero at this severity or worse (critical, high, medium, low, info, none)")
	identities := stringList{}
	fs.Var(&identities, "i", "private key file, repeatable")
	fs.Parse(args)

	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "ssh: -H <host> is required")
		return 2
	}
	severity, ok := report.ParseSeverity(*failOn)
	if !ok && *failOn != "none" {
		fmt.Fprintf(os.Stderr, "ssh: unknown severity %q\n", *failOn)
		return 2
	}

	targets := parseSSHTargets(hosts, *user, *port)
	reports := parallel(len(targets), *workers, func(i int) report.Report {
		t := targets[i]
		rep := report.Report{Target: t.addr, Mode: "host/ssh", Time: time.Now()}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout*6)
		defer cancel()

		prober, err := hostcheck.Dial(ctx, hostcheck.SSHOptions{
			Host:            t.host,
			Port:            t.port,
			User:            t.user,
			Password:        *password,
			Passphrase:      *passphrase,
			IdentityFiles:   identities,
			UseAgent:        *useAgent,
			KnownHosts:      *knownHosts,
			InsecureHostKey: *insecureHostKey,
			Timeout:         *timeout,
		})
		if err != nil {
			rep.Findings = []report.Finding{{
				ID:       "SSH_CONNECT_FAILED",
				Severity: report.High,
				Title:    "SSH connection failed",
				Detail:   err.Error(),
			}}
			return rep
		}
		defer prober.Close()

		findings, meta, err := hostcheck.Scan(ctx, prober, hostcheck.Options{Webroot: *webroot, Timeout: *timeout})
		rep.Findings = findings
		rep.Meta = meta
		if err != nil {
			rep.Findings = append(rep.Findings, report.Finding{
				ID:       "SCAN_FAILED",
				Severity: report.High,
				Title:    "Scan failed",
				Detail:   err.Error(),
			})
		}
		return rep
	})
	return emit(reports, *jsonOut, severity, *failOn == "none")
}

// sshTarget is one host to scan.
type sshTarget struct {
	host string
	port int
	user string
	addr string
}

// parseSSHTargets accepts host, host:port and user@host:port.
func parseSSHTargets(in []string, defaultUser string, defaultPort int) []sshTarget {
	var out []sshTarget
	for _, raw := range in {
		t := sshTarget{user: defaultUser, port: defaultPort}
		host := strings.TrimSpace(raw)
		if u, h, ok := strings.Cut(host, "@"); ok {
			t.user = u
			host = h
		}
		if h, p, err := splitHostPort(host); err == nil {
			t.host = h
			t.port = p
		} else {
			t.host = host
		}
		t.addr = fmt.Sprintf("%s@%s:%d", t.user, t.host, t.port)
		out = append(out, t)
	}
	return out
}

// splitHostPort splits host:port, keeping bare IPv6 addresses intact.
func splitHostPort(host string) (string, int, error) {
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host, 0, fmt.Errorf("no port")
	}
	port, err := strconv.Atoi(host[idx+1:])
	if err != nil {
		return host, 0, err
	}
	return host[:idx], port, nil
}

// parallel runs fn over the indexes with a bounded worker pool and keeps the
// results in the original order.
func parallel(n, workers int, fn func(i int) report.Report) []report.Report {
	if workers < 1 {
		workers = 1
	}
	if workers > n {
		workers = n
	}
	out := make([]report.Report, n)
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = fn(i)
			}
		}()
	}
	for i := range n {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

// emit prints the report and returns the process exit code.
func emit(reports []report.Report, jsonOut bool, failOn report.Severity, neverFail bool) int {
	for i := range reports {
		reports[i].Sort()
		reports[i].Summary = reports[i].Counts()
	}
	bundle := report.NewBundle(reports)
	if jsonOut {
		if err := bundle.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			return 2
		}
	} else {
		bundle.WriteText(os.Stdout)
	}
	if neverFail {
		return 0
	}
	worst := bundle.Worst()
	if worst != "" && report.Rank(worst) <= report.Rank(failOn) {
		return 1
	}
	return 0
}
