# php2shell-scanner

Detects exposure to the PHP core RCEs **CVE-2026-109618** and **CVE-2026-109619**
("PHP2Shell", published 2026-10-21) in three modes:

| mode | what it does |
|------|--------------|
| `url` | blackbox scan of a web target over HTTP, no shell access needed |
| `local` | host checks on the machine the scanner runs on |
| `ssh`  | the same host checks on a remote host over SSH |

The scanner is a detector, not an exploit. The only request it sends is a benign
`session.upload_progress` arming probe that contains no PHP code unless you ask
for the inert canary with `--canary`.

**Authorized use only.** Run this against systems you own or have prior written
permission to test. It is provided with no warranty and no liability for
damages. Read [Disclaimer and responsibility](#disclaimer-and-responsibility)
before you use it.

## Install

Download the binary for your platform from the
[releases page](https://github.com/aancw/php2shell-scanner/releases/latest):

| platform | asset |
|----------|-------|
| linux x86_64 | `php2shell-scanner-linux-amd64.tar.gz` |
| linux arm64 | `php2shell-scanner-linux-arm64.tar.gz` |
| linux armv6 | `php2shell-scanner-linux-arm.tar.gz` |
| macOS intel | `php2shell-scanner-darwin-amd64.tar.gz` |
| macOS apple silicon | `php2shell-scanner-darwin-arm64.tar.gz` |
| windows x86_64 | `php2shell-scanner-windows-amd64.exe` |

```bash
curl -fsSLO https://github.com/aancw/php2shell-scanner/releases/latest/download/php2shell-scanner-linux-amd64.tar.gz
curl -fsSLO https://github.com/aancw/php2shell-scanner/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS

tar -xzf php2shell-scanner-linux-amd64.tar.gz
sudo install php2shell-scanner /usr/local/bin/
```

The binaries are statically linked, so there is nothing to install besides the
file itself.

## Usage

```bash
# blackbox
php2shell-scanner url -u http://target/index.php
php2shell-scanner url -u https://target/ --json --fail-on critical

# this machine
php2shell-scanner local
php2shell-scanner local --webroot /var/www/html

# remote host over ssh
php2shell-scanner ssh -H 10.0.0.5 -U deploy -i ~/.ssh/id_ed25519
php2shell-scanner ssh -H 10.0.0.5 -U deploy --agent --webroot /srv/www
```

### Scanning many hosts

`url` and `ssh` take repeatable targets. They are scanned in parallel
(`--concurrency`, default 5) and the results come back per target.

```bash
php2shell-scanner url -u http://a/ -u http://b/ -u http://c/

php2shell-scanner ssh -H web1 -H web2 -H deploy@web3:2222
```

A host can be `host`, `host:port` or `user@host:port`. The port from `-H` wins
over `-p`. `local` stays single target, it is the machine the scanner runs on.

A target that cannot be reached does not stop the run: it gets a
`SCAN_FAILED` or `SSH_CONNECT_FAILED` finding and the other targets are still
scanned.

### Password authentication for SSH

```bash
php2shell-scanner ssh -H web1 -U deploy --password 'secret'
SSH_PASSWORD='secret' php2shell-scanner ssh -H web1 -U deploy
```

The same credentials are used for every host in the run. Keys, the agent
(`--agent`) and the password can be combined; the server decides what it
accepts.

Useful flags:

| flag | modes | meaning |
|------|-------|---------|
| `--json` | all | print the report as JSON |
| `--fail-on <severity>` | all | exit 1 at this severity or worse (default `high`, `none` disables) |
| `--webroot <dir>` | local, ssh | extra document root to scan; the document roots of the web server configuration are detected automatically |
| `--probe` / `--canary` | url | arming probe on by default; `--canary` adds an inert PHP comment so Suricata/YARA rules fire |
| `--crawl` | url | look for exposed phpinfo pages (on by default) |
| `--insecure` | url | skip TLS verification |
| `--path` | url | extra endpoint to probe, repeatable |
| `--agent`, `--password`, `--passphrase`, `--known-hosts`, `--insecure-host-key` | ssh | authentication and host key handling |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or runtime error.

## What is checked

### Version (all modes)

| branch | fixed in | last vulnerable |
|--------|----------|-----------------|
| 8.5 | 8.5.12 | 8.5.11 |
| 8.4 | 8.4.27 | 8.4.26 |
| 8.3 | 8.3.36 | 8.3.35 |
| 8.2 | 8.2.35 | 8.2.34 |
| ≤ 8.1 | EOL, no routine updates (7.4/8.0/8.1 backports exist) | treated as affected |

A build below the fix of its branch is reported as **critical**; 8.1 and older are
reported as **critical** end-of-life branches that need a vendor package or the
source backports.

### Blackbox (`url`)

* PHP version from `X-Powered-By`, the `Server` header, the body, or an exposed
  phpinfo page (found with the `?=PHPB8B5F2A0-...` easter egg).
* SAPI: `Apache 2.0 Handler` means mod_php, which is the worst case for
  CVE-2026-109618 because request cleanup runs even when startup failed, so the
  exploit lands before any application code and application-level authentication
  cannot stop it.
* phpinfo values that decide exploitability: `session.upload_progress.enabled`,
  `memory_limit`, `fatal_error_backtraces` (8.5), `session.use_only_cookies`,
  `session.serialize_handler`.
* Arming probe: one multipart POST with a `PHPSESSID` field and a
  `PHP_SESSION_UPLOAD_PROGRESS` field and no cookie. That is the request shape
  the Suricata rules in [php2shell-lab](https://github.com/mikensec/php2shell-lab)
  key on, so the probe doubles as a correlation point. The probe never contains
  a PHP open tag unless `--canary` is given.

The OOM corruption path is **not** probed: proving it means exhausting the
target's memory, which is a denial of service. The scanner reports the
configuration that makes the path reachable instead.

### Host (`local`, `ssh`)

* PHP interpreters and versions (`php`, `php8.x`, `php-fpm`), plus the SAPI in
  use: mod_php module present, php-fpm processes, web server processes.
* `session.upload_progress.enabled`, `memory_limit`, `fatal_error_backtraces`,
  `session.serialize_handler`, `session.use_only_cookies` from the interpreter
  **and** from the ini files, FPM pools and web server configuration on disk.
  The CLI ini is not the web ini, so both are read.
* `session.upload_progress.enabled=0` is only a mitigation when it is set in the
  configuration that applies before request parsing; a `.user.ini` value is
  reported as too late.
* `session.serialize_handler` mismatch between files that share one
  `session.save_path` (the configuration half of the session primitive).
* Session directory scan for artefacts of the content injection: a `sess_*`
  file that carries `upload_progress_` next to a PHP open tag is **critical**
  (poisoned session file), a bare marker is an attempt indicator, and an
  aborted serialization is the write-denial primitive.
* Document root scan for artefacts of the content injection and for PHP
  configuration. The roots come from the `DocumentRoot` and `root` directives of
  the Apache and Nginx configuration; `--webroot` adds one more. Files carrying
  the `upload_progress_` marker are reported, and `.htaccess`/`*.ini` files are
  read for the same directives as the system configuration.
* `session.upload_progress.cleanup` decides whether an arming attempt leaves a
  file behind: with cleanup off the progress entry stays in the session file,
  with cleanup on it is removed when the request ends and a later session
  directory scan misses it.
* Post-exploitation tell: a PHP or web server process with a shell as child.

## Verification against the lab

The scanner was verified against the offline lab in
[mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab) and against
a plain `php:8.3.35-apache` container.

### Running the local mode inside a container

`local` scans the machine it runs on, so point it at a container by putting the
binary in it. Build on the host, copy, run:

```bash
# 1. build for linux (native arch of this host)
mkdir -p dist
GOOS=linux go build -o dist/p2s .

# 2. copy it in
C=php2shell-target
docker cp dist/p2s $C:/usr/local/bin/p2s

# 3. run it
docker exec $C /usr/local/bin/p2s local
```

For a container with the other architecture:

```bash
GOOS=linux GOARCH=amd64 go build -o dist/p2s-amd64 .   # x86_64 container
GOOS=linux GOARCH=arm64 go build -o dist/p2s-arm64 .   # aarch64 container
```

Copy to `/usr/local/bin`, not `/tmp`: the lab victim mounts `/tmp` as tmpfs, so
a file copied there disappears. Add `--webroot` only when the document root is
not in the web server configuration.

### The lab victim

```bash
# in the lab: make the victim vulnerable (the lab defaults to a floating tag)
cp .env.example .env         # pins PHP_TAG=8.3.35-apache
./lab.sh up
./lab.sh version             # -> [VULNERABLE] 8.3.35 < 8.3.36

# blackbox against the victim
php2shell-scanner url -u http://<target-ip>/index.php
```

`lab/` holds a throwaway SSH target (PHP 8.3.35 with an SSH server) so the `ssh`
mode can be tested without touching a real host:

```bash
cd lab
ssh-keygen -t ed25519 -f ./id_ed25519 -N ''
cp ./id_ed25519.pub ./authorized_keys
docker compose up -d --build
ssh-keyscan -p 2222 127.0.0.1 >> ./known_hosts

../php2shell-scanner ssh -H 127.0.0.1 -p 2222 -U root \
  -i ./id_ed25519 --known-hosts ./known_hosts --webroot /var/www/html
```

The blackbox arming probe and the host-side session scan are two halves of the
same check: the probe writes a `sess_<injected id>` file into the session
directory, and the host scan finds it. With `--canary` the marker contains an
inert `<?php /* ... */ ?>` comment, which is what makes the Suricata rule
`30260002` and the YARA rule `PHP_UploadProgress_Session_Poison` match.

## Notes

* The lab pins `PHP_TAG=8.3.35-apache` in `.env`. Without that pin the compose
  file resolves a floating tag, which is already patched (8.3.36) and reports
  as **patched**.
* `session.upload_progress.enabled=0` closes the confirmed session paths only.
  `memory_limit=-1` removes the predictable memory-limit failure for the OOM
  path. Neither is a substitute for the patch.
* The version table is the one from the PHP advisories of 2026-10-21. Confirm
  the range against php.net before acting on an end-of-life branch.

## Disclaimer and responsibility

This tool is for authorized security testing only. Running it against a system
without the owner's prior written permission can be an offence under computer
misuse and unauthorized access laws, and knowing which of them apply is your
responsibility. Own the target or hold a signed scope, statement of work or
equivalent authorization that covers exactly these checks, and stay inside it.

* **A detector, not an exploit.** There is no exploit payload, no code execution
  primitive and no post-exploitation action. The tool fingerprints versions and
  configuration and, unless the probe is disabled, sends one benign
  `session.upload_progress` request. The OOM corruption path is deliberately
  never probed.
* **It still changes target state.** The `url` probe runs against every target,
  not only vulnerable ones: on any host with `session.upload_progress.enabled`
  and `session.upload_progress.cleanup` off it can leave a `sess_*` entry
  behind, patched or not, and its POST shows up in access logs and can trip IDS
  rules. `local` and `ssh` mode read files, ini values and session directories
  with the privileges you hand them, so paths, configuration and any credentials
  stored in those files end up in the report.
* **Heuristics, not proof.** Findings can be false positive or false negative.
  Confirm a critical result by hand before you patch, act on or disclose it.
* **No warranty.** The tool is provided "as is", without warranty of any kind,
  express or implied, including merchantability, fitness for a particular
  purpose and non-infringement.
* **No liability.** The authors and contributors are not liable for any claim,
  damage or other liability — service disruption, denial of service, data loss,
  legal action, regulatory penalty — arising from the use or misuse of this
  tool, even if advised of the possibility.
* **Handle reports as sensitive.** They carry hostnames, versions, file paths
  and configuration detail from the scanned environment; treat them with the
  same care as the target's own vulnerability data.
* **Independent tool.** Not endorsed by, affiliated with or maintained by the
  PHP Group, or by any vendor, distribution or hosting provider named above.
  All product and project names belong to their respective owners.

## Development

```bash
go build -o php2shell-scanner .
go vet ./...
go test ./...
```

Go 1.27+. One dependency: `golang.org/x/crypto/ssh` (SSH transport only).

`.github/workflows/release.yml` builds the release binaries. It runs when a
release is published, and it can also be started by hand with
`workflow_dispatch` and a tag, in which case it creates the release when it
does not exist yet.

## Credits
- [mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab)
