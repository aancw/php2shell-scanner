package hostcheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHOptions configures the SSH connection.
type SSHOptions struct {
	Host            string
	Port            int
	User            string
	Password        string
	Passphrase      string
	IdentityFiles   []string
	UseAgent        bool
	KnownHosts      string
	InsecureHostKey bool
	Timeout         time.Duration
}

// SSHProber runs the checks on a remote host over SSH.
type SSHProber struct {
	client  *ssh.Client
	addr    string
	timeout time.Duration
}

// Target names the scanned host.
func (p *SSHProber) Target() string { return p.addr }

// Close releases the connection.
func (p *SSHProber) Close() error {
	if p.client == nil {
		return nil
	}
	return p.client.Close()
}

// Dial opens an SSH connection to the target host.
func Dial(ctx context.Context, opts SSHOptions) (*SSHProber, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("no ssh host given")
	}
	if opts.User == "" {
		opts.User = os.Getenv("USER")
	}
	if opts.Port == 0 {
		opts.Port = 22
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	auth, err := authMethods(opts)
	if err != nil {
		return nil, err
	}
	hostKey, err := hostKeyCallback(opts)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         opts.Timeout,
	}
	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return &SSHProber{client: ssh.NewClient(c, chans, reqs), addr: addr, timeout: opts.Timeout}, nil
}

// Run executes the script in a remote shell and returns its combined output.
func (p *SSHProber) Run(ctx context.Context, script string) (string, error) {
	timeout := p.timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	session, err := p.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Start("sh -c " + shellQuote(script)); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-cctx.Done():
		session.Close()
		return stdout.String() + stderr.String(), cctx.Err()
	case err := <-done:
		return stdout.String() + stderr.String(), err
	}
}

func authMethods(opts SSHOptions) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	for _, file := range opts.IdentityFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read identity %s: %w", file, err)
		}
		signer, err := parseKey(data, opts.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", file, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if opts.UseAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			conn, err := net.Dial("unix", sock)
			if err != nil {
				return nil, fmt.Errorf("ssh agent socket %s: %w", sock, err)
			}
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if opts.Password != "" {
		methods = append(methods, ssh.Password(opts.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no ssh authentication method: pass --ssh-identity, --ssh-password or enable --ssh-agent")
	}
	return methods, nil
}

func parseKey(data []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
		if err == nil {
			return signer, nil
		}
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil
	}
	raw, rawErr := ssh.ParseRawPrivateKey(data)
	if rawErr != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(raw)
}

func hostKeyCallback(opts SSHOptions) (ssh.HostKeyCallback, error) {
	if opts.InsecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := opts.KnownHosts
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("locate home directory: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("known_hosts %s: %w (use --ssh-insecure-host-key to skip host key checks)", path, err)
	}
	return cb, nil
}

// shellQuote wraps a script so the remote shell runs it verbatim.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
