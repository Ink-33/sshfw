package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type secretStore interface {
	Get(service, user string) (string, error)
}

type osKeyring struct{}

func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }

type proxyConfig struct {
	Name                                           string
	Listen, Upstream, KeysDir, HostKey, KnownHosts string
}

type proxy struct {
	config            proxyConfig
	serverConfig      *ssh.ServerConfig
	clientHostKey     ssh.HostKeyCallback
	clientHostKeyAlgs []string
	store             secretStore
}

var userPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

func validUser(user string) bool { return userPattern.MatchString(user) }

func newProxy(config proxyConfig, store secretStore) (*proxy, error) {
	if err := validateListen(config.Listen); err != nil {
		return nil, err
	}
	if _, err := normalizeAddress(config.Upstream); err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	if store == nil {
		return nil, errors.New("secret store is required")
	}
	if info, err := os.Stat(config.KeysDir); err != nil || !info.IsDir() {
		return nil, errors.New("authorized keys directory is unavailable")
	}
	info, err := os.Stat(config.HostKey)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("host key must not be readable by group or others")
	}
	private, err := os.ReadFile(config.HostKey)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(private)
	clear(private)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("host key must be Ed25519")
	}
	hostCallback, err := knownhosts.New(config.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}
	hostAlgos, err := hostKeyAlgorithms(config.KnownHosts, config.Upstream)
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}
	p := &proxy{config: config, clientHostKey: hostCallback, clientHostKeyAlgs: hostAlgos, store: store}
	p.serverConfig = &ssh.ServerConfig{
		MaxAuthTries: 3,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !validUser(meta.User()) {
				return nil, errors.New("invalid username")
			}
			allowed, err := authorizedKey(config.KeysDir, meta.User(), key)
			if err != nil || !allowed {
				return nil, errors.New("public key not authorized")
			}
			return nil, nil
		},
	}
	p.serverConfig.AddHostKey(signer)
	return p, nil
}

func authorizedKey(root, user string, offered ssh.PublicKey) (bool, error) {
	if !validUser(user) {
		return false, errors.New("invalid username")
	}
	data, err := os.ReadFile(filepath.Join(root, user, "authorized_keys"))
	if err != nil {
		return false, err
	}
	for len(data) > 0 {
		line, rest, found := bytes.Cut(data, []byte{'\n'})
		if found {
			data = rest
		} else {
			data = nil
		}
		key, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err == nil && len(options) == 0 && bytes.Equal(key.Marshal(), offered.Marshal()) {
			return true, nil
		}
	}
	return false, nil
}

func (p *proxy) serve(logger *log.Logger) error {
	listener, err := net.Listen("tcp", p.config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	logger.Printf("listening on %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := p.handle(conn); err != nil {
				logger.Printf("connection ended: %v", err)
			}
		}()
	}
}

// stdioConn adapts process stdin/stdout to net.Conn for ProxyCommand mode.
type stdioConn struct {
	io.Reader
	io.Writer
}

func (stdioConn) Close() error                     { return nil }
func (stdioConn) LocalAddr() net.Addr              { return stdioAddr("local") }
func (stdioConn) RemoteAddr() net.Addr             { return stdioAddr("remote") }
func (stdioConn) SetDeadline(time.Time) error      { return nil }
func (stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (stdioConn) SetWriteDeadline(time.Time) error { return nil }

type stdioAddr string

func (a stdioAddr) Network() string { return "stdio" }
func (a stdioAddr) String() string  { return string(a) }

func (p *proxy) serveStdio(logger *log.Logger) error {
	conn := stdioConn{Reader: os.Stdin, Writer: os.Stdout}
	err := p.handle(conn)
	if err != nil {
		logger.Printf("connection ended: %v", err)
	}
	return err
}

func (p *proxy) handle(localNet net.Conn) error {
	defer localNet.Close()
	_ = localNet.SetDeadline(time.Now().Add(20 * time.Second))
	local, localChannels, localRequests, err := ssh.NewServerConn(localNet, p.serverConfig)
	if err != nil {
		return fmt.Errorf("local handshake: %w", err)
	}
	defer local.Close()
	_ = localNet.SetDeadline(time.Time{})
	password, err := p.store.Get(credentialService(p.config.Upstream), local.User())
	if err != nil {
		return fmt.Errorf("remote credential for %q unavailable: %w", local.User(), err)
	}
	if password == "" {
		return errors.New("remote credential is empty")
	}
	upstreamNet, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", p.config.Upstream)
	if err != nil {
		return fmt.Errorf("upstream dial: %w", err)
	}
	defer upstreamNet.Close()
	_ = upstreamNet.SetDeadline(time.Now().Add(20 * time.Second))
	remote, remoteChannels, remoteRequests, err := ssh.NewClientConn(upstreamNet, p.config.Upstream, &ssh.ClientConfig{
		User: local.User(), Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: p.clientHostKey, HostKeyAlgorithms: p.clientHostKeyAlgs,
		Timeout: 10 * time.Second,
	})
	password = ""
	if err != nil {
		return fmt.Errorf("upstream handshake: %w", err)
	}
	defer remote.Close()
	_ = upstreamNet.SetDeadline(time.Time{})
	go forwardRequests(localRequests, remote)
	go forwardRequests(remoteRequests, local)
	go forwardChannels(localChannels, remote)
	go forwardChannels(remoteChannels, local)
	remoteDone := make(chan error, 1)
	go func() { remoteDone <- remote.Wait() }()
	localDone := make(chan error, 1)
	go func() { localDone <- local.Wait() }()
	select {
	case err := <-remoteDone:
		return err
	case err := <-localDone:
		return err
	}
}

func forwardRequests(in <-chan *ssh.Request, out ssh.Conn) {
	for req := range in {
		ok, payload, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(err == nil && ok, payload)
		}
		if err != nil {
			return
		}
	}
}

func forwardChannels(in <-chan ssh.NewChannel, out ssh.Conn) {
	for incoming := range in {
		go forwardChannel(incoming, out)
	}
}

func forwardChannel(incoming ssh.NewChannel, out ssh.Conn) {
	other, otherReqs, err := out.OpenChannel(incoming.ChannelType(), incoming.ExtraData())
	if err != nil {
		var rejected *ssh.OpenChannelError
		if errors.As(err, &rejected) {
			_ = incoming.Reject(rejected.Reason, rejected.Message)
		} else {
			_ = incoming.Reject(ssh.ConnectionFailed, "upstream channel unavailable")
		}
		return
	}
	current, currentReqs, err := incoming.Accept()
	if err != nil {
		_ = other.Close()
		return
	}
	currentRequestsDone := make(chan struct{})
	otherRequestsDone := make(chan struct{})
	go func() { forwardChannelRequests(currentReqs, other); close(currentRequestsDone) }()
	go func() { forwardChannelRequests(otherReqs, current); close(otherRequestsDone) }()

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = current.Close()
			_ = other.Close()
		})
	}

	// Local -> upstream. If the remote shell has already exited this may block
	// on a local Read; the upstream->local path closes both sides to unblock it.
	go func() {
		copyChannel(other, current)
		_ = other.CloseWrite()
	}()
	// Upstream -> local. Data EOF happens first after logout; EXIT_STATUS may
	// still follow, so relay requests briefly, then tear down so the session
	// cannot hang with the local client waiting forever.
	go func() {
		copyChannel(current, other)
		select {
		case <-otherRequestsDone:
		case <-currentRequestsDone:
		case <-time.After(5 * time.Second):
		}
		closeBoth()
	}()
}

func forwardChannelRequests(in <-chan *ssh.Request, out ssh.Channel) {
	for req := range in {
		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(err == nil && ok, nil)
		}
		if err != nil {
			return
		}
	}
}

func copyChannel(dst, src ssh.Channel) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst.Stderr(), src.Stderr())
	}()
	wg.Wait()
	_ = dst.CloseWrite()
}
