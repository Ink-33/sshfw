package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type testSecrets map[string]string

func (s testSecrets) Get(_, user string) (string, error) {
	if value, ok := s[user]; ok {
		return value, nil
	}
	return "", errors.New("missing secret")
}

func testSigner(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

type testUpstream struct {
	addr      string
	signer    ssh.Signer
	close     func()
	forwarded chan ssh.Channel
}

func startUpstream(t *testing.T) *testUpstream {
	t.Helper()
	signer, _ := testSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &testUpstream{addr: listener.Addr().String(), signer: signer, close: func() { _ = listener.Close() }, forwarded: make(chan ssh.Channel, 1)}
	config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if meta.User() == "alice" && string(pass) == "secret" {
			return nil, nil
		}
		return nil, errors.New("bad password")
	}}
	config.AddHostKey(signer)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go func() {
					for req := range requests {
						if req.Type == "tcpip-forward" {
							_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{42424}))
							go func() {
								time.Sleep(50 * time.Millisecond)
								payload := ssh.Marshal(struct {
									Addr       string
									Port       uint32
									OriginAddr string
									OriginPort uint32
								}{"127.0.0.1", 42424, "127.0.0.1", 12345})
								ch, replies, err := server.OpenChannel("forwarded-tcpip", payload)
								if err == nil {
									go ssh.DiscardRequests(replies)
									u.forwarded <- ch
								}
							}()
						} else {
							_ = req.Reply(true, []byte("ok"))
						}
					}
				}()
				for incoming := range channels {
					go func() {
						ch, reqs, err := incoming.Accept()
						if err != nil {
							return
						}
						defer ch.Close()
						if incoming.ChannelType() == "direct-tcpip" {
							go ssh.DiscardRequests(reqs)
							_, _ = io.Copy(ch, ch)
							return
						}
						for req := range reqs {
							switch req.Type {
							case "exec":
								_ = req.Reply(true, nil)
								_, _ = ch.Write([]byte("output"))
								_, _ = ch.Stderr().Write([]byte("warning"))
								_ = ch.CloseWrite()
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
								return
							case "subsystem", "shell":
								_ = req.Reply(true, nil)
								_, _ = io.Copy(ch, ch)
								return
							default:
								_ = req.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(u.close)
	return u
}

type testProxy struct {
	addr         string
	close        func()
	knownHosts   string
	keysDir      string
	clientSigner ssh.Signer
	upstream     *testUpstream
}

func startProxy(t *testing.T, secrets testSecrets, trustUpstream bool) *testProxy {
	t.Helper()
	u := startUpstream(t)
	dir := t.TempDir()
	clientSigner, _ := testSigner(t)
	_, hostKeyPEM := testSigner(t)
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(filepath.Join(keysDir, "alice"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "alice", "authorized_keys"), ssh.MarshalAuthorizedKey(clientSigner.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(dir, "host_key")
	if err := os.WriteFile(hostKey, hostKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	trusted := u.signer
	if !trustUpstream {
		trusted, _ = testSigner(t)
	}
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{u.addr}, trusted.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p, err := newProxy(proxyConfig{Listen: listener.Addr().String(), Upstream: u.addr, KeysDir: keysDir, HostKey: hostKey, KnownHosts: knownHosts}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = p.handle(conn) }()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return &testProxy{addr: listener.Addr().String(), close: func() { _ = listener.Close() }, knownHosts: knownHosts, keysDir: keysDir, clientSigner: clientSigner, upstream: u}
}

func (p *testProxy) dial(user string) (*ssh.Client, error) {
	return ssh.Dial("tcp", p.addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(p.clientSigner)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
}

func TestAuthorizationAndValidation(t *testing.T) {
	p := startProxy(t, testSecrets{"alice": "secret"}, true)
	client, err := p.dial("alice")
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if _, err := p.dial("bob"); err == nil {
		t.Fatal("alice's key authorized bob")
	}
	stranger, _ := testSigner(t)
	if client, err := ssh.Dial("tcp", p.addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(stranger)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second,
	}); err == nil {
		_ = client.Close()
		t.Fatal("unlisted key authorized")
	}
	if _, err := p.dial("../alice"); err == nil {
		t.Fatal("unsafe username accepted")
	}
	if err := validateListen("0.0.0.0:2222"); err == nil {
		t.Fatal("non-loopback listener accepted")
	}
}

func TestSessionAndDirectForward(t *testing.T) {
	p := startProxy(t, testSecrets{"alice": "secret"}, true)
	client, err := p.dial("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	session.Stdout, session.Stderr = &stdout, &stderr
	err = session.Run("anything")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
		t.Fatalf("exit status: %v", err)
	}
	if stdout.String() != "output" || stderr.String() != "warning" {
		t.Fatalf("streams: %q / %q", stdout.String(), stderr.String())
	}
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil || !ok {
		t.Fatalf("subsystem: %v %v", ok, err)
	}
	if _, err := channel.Write([]byte("sftp")); err != nil {
		t.Fatal(err)
	}
	check := make([]byte, 4)
	if _, err := io.ReadFull(channel, check); err != nil || string(check) != "sftp" {
		t.Fatalf("subsystem data: %q, %v", check, err)
	}
	shell, shellReqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()
	go ssh.DiscardRequests(shellReqs)
	ok, err = shell.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: %v %v", ok, err)
	}
	if _, err := shell.Write([]byte("shell")); err != nil {
		t.Fatal(err)
	}
	shellEcho := make([]byte, 5)
	if _, err := io.ReadFull(shell, shellEcho); err != nil || string(shellEcho) != "shell" {
		t.Fatalf("shell data: %q, %v", shellEcho, err)
	}
	conn, err := client.Dial("tcp", "example.com:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("direct forwarding: %q, %v", buf, err)
	}
}

func TestReverseForwardAndGlobalRequest(t *testing.T) {
	p := startProxy(t, testSecrets{"alice": "secret"}, true)
	client, err := p.dial("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ok, data, err := client.SendRequest("test-global", true, nil)
	if err != nil || !ok || string(data) != "ok" {
		t.Fatalf("global request: %v %v %q", ok, err, data)
	}
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("reply"))
			_ = conn.Close()
		}
	}()
	select {
	case ch := <-p.upstream.forwarded:
		defer ch.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(ch, buf); err != nil || string(buf) != "reply" {
			t.Fatalf("reverse forwarding: %q, %v", buf, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reverse forwarding timed out")
	}
	wg.Wait()
}

func TestUpstreamHostKeyAndCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secrets testSecrets
		trust   bool
	}{
		{"missing credential", testSecrets{}, true},
		{"wrong password", testSecrets{"alice": "incorrect"}, true},
		{"wrong host key", testSecrets{"alice": "secret"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := startProxy(t, tc.secrets, tc.trust)
			client, err := p.dial("alice")
			if err != nil {
				return
			}
			defer client.Close()
			_, err = client.NewSession()
			if err == nil {
				t.Fatal("upstream failure was not propagated")
			}
		})
	}
}

func TestNormalizeAddress(t *testing.T) {
	if got, err := normalizeAddress("EXAMPLE.COM:0022"); err != nil || got != "example.com:22" {
		t.Fatalf("%q, %v", got, err)
	}
	for _, bad := range []string{"", "host", "host:0", "host:65536", "host:x"} {
		if _, err := normalizeAddress(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if credentialService("example.com:22") != "sshfw:example.com:22" {
		t.Fatal("credential namespace changed")
	}
}
