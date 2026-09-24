package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestEnsureHostKeyGeneratesAndReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshfw_host_key")
	signer, err := ensureHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type: %s", signer.PublicKey().Type())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OPENSSH PRIVATE KEY") {
		t.Fatalf("host key is not OpenSSH format: %s", data[:min(40, len(data))])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("host key permissions: %v", info.Mode().Perm())
	}
	signer2, err := ensureHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), signer2.PublicKey().Marshal()) {
		t.Fatal("host key was regenerated")
	}
}

func TestDiscoverUsers(t *testing.T) {
	dir := t.TempDir()
	mk := func(user, body string) {
		path := filepath.Join(dir, user)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			if err := os.WriteFile(filepath.Join(path, "authorized_keys"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("alice", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlice alice@test\n")
	mk("bob", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBob bob@test\n")
	mk("bad user!", "x")
	mk("carol", "")
	users, err := discoverUsers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0] != "alice" || users[1] != "bob" {
		t.Fatalf("users: %v", users)
	}
}

func TestFindIdentityFile(t *testing.T) {
	keysDir := t.TempDir()
	sshDir := t.TempDir()
	user := "alice"
	if err := os.MkdirAll(filepath.Join(keysDir, user), 0700); err != nil {
		t.Fatal(err)
	}
	signer, priv := testSigner(t)
	pub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther other@test\n"
	if err := os.WriteFile(filepath.Join(keysDir, user, "authorized_keys"), []byte(other+"\n"+pub), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), priv, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	got := findIdentityFile(keysDir, user, sshDir)
	want := filepath.Join(sshDir, "id_ed25519")
	if got != want {
		t.Fatalf("identity=%q want %q", got, want)
	}
	if got := findIdentityFile(keysDir, "nobody", sshDir); got != "" {
		t.Fatalf("unknown user identity=%q", got)
	}
}

func TestBuildSSHConfigBlock(t *testing.T) {
	cfg := proxyConfig{
		Listen:  "127.0.0.1:2222",
		KeysDir: t.TempDir(),
		HostKey: filepath.Join(t.TempDir(), "sshfw_host_key"),
	}
	block := buildSSHConfigBlock(cfg, []string{"alice", "bob"})
	for _, want := range []string{
		sshConfigBegin,
		sshConfigEnd,
		"Host sshfw\n",
		"Host sshfw-alice\n",
		"Host sshfw-bob\n",
		"ProxyCommand ",
		" stdio\n",
		"User alice",
		"HostKeyAlias sshfw",
		"StrictHostKeyChecking accept-new",
		"UserKnownHostsFile " + filepath.ToSlash(knownHostsLocalPath(cfg.HostKey)),
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("block missing %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "HostName ") || strings.Contains(block, "Port ") {
		t.Fatalf("block should use ProxyCommand only:\n%s", block)
	}
}

func TestBuildSSHConfigBlockUpstreamName(t *testing.T) {
	cfg := proxyConfig{
		Name:    "example",
		Listen:  "127.0.0.1:2222",
		KeysDir: t.TempDir(),
		HostKey: filepath.Join(t.TempDir(), "sshfw_host_key"),
	}
	single := buildSSHConfigBlock(cfg, []string{"alice"})
	if !strings.Contains(single, "Host sshfw-example\n") {
		t.Fatalf("missing named host:\n%s", single)
	}
	if !strings.Contains(single, "User alice\n") {
		t.Fatalf("missing user:\n%s", single)
	}
	if strings.Contains(single, "Host sshfw-alice\n") || strings.Contains(single, "Host sshfw\n") {
		t.Fatalf("unexpected extra hosts:\n%s", single)
	}

	multi := buildSSHConfigBlock(cfg, []string{"alice", "bob"})
	if !strings.Contains(multi, "Host sshfw-example\n") {
		t.Fatalf("missing primary:\n%s", multi)
	}
	if !strings.Contains(multi, "Host sshfw-example-alice\n") || !strings.Contains(multi, "Host sshfw-example-bob\n") {
		t.Fatalf("missing per-user hosts:\n%s", multi)
	}
}

func TestWriteSSHConfigIdempotentAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	userContent := "Host example\n    HostName example.com\n"
	if err := os.WriteFile(path, []byte(userContent), 0600); err != nil {
		t.Fatal(err)
	}
	block := sshConfigBegin + "\nHost sshfw\n    HostName 127.0.0.1\n" + sshConfigEnd + "\n"
	if err := writeSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), userContent) || !strings.Contains(string(first), block) {
		t.Fatalf("merge failed:\n%s", first)
	}
	if err := writeSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("not idempotent:\n%s\n---\n%s", first, second)
	}
	updated := strings.Replace(block, "Host sshfw\n", "Host sshfw\n    User changed\n", 1)
	if err := writeSSHConfig(path, updated); err != nil {
		t.Fatal(err)
	}
	third, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(third), sshConfigBegin) != 1 || !strings.Contains(string(third), "User changed") {
		t.Fatalf("replace failed:\n%s", third)
	}
	if err := removeSSHConfig(path); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != userContent {
		t.Fatalf("remove did not restore:\n%q", restored)
	}
}

func TestWriteKnownHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.local")
	signer, _ := testSigner(t)
	if err := writeKnownHosts(path, signer, "127.0.0.1:2222"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "sshfw") || !strings.Contains(text, "[127.0.0.1]:2222") {
		t.Fatalf("known_hosts entries: %s", text)
	}
	if !strings.Contains(text, "ssh-ed25519") {
		t.Fatalf("missing key type: %s", text)
	}
}

func TestHostKeyAlgorithms(t *testing.T) {
	signer, _ := testSigner(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"[127.0.0.1]:2222"}, signer.PublicKey()) + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	algos, err := hostKeyAlgorithms(path, "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	if len(algos) != 1 || algos[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("algos: %v", algos)
	}
	if _, err := hostKeyAlgorithms(path, "127.0.0.1:22"); err == nil {
		t.Fatal("untrusted host accepted")
	}
}
