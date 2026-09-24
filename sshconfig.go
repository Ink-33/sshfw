package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	sshConfigBegin = "# >>> sshfw managed block >>>"
	sshConfigEnd   = "# <<< sshfw managed block <<<"
)

func defaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".ssh", "config")
	}
	return filepath.Join(home, ".ssh", "config")
}

func defaultSSHDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

func ensureHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			return nil, errors.New("host key must be Ed25519")
		}
		return signer, nil
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(block)
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("host key directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	return ssh.NewSignerFromKey(private)
}

func discoverUsers(keysDir string) ([]string, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, err
	}
	var users []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !validUser(name) {
			continue
		}
		if _, err := os.Stat(filepath.Join(keysDir, name, "authorized_keys")); err != nil {
			continue
		}
		users = append(users, name)
	}
	sort.Strings(users)
	return users, nil
}

func findIdentityFile(keysDir, user, sshDir string) string {
	data, err := os.ReadFile(filepath.Join(keysDir, user, "authorized_keys"))
	if err != nil {
		return ""
	}
	authorized := make(map[string]bool)
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		key, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err == nil && len(options) == 0 {
			authorized[string(key.Marshal())] = true
		}
	}
	if len(authorized) == 0 {
		return ""
	}
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "id_") {
			continue
		}
		if strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, ".ppk") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(sshDir, name)
		keyData, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		clear(keyData)
		if err != nil {
			continue
		}
		if authorized[string(signer.PublicKey().Marshal())] {
			return path
		}
	}
	return ""
}

func knownHostsLocalPath(hostKeyPath string) string {
	return filepath.Join(filepath.Dir(hostKeyPath), "known_hosts.local")
}

func sshConfigPathValue(path string) string {
	return filepath.ToSlash(path)
}

func hostAlias(name, user string, multi bool) string {
	if name == "" {
		if user == "" {
			return "sshfw"
		}
		return "sshfw-" + user
	}
	if user == "" {
		return "sshfw-" + name
	}
	if multi {
		return "sshfw-" + name + "-" + user
	}
	return "sshfw-" + name
}

func sshfwExecutable() string {
	if exe, err := os.Executable(); err == nil {
		return sshConfigPathValue(exe)
	}
	return "sshfw"
}

func proxyCommand() string {
	return fmt.Sprintf(`"%s" stdio`, sshfwExecutable())
}

func buildSSHConfigBlock(cfg proxyConfig, users []string) string {
	knownLocal := sshConfigPathValue(knownHostsLocalPath(cfg.HostKey))
	sshDir := defaultSSHDir()
	multi := len(users) > 1
	cmd := proxyCommand()

	writeHost := func(b *strings.Builder, alias, user string) {
		fmt.Fprintf(b, "Host %s\n", alias)
		fmt.Fprintf(b, "    ProxyCommand %s\n", cmd)
		if user != "" {
			fmt.Fprintf(b, "    User %s\n", user)
			if identity := findIdentityFile(cfg.KeysDir, user, sshDir); identity != "" {
				fmt.Fprintf(b, "    IdentityFile %s\n", sshConfigPathValue(identity))
			}
		}
		b.WriteString("    HostKeyAlias sshfw\n")
		fmt.Fprintf(b, "    UserKnownHostsFile %s\n", knownLocal)
		b.WriteString("    StrictHostKeyChecking accept-new\n")
	}

	var b strings.Builder
	b.WriteString(sshConfigBegin + "\n")
	switch {
	case len(users) == 0:
		writeHost(&b, hostAlias(cfg.Name, "", false), "")
	case len(users) == 1:
		writeHost(&b, hostAlias(cfg.Name, users[0], false), users[0])
	default:
		writeHost(&b, hostAlias(cfg.Name, "", false), "")
		for _, user := range users {
			b.WriteString("\n")
			writeHost(&b, hostAlias(cfg.Name, user, multi), user)
		}
	}
	b.WriteString(sshConfigEnd + "\n")
	return b.String()
}

func replaceManagedBlock(content, block string) string {
	block = strings.TrimRight(block, "\n") + "\n"
	begin := strings.Index(content, sshConfigBegin)
	end := strings.Index(content, sshConfigEnd)
	if begin >= 0 && end >= begin {
		end += len(sshConfigEnd)
		if end < len(content) && content[end] == '\n' {
			end++
		}
		return content[:begin] + block + content[end:]
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + block
}

func stripManagedBlock(content string) string {
	begin := strings.Index(content, sshConfigBegin)
	end := strings.Index(content, sshConfigEnd)
	if begin < 0 || end < begin {
		return content
	}
	end += len(sshConfigEnd)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	return content[:begin] + content[end:]
}

func writeSSHConfig(path, block string) error {
	content := ""
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated := replaceManagedBlock(content, block)
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(updated), 0600)
}

func removeSSHConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	updated := stripManagedBlock(string(data))
	if updated == string(data) {
		return nil
	}
	return os.WriteFile(path, []byte(updated), 0600)
}

func writeKnownHosts(path string, signer ssh.Signer, listen string) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	addresses := []string{"sshfw", "[127.0.0.1]:" + port}
	line := knownhosts.Line(addresses, signer.PublicKey()) + "\n"
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(line), 0600)
}

func expandHostKeyAlgo(typ string) []string {
	switch typ {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	default:
		return []string{typ}
	}
}

// hostKeyAlgorithms returns the host key algorithms to offer for upstream,
// limited to key types already trusted in known_hosts for that address.
// Go's default preference can negotiate ECDSA/RSA and then fail with
// "key mismatch" when known_hosts only has Ed25519.
func hostKeyAlgorithms(path, upstream string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{
		knownhosts.Normalize(upstream): true,
		upstream:                       true,
	}
	var algos []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
			fields = fields[1:]
		}
		if len(fields) < 3 {
			continue
		}
		matched := false
		for _, host := range strings.Split(fields[0], ",") {
			if want[host] || want[knownhosts.Normalize(host)] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fields[1] + " " + fields[2]))
		if err != nil {
			continue
		}
		for _, algo := range expandHostKeyAlgo(key.Type()) {
			if !seen[algo] {
				seen[algo] = true
				algos = append(algos, algo)
			}
		}
	}
	if len(algos) == 0 {
		return nil, fmt.Errorf("no trusted host key for %s in %s", upstream, path)
	}
	return algos, nil
}
