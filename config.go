package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type fileConfig struct {
	Name       string `json:"name,omitempty"`
	Listen     string `json:"listen"`
	Upstream   string `json:"upstream"`
	KeysDir    string `json:"authorized_keys_dir"`
	HostKey    string `json:"host_key"`
	KnownHosts string `json:"known_hosts"`
}

func (c fileConfig) proxyConfig() proxyConfig {
	return proxyConfig{
		Name: c.Name, Listen: c.Listen, Upstream: c.Upstream, KeysDir: c.KeysDir,
		HostKey: c.HostKey, KnownHosts: c.KnownHosts,
	}
}

func sshfwHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sshfw"), nil
}

func defaultConfigPath() string {
	home, err := sshfwHome()
	if err != nil {
		return filepath.Join(".sshfw", "sshfw.json")
	}
	return filepath.Join(home, "sshfw.json")
}

func readConfig(path string) (proxyConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return proxyConfig{}, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return proxyConfig{}, fmt.Errorf("config: %w", err)
	}
	if info.Size() > 64*1024 {
		return proxyConfig{}, errors.New("config: file exceeds 64 KiB")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 64*1024))
	decoder.DisallowUnknownFields()
	var config fileConfig
	if err := decoder.Decode(&config); err != nil {
		return proxyConfig{}, fmt.Errorf("config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return proxyConfig{}, errors.New("config: expected one JSON object")
	}
	if config.Name != "" && !validUser(config.Name) {
		return proxyConfig{}, errors.New("config: name must be a simple host alias token")
	}
	if config.Listen == "" {
		config.Listen = "127.0.0.1:2222"
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return proxyConfig{}, err
	}
	config.KeysDir = relativeTo(base, config.KeysDir)
	config.HostKey = relativeTo(base, config.HostKey)
	config.KnownHosts = relativeTo(base, config.KnownHosts)
	return config.proxyConfig(), nil
}

func relativeTo(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

type wizardStep struct {
	label    string
	help     string
	fallback string
	validate func(string) (string, error)
	value    string
}

func promptConfig(input io.Reader, output io.Writer) (fileConfig, error) {
	reader := bufio.NewReader(input)
	fmt.Fprintln(output, "sshfw configuration wizard")
	fmt.Fprintln(output, "Config lives under ~/.sshfw by default. Type ? for help, b to go back.")
	fmt.Fprintln(output, "Passwords are never stored in the config file.")

	address := func(s string) (string, error) { return normalizeAddress(s) }
	listen := func(s string) (string, error) {
		if err := validateListen(s); err != nil {
			return "", err
		}
		return s, nil
	}
	path := func(s string) (string, error) {
		if s == "" {
			return "", errors.New("path is required")
		}
		if s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "~\\") {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			s = filepath.Join(home, strings.TrimLeft(s[1:], "/\\"))
		}
		return filepath.Abs(s)
	}

	steps := []*wizardStep{
		{
			label:    "Remote SSH host:port",
			help:     "Upstream SSH server address as HOST:PORT (for example example.com:22). The proxy signs in here with a password from the OS credential store.",
			validate: address,
		},
		{
			label: "Upstream name",
			help:  "Short name used for SSH Host aliases. Example: example produces Host sshfw-example. Leave empty to use sshfw-<user>.",
			validate: func(s string) (string, error) {
				if s == "" {
					return "", nil
				}
				if !validUser(s) || strings.ContainsAny(s, "@") {
					return "", errors.New("name must be a simple token (letters, digits, . _ -)")
				}
				return s, nil
			},
		},
		{
			label:    "Local listen address",
			help:     "Loopback address the proxy listens on. Must be 127.0.0.1:PORT. Local SSH clients connect here (default port 2222).",
			fallback: "127.0.0.1:2222",
			validate: listen,
		},
		{
			label:    "Authorized keys directory",
			help:     "Directory of <user>/authorized_keys files. Each subdirectory name is a login name; that user's public key goes in authorized_keys. Default ~/.sshfw/users.",
			fallback: "~/.sshfw/users",
			validate: path,
		},
		{
			label:    "Proxy Ed25519 host private key",
			help:     "Persistent Ed25519 host private key for the local proxy. Generated automatically if missing. Keep it stable so local clients can verify the proxy.",
			fallback: "~/.sshfw/sshfw_host_key",
			validate: path,
		},
		{
			label:    "Upstream known_hosts file",
			help:     "Trusted upstream host keys (OpenSSH known_hosts format). Add only keys you have verified out-of-band. Default ~/.sshfw/known_hosts.",
			fallback: "~/.sshfw/known_hosts",
			validate: path,
		},
	}

	readLine := func() (string, error) {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if errors.Is(err, io.EOF) && line == "" {
			return "", io.EOF
		}
		return strings.TrimSpace(line), nil
	}

	for i := 0; i < len(steps); {
		s := steps[i]
		if s.fallback == "" {
			fmt.Fprintf(output, "%s: ", s.label)
		} else {
			fmt.Fprintf(output, "%s [%s]: ", s.label, s.fallback)
		}
		value, err := readLine()
		if err != nil {
			return fileConfig{}, err
		}
		if value == "?" {
			fmt.Fprintf(output, "%s\n", s.help)
			continue
		}
		if value == "b" {
			if i == 0 {
				fmt.Fprintln(output, "Already at the first step.")
				continue
			}
			i--
			continue
		}
		if value == "" {
			value = s.fallback
		}
		validated, validationErr := s.validate(value)
		if validationErr != nil {
			fmt.Fprintf(output, "Invalid value: %v\n", validationErr)
			continue
		}
		s.value = validated
		i++
	}

	config := fileConfig{
		Upstream:   steps[0].value,
		Name:       steps[1].value,
		Listen:     steps[2].value,
		KeysDir:    steps[3].value,
		HostKey:    steps[4].value,
		KnownHosts: steps[5].value,
	}

	fmt.Fprintln(output, "Configuration summary:")
	fmt.Fprintf(output, "  Remote SSH host:port  %s\n", config.Upstream)
	fmt.Fprintf(output, "  Upstream name         %s\n", config.Name)
	fmt.Fprintf(output, "  Local listen address  %s\n", config.Listen)
	fmt.Fprintf(output, "  Authorized keys dir   %s\n", config.KeysDir)
	fmt.Fprintf(output, "  Proxy host key        %s\n", config.HostKey)
	fmt.Fprintf(output, "  Upstream known_hosts  %s\n", config.KnownHosts)

	for {
		fmt.Fprint(output, "Write this configuration? [Y/n]: ")
		answer, err := readLine()
		if err != nil {
			return fileConfig{}, err
		}
		switch strings.ToLower(answer) {
		case "", "y", "yes":
			return config, nil
		case "n", "no":
			return fileConfig{}, errors.New("aborted")
		case "?":
			fmt.Fprintln(output, "Enter y (default) to save the configuration, or n to abort without writing.")
		default:
			fmt.Fprintln(output, "Please answer y or n.")
		}
	}
}

func writeConfig(path string, config fileConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write config: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close config: %w", err)
	}
	return nil
}

func configUpstream(configPath, upstream string) (string, error) {
	if configPath == "" {
		if _, err := os.Stat(defaultConfigPath()); err == nil {
			configPath = defaultConfigPath()
		}
	}
	if configPath != "" {
		config, err := readConfig(configPath)
		if err != nil {
			return "", err
		}
		if upstream == "" {
			upstream = config.Upstream
		}
	}
	return normalizeAddress(upstream)
}

func validateConfig(config proxyConfig) (proxyConfig, error) {
	if config.KeysDir == "" || config.HostKey == "" || config.KnownHosts == "" {
		return proxyConfig{}, errors.New("serve requires --upstream, --authorized-keys-dir, --host-key and --known-hosts, or --config")
	}
	target, err := normalizeAddress(config.Upstream)
	if err != nil {
		return proxyConfig{}, fmt.Errorf("upstream: %w", err)
	}
	config.Upstream = target
	if err := validateListen(config.Listen); err != nil {
		return proxyConfig{}, err
	}
	return config, nil
}
