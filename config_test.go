package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInteractiveConfigRoundTrip(t *testing.T) {
	var prompts bytes.Buffer
	input := strings.NewReader("bad-address\nREMOTE.EXAMPLE.COM:0022\nexample\n0.0.0.0:2222\n\n./users\n./host_key\n./known_hosts\ny\n")
	config, err := promptConfig(input, &prompts)
	if err != nil {
		t.Fatal(err)
	}
	if config.Upstream != "remote.example.com:22" || config.Listen != "127.0.0.1:2222" {
		t.Fatalf("unexpected addresses: %+v", config)
	}
	if !strings.Contains(prompts.String(), "Invalid value") {
		t.Fatal("invalid address did not reprompt")
	}
	if !strings.Contains(prompts.String(), "Configuration summary:") {
		t.Fatal("missing configuration summary")
	}
	path := filepath.Join(t.TempDir(), "sshfw.json")
	if err := writeConfig(path, config); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("password")) || !bytes.Contains(data, []byte(`"upstream": "remote.example.com:22"`)) {
		t.Fatalf("unexpected config contents: %s", data)
	}
	loaded, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Upstream != config.Upstream || loaded.KeysDir != config.KeysDir || loaded.HostKey != config.HostKey || loaded.KnownHosts != config.KnownHosts {
		t.Fatalf("round trip mismatch: %+v", loaded)
	}
	if err := writeConfig(path, config); err == nil {
		t.Fatal("existing config overwritten")
	}
	if got, err := configUpstream(path, ""); err != nil || got != "remote.example.com:22" {
		t.Fatalf("password upstream: %q, %v", got, err)
	}
}

func TestReadConfigRejectsUnknownFieldsAndResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"upstream":"example.com:22","authorized_keys_dir":"users","host_key":"host_key","known_hosts":"known_hosts"}`), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.KeysDir != filepath.Join(dir, "users") || config.Listen != "127.0.0.1:2222" {
		t.Fatalf("relative path/default: %+v", config)
	}
	if err := os.WriteFile(path, []byte(`{"upstream":"example.com:22","password":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("unknown password field accepted")
	}
	if _, err := promptConfig(strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("empty interactive input accepted")
	}
}

func TestPromptConfigDefaultsAndConfirm(t *testing.T) {
	var prompts bytes.Buffer
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	input := strings.NewReader("example.com:22\n\n\n\n\n\ny\n")
	config, err := promptConfig(input, &prompts)
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "" {
		t.Fatalf("default name: %q", config.Name)
	}
	wantKeys := filepath.Join(home, ".sshfw", "users")
	wantHost := filepath.Join(home, ".sshfw", "sshfw_host_key")
	wantKnown := filepath.Join(home, ".sshfw", "known_hosts")
	if config.KeysDir != wantKeys || config.HostKey != wantHost || config.KnownHosts != wantKnown {
		t.Fatalf("defaults: %+v want keys=%s host=%s known=%s", config, wantKeys, wantHost, wantKnown)
	}
	if config.Listen != "127.0.0.1:2222" {
		t.Fatalf("listen default: %q", config.Listen)
	}

	if _, err := promptConfig(strings.NewReader("example.com:22\n\n\n\n\n\nn\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("abort was not refused")
	}
}

func TestPromptConfigHelpAndBack(t *testing.T) {
	var prompts bytes.Buffer
	// ? on first step, b at first step, then set upstream, go back, change it.
	input := strings.NewReader("?\nb\nfirst.example.com:22\nb\nsecond.example.com:22\n\n\n\n\n\ny\n")
	config, err := promptConfig(input, &prompts)
	if err != nil {
		t.Fatal(err)
	}
	if config.Upstream != "second.example.com:22" {
		t.Fatalf("back step did not replace value: %+v", config)
	}
	out := prompts.String()
	if !strings.Contains(out, "Upstream SSH server address") {
		t.Fatal("help text missing")
	}
	if !strings.Contains(out, "Already at the first step.") {
		t.Fatal("back at first step message missing")
	}
}

func TestWriteConfigCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "sshfw.json")
	config := fileConfig{
		Upstream: "example.com:22", Listen: "127.0.0.1:2222",
		KeysDir: "users", HostKey: "host_key", KnownHosts: "known_hosts",
	}
	if err := writeConfig(path, config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	got := defaultConfigPath()
	want := filepath.Join(home, ".sshfw", "sshfw.json")
	if got != want {
		t.Fatalf("defaultConfigPath=%q want %q", got, want)
	}
}
