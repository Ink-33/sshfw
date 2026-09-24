package main

import (
	"strings"
	"testing"
)

func TestHelpText(t *testing.T) {
	err := run([]string{"help"})
	if err == nil || err.Error() != "help" {
		t.Fatalf("run help: %v", err)
	}
	for _, want := range []string{
		"sshfw <command> [flags]",
		"configure",
		"ssh-config",
		"stdio",
		"serve",
		"password",
		"Typical setup",
		"ProxyCommand",
		"~/.sshfw/sshfw.json",
		"ssh sshfw-<name>",
	} {
		if !strings.Contains(helpText, want) {
			t.Fatalf("help missing %q", want)
		}
	}
	if err := run(nil); err == nil || err.Error() != "help" {
		t.Fatalf("run empty: %v", err)
	}
	err = run([]string{"nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown: %v", err)
	}
}
