package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		switch {
		case errors.Is(err, errHelp):
			fmt.Fprint(os.Stdout, helpText)
			os.Exit(0)
		case errors.Is(err, flag.ErrHelp):
			// Subcommand usage already printed by fs.Usage.
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "sshfw:", err)
		fmt.Fprintln(os.Stderr, "Run 'sshfw help' for full usage.")
		os.Exit(1)
	}
}

var errHelp = errors.New("help")

const helpText = `sshfw — localhost SSH proxy

  Local clients authenticate with a public key. The proxy then signs in to one
  upstream SSH server with the same username and a password from the OS
  credential store (Windows Credential Manager / macOS Keychain / Secret Service).

Usage
  sshfw <command> [flags]
  sshfw help

Commands
  configure     Create ~/.sshfw/ config and register ~/.ssh/config
  ssh-config    Refresh or remove the managed block in ~/.ssh/config
  stdio         Proxy one SSH session over stdin/stdout (used by ProxyCommand)
  serve         Run a loopback TCP proxy (optional; not needed for ProxyCommand)
  password      set|delete the upstream password in the OS keyring
  help          Show this help

Typical setup (no daemon)
  1. sshfw configure
       Write ~/.sshfw/sshfw.json, generate host key, register ssh config.
  2. Put each local public key in:
       ~/.sshfw/users/<user>/authorized_keys
       <user> is also the upstream login name.
  3. Put the VERIFIED upstream host key in:
       ~/.sshfw/known_hosts
       Format is OpenSSH known_hosts, including [host]:port if needed.
  4. sshfw password set --user <user>
       Stores the upstream password in the OS keyring (never on disk).
  5. ssh sshfw-<name>
       Or ssh sshfw-<user> when config has no "name".
       Managed Host entries use: ProxyCommand "<sshfw>" stdio

Examples
  sshfw configure
  sshfw configure --output /path/to/sshfw.json
  sshfw ssh-config
  sshfw ssh-config --remove
  sshfw password set --user alice
  sshfw password delete --user alice
  sshfw serve --listen 127.0.0.1:2222
  ssh sshfw-example
  sftp sshfw-example

Command reference
  configure [--output FILE]
      FILE defaults to ~/.sshfw/sshfw.json. Existing files are never overwritten.

  ssh-config [--config FILE] [--remove]
      Rewrite (default) or delete the managed block between
      "# >>> sshfw managed block >>>" and "# <<< sshfw managed block <<<".
      Other content in ~/.ssh/config is left untouched.

  stdio  [--config FILE] [--upstream HOST:PORT --authorized-keys-dir DIR
          --host-key FILE --known-hosts FILE]
      Serve exactly one SSH connection on stdin/stdout, then exit.
      Intended for OpenSSH ProxyCommand; no TCP listener.

  serve  [--config FILE] [--upstream HOST:PORT --authorized-keys-dir DIR
          --host-key FILE --known-hosts FILE] [--listen 127.0.0.1:2222]
      Listen on a loopback TCP port and proxy each connection.
      --listen must be 127.0.0.1. Flags override values from --config.

  password set|delete --user USER [--config FILE | --upstream HOST:PORT]
      set reads the password from a TTY without echo. delete removes it.
      Passwords live only in the OS keyring.

Defaults and paths
  config            ~/.sshfw/sshfw.json
  authorized keys   ~/.sshfw/users/<user>/authorized_keys
  proxy host key    ~/.sshfw/sshfw_host_key          (Ed25519, auto-generated)
  upstream keys     ~/.sshfw/known_hosts             (you verify and maintain)
  proxy known_hosts ~/.sshfw/known_hosts.local       (auto-generated)
  ssh config        ~/.ssh/config                    (managed block only)

Host aliases (managed block)
  Config field "name" (e.g. example) selects the alias:
    one user   ->  Host sshfw-example          User <user>
    many users ->  Host sshfw-example-<user>
    no name    ->  Host sshfw-<user>
  HostKeyAlias is always sshfw and uses known_hosts.local.

Notes
  - Never puts passwords in config files, argv, env, or logs.
  - Upstream host keys are strict: unknown or changed keys fail the handshake.
  - Username / name charset: start with letter or digit; then letters, digits, . _ @ -
  - Authorized-key options in authorized_keys are rejected, not ignored.
`

func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if _, err := os.Stat(defaultConfigPath()); err == nil {
		return defaultConfigPath()
	}
	return ""
}

func run(args []string) error {
	if len(args) == 0 {
		return errHelp
	}
	switch args[0] {
	case "help", "-h", "--help":
		return errHelp
	case "configure":
		fs := flag.NewFlagSet("configure", flag.ContinueOnError)
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: sshfw configure [--output FILE]")
			fmt.Fprintln(os.Stderr, "Create ~/.sshfw/ layout and register ~/.ssh/config. FILE defaults to ~/.sshfw/sshfw.json.")
		}
		output := fs.String("output", "", "config file to create (default ~/.sshfw/sshfw.json)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return errors.New("unexpected argument: " + strings.Join(fs.Args(), " "))
		}
		configPath := *output
		if configPath == "" {
			configPath = defaultConfigPath()
		}
		if home, err := sshfwHome(); err == nil {
			if err := os.MkdirAll(home, 0700); err != nil {
				return fmt.Errorf("create %s: %w", home, err)
			}
		}
		config, err := promptConfig(os.Stdin, os.Stderr)
		if err != nil {
			return fmt.Errorf("configure: %w", err)
		}
		if err := writeConfig(configPath, config); err != nil {
			return err
		}
		if err := os.MkdirAll(config.KeysDir, 0700); err != nil {
			return fmt.Errorf("authorized keys directory: %w", err)
		}
		signer, err := ensureHostKey(config.HostKey)
		if err != nil {
			return err
		}
		knownLocal := knownHostsLocalPath(config.HostKey)
		if err := writeKnownHosts(knownLocal, signer, config.Listen); err != nil {
			return err
		}
		sshConfigPath := defaultSSHConfigPath()
		users, err := discoverUsers(config.KeysDir)
		if err != nil {
			return err
		}
		block := buildSSHConfigBlock(config.proxyConfig(), users)
		if err := writeSSHConfig(sshConfigPath, block); err != nil {
			return fmt.Errorf("ssh config: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Created", configPath)
		fmt.Fprintln(os.Stderr, "Host key:", config.HostKey)
		fmt.Fprintln(os.Stderr, "Local known_hosts:", knownLocal)
		fmt.Fprintln(os.Stderr, "Registered managed block in", sshConfigPath)
		if len(users) == 0 {
			fmt.Fprintln(os.Stderr, "Add public keys under", config.KeysDir, "as <user>/authorized_keys, then run: sshfw ssh-config")
		} else if config.Name != "" && len(users) == 1 {
			fmt.Fprintln(os.Stderr, "Connect with: ssh", hostAlias(config.Name, users[0], false))
		} else {
			fmt.Fprintln(os.Stderr, "Connect with: ssh", hostAlias(config.Name, users[0], len(users) > 1))
		}
		return nil
	case "ssh-config":
		fs := flag.NewFlagSet("ssh-config", flag.ContinueOnError)
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: sshfw ssh-config [--config FILE] [--remove]")
			fmt.Fprintln(os.Stderr, "Rewrite (or with --remove delete) the sshfw managed block in ~/.ssh/config.")
		}
		configPath := fs.String("config", "", "JSON config file (default ~/.sshfw/sshfw.json)")
		remove := fs.Bool("remove", false, "remove the managed block from ~/.ssh/config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return errors.New("unexpected argument: " + strings.Join(fs.Args(), " "))
		}
		sshConfigPath := defaultSSHConfigPath()
		if *remove {
			if err := removeSSHConfig(sshConfigPath); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Removed sshfw managed block from", sshConfigPath)
			return nil
		}
		path := resolveConfigPath(*configPath)
		if path == "" {
			return errors.New("no config found; run sshfw configure first")
		}
		config, err := readConfig(path)
		if err != nil {
			return err
		}
		users, err := discoverUsers(config.KeysDir)
		if err != nil {
			return err
		}
		block := buildSSHConfigBlock(config, users)
		if err := writeSSHConfig(sshConfigPath, block); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Updated sshfw managed block in", sshConfigPath)
		if len(users) == 1 {
			fmt.Fprintln(os.Stderr, "  ssh", hostAlias(config.Name, users[0], false))
		} else {
			for _, user := range users {
				fmt.Fprintln(os.Stderr, "  ssh", hostAlias(config.Name, user, len(users) > 1))
			}
		}
		return nil
	case "serve", "stdio":
		cmd := args[0]
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		fs.Usage = func() {
			if cmd == "stdio" {
				fmt.Fprintln(os.Stderr, "Usage: sshfw stdio [--config FILE] [--upstream HOST:PORT --authorized-keys-dir DIR --host-key FILE --known-hosts FILE]")
				fmt.Fprintln(os.Stderr, "Proxy one SSH session on stdin/stdout (OpenSSH ProxyCommand). No TCP listener.")
			} else {
				fmt.Fprintln(os.Stderr, "Usage: sshfw serve [--config FILE] [--upstream HOST:PORT --authorized-keys-dir DIR --host-key FILE --known-hosts FILE] [--listen 127.0.0.1:2222]")
				fmt.Fprintln(os.Stderr, "Run a loopback TCP SSH proxy. Optional; ProxyCommand uses 'sshfw stdio' instead.")
			}
		}
		configPath := fs.String("config", "", "JSON config file (default ~/.sshfw/sshfw.json)")
		listen := fs.String("listen", "127.0.0.1:2222", "loopback listen address")
		upstream := fs.String("upstream", "", "remote SSH host:port")
		keysDir := fs.String("authorized-keys-dir", "", "directory of <user>/authorized_keys files")
		hostKey := fs.String("host-key", "", "Ed25519 SSH host private key")
		knownHosts := fs.String("known-hosts", "", "trusted remote SSH host keys")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return errors.New("unexpected argument: " + strings.Join(fs.Args(), " "))
		}
		config := proxyConfig{Listen: *listen}
		path := resolveConfigPath(*configPath)
		if path != "" {
			var err error
			config, err = readConfig(path)
			if err != nil {
				return err
			}
		}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "listen":
				config.Listen = *listen
			case "upstream":
				config.Upstream = *upstream
			case "authorized-keys-dir":
				config.KeysDir = *keysDir
			case "host-key":
				config.HostKey = *hostKey
			case "known-hosts":
				config.KnownHosts = *knownHosts
			}
		})
		if cmd == "stdio" && config.Listen == "" {
			config.Listen = "127.0.0.1:2222"
		}
		config, err := validateConfig(config)
		if err != nil {
			return err
		}
		server, err := newProxy(config, osKeyring{})
		if err != nil {
			return err
		}
		logger := log.New(os.Stderr, "sshfw: ", log.LstdFlags)
		if cmd == "stdio" {
			return server.serveStdio(logger)
		}
		return server.serve(logger)
	case "password":
		if len(args) < 2 || (args[1] != "set" && args[1] != "delete") {
			fmt.Fprintln(os.Stderr, "Usage: sshfw password set|delete --user USER [--config FILE | --upstream HOST:PORT]")
			return errors.New("password requires subcommand set or delete")
		}
		fs := flag.NewFlagSet("password "+args[1], flag.ContinueOnError)
		fs.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: sshfw password %s --user USER [--config FILE | --upstream HOST:PORT]\n", args[1])
			if args[1] == "set" {
				fmt.Fprintln(os.Stderr, "Store the upstream password in the OS keyring (TTY required, no echo).")
			} else {
				fmt.Fprintln(os.Stderr, "Remove the upstream password from the OS keyring.")
			}
		}
		configPath := fs.String("config", "", "JSON config file (default ~/.sshfw/sshfw.json)")
		upstream := fs.String("upstream", "", "remote SSH host:port")
		user := fs.String("user", "", "remote SSH username (also the local authorized_keys folder name)")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return errors.New("unexpected argument: " + strings.Join(fs.Args(), " "))
		}
		if *user == "" {
			fs.Usage()
			return errors.New("password command requires --user USER")
		}
		if !validUser(*user) {
			return fmt.Errorf("invalid --user %q (use letters, digits, . _ @ -; start with letter or digit)", *user)
		}
		target, err := configUpstream(resolveConfigPath(*configPath), *upstream)
		if err != nil {
			return fmt.Errorf("upstream: %w", err)
		}
		service := credentialService(target)
		if args[1] == "delete" {
			return keyring.Delete(service, *user)
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("password set requires a terminal")
		}
		fmt.Fprint(os.Stderr, "Remote SSH password: ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		defer clear(secret)
		if len(secret) == 0 {
			return errors.New("empty password refused")
		}
		return keyring.Set(service, *user, string(secret))
	default:
		return fmt.Errorf("unknown command %q (configure | ssh-config | stdio | serve | password | help)", args[0])
	}
}

func normalizeAddress(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", errors.New("expected HOST:PORT")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("port must be 1..65535")
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port)), nil
}

func validateListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return errors.New("--listen must use 127.0.0.1")
	}
	_, err = normalizeAddress(address)
	return err
}

func credentialService(upstream string) string { return "sshfw:" + upstream }

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
