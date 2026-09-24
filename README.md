# sshfw

Localhost-only SSH proxy: clients authenticate to the proxy with a **public key**; the proxy then signs in to **one upstream SSH server** with the same username and a password stored in the **OS credential store** (Windows Credential Manager / macOS Keychain / Linux Secret Service). Interactive sessions, commands, SFTP/SCP, and port forwarding are relayed.

No plaintext password files, no environment-variable fallback, no non-loopback listener.

```
you ──(pubkey)──► sshfw ──(password, keyring)──► upstream SSH
```

## Why

Some hosts only allow password authentication, or you would rather not put your private key on every laptop. `sshfw` keeps the upstream password in the system keyring and exposes a normal OpenSSH `Host` alias that uses `ProxyCommand` — no daemon to start by hand.

## Build

```sh
go build -o sshfw .
# or
make build          # current platform → dist/
make check          # go test + go vet
make build-all      # windows / linux / darwin amd64
make install        # go install
make clean
```

Requires Go (see `go.mod`). Runtime needs access to the OS credential store. `password set` must run in a terminal (no echo).

## Quick start

```sh
sshfw configure
# 1. put your public key in ~/.sshfw/users/<user>/authorized_keys
# 2. put the VERIFIED upstream host key in ~/.sshfw/known_hosts
sshfw password set --user <user>
ssh sshfw-<name>
```

`configure` writes `~/.sshfw/`, generates the proxy host key, and registers a managed block in `~/.ssh/config`. Host entries use:

```text
ProxyCommand "<path/to/sshfw>" stdio
```

so the proxy starts with your SSH session and exits when it ends. `sshfw serve` (loopback TCP) remains available for clients that cannot use `ProxyCommand`.

### Wizard

`sshfw configure` is interactive: `?` shows help for the current field, `b` goes back, and a summary is confirmed before writing. Existing config files are never overwritten (`--output` to save elsewhere).

## Commands

| Command | Purpose |
| ------- | ------- |
| `configure [--output FILE]` | Create `~/.sshfw/` layout and register `~/.ssh/config` |
| `ssh-config [--config FILE] [--remove]` | Refresh or delete the managed SSH config block |
| `stdio [...]` | One SSH session on stdin/stdout (for `ProxyCommand`) |
| `serve [...]` | Loopback TCP proxy (optional) |
| `password set\|delete --user USER` | Manage upstream password in the OS keyring |
| `help` | Full usage |

Run `sshfw help` for flags, defaults, and alias rules.

## Layout (`~/.sshfw/`)

| Path | Purpose |
| ---- | ------- |
| `sshfw.json` | Config: `name`, `listen`, `upstream`, paths |
| `users/<user>/authorized_keys` | Local public keys; `<user>` is the upstream login |
| `sshfw_host_key` | Proxy Ed25519 host private key (auto) |
| `known_hosts` | Trusted **upstream** host keys (you verify) |
| `known_hosts.local` | Proxy host key for local clients (auto) |

Managed `~/.ssh/config` block is delimited by:

```text
# >>> sshfw managed block >>>
# <<< sshfw managed block <<<
```

Everything outside those markers is left untouched. Re-running `sshfw ssh-config` is idempotent.

### Host aliases

Config field `name` (e.g. `example`) chooses the alias:

| Situation | Alias |
| --------- | ----- |
| `name` set, one user | `sshfw-example` (with `User`) |
| `name` set, several users | `sshfw-example-<user>` |
| no `name` | `sshfw-<user>` |

`HostKeyAlias` is always `sshfw` and uses `known_hosts.local`.

## Security notes

- Passwords live **only** in the OS keyring; never in config files, argv, env, or logs.
- Upstream host keys are strict: unknown or changed keys fail the handshake. `ssh-keyscan` alone does **not** authenticate a server — verify fingerprints out of band.
- `authorized_keys` entries with options are rejected, not ignored.
- Usernames / `name` must start with a letter or digit, then letters, digits, `.`, `_`, `@`, `-`.
- `--listen` must be `127.0.0.1`. Non-loopback binds are refused.

## Migrating from `./sshfw.json`

Move `sshfw.json`, `users/`, `sshfw_host_key`, and `known_hosts` under `~/.sshfw/` (or pass explicit `--config` / `--output` paths), then run `sshfw ssh-config` once.

## Development

```sh
make check
make test-race
```

CI (`.github/workflows/ci.yml`) runs `make vet` / `make test` / `make test-race` and `make build-all` (Windows, Linux, macOS). Triggers on push, pull request, release, and manual dispatch. Release events attach the three `dist/*.tar.gz` archives to the GitHub release.

Working notes under `.ai/` are local-only and gitignored.

## License

[MIT](LICENSE) © 2026 Ink33

