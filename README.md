# LittleSnitchRules

`lsrules` serves [Little Snitch](https://obdev.at/products/littlesnitch) rule
groups (`.lsrules`) over HTTPS from the machine they describe.

## Why this exists

Little Snitch subscribes to a rule group by URL, keeps it in sync, and refuses
anything but HTTPS:

> For security reasons, only HTTPS URLs are allowed.

That leaves two options. Publish the rule groups somewhere public — but a rule
group describes what runs on this machine, which is an argument against
publishing it. Or serve them from the machine itself, which is what this does:
loopback only, with a certificate from the machine's own CA.

```
LittleSnitchConfig/rules/*.lsrules
   └─ lsrules (com.schretzi.lsrules) on https://localhost:8443/
        └─ Little Snitch subscription
```

## Installation

```sh
brew install schretzi/tap/lsrules
```

It needs a certificate. On this setup it comes from MacbookSetup's `local_ca`
role, which issues it as `lsrules` with `step --bundle` — leaf plus issuing
intermediate, so a client verifies against the root the System keychain
already trusts and nothing extra has to be installed:

```sh
ansible-playbook site.yml --tags local_ca --ask-become-pass   # in MacbookSetup
```

Then:

```sh
lsrules config init          # writes ~/.config/lsrules/config.yaml
lsrules config validate
lsrules service install
```

`config validate` reports every problem at once rather than one per run: a
server that cannot start is a launchd crash-loop with a healthy-looking label,
so it is worth finding all of it before the plist is written.

## Usage

```sh
lsrules status               # what is served, whether TLS works, the job
lsrules serve                # foreground, for watching it work
lsrules service status       # the launchd job alone
```

`status` probes the port and completes a TLS handshake rather than trusting
launchd's opinion of the job — the failure worth catching is a subscription
that quietly stops refreshing, and launchd reports that job as running.

Subscribe with **Rule Groups → + → Subscribe to rule group**, or:

```sh
open "x-littlesnitch:subscribe-rules?url=https://localhost:8443/proxy-chain.lsrules"
```

A live subscription shows up in `~/Library/Logs/lsrules.log` as a fetch
followed by conditional requests:

```
2026-08-31T07:10:35+02:00 127.0.0.1 "GET /proxy-chain.lsrules" 200 412 1.2ms
2026-08-31T07:11:02+02:00 127.0.0.1 "HEAD /proxy-chain.lsrules" 304 0 340µs
```

The 304 is the point: a one-time import never asks again, so that line is what
distinguishes a subscription from an import.

## What it serves, and what it will not

Exactly the `*.lsrules` files in one directory. Not a file server over that
directory — a rule group lives in a git checkout next to a README, a backlog
and a `.git`, and none of that belongs on a listening socket. Anything else is
404, including paths that try to walk out of the directory.

It binds loopback. Nothing here should be reachable from the network.

## Configuration

```yaml
rules_dir: ~/Workspace/Schretzi/LittleSnitchConfig/rules
listen:
  host: 127.0.0.1
  port: 8443
tls:
  cert: ~/.local/share/localca/lsrules.crt   # leaf + intermediate
  key: ~/.local/share/localca/lsrules.key
log:
  path: ~/Library/Logs/lsrules.log
```

There are no rotation settings. Rotation belongs to `newsyslog`
(MacbookSetup, `etc/newsyslog.d/lsrules.conf`); this process's only
obligation is to notice when the file has been rotated out from under it,
which `internal/logfile` does by re-stating the path and reopening when the
inode changes.

## Conventions

Same as every other background job on this machine:

| | |
| --- | --- |
| launchd label | `com.schretzi.lsrules` |
| plist | `~/Library/LaunchAgents/com.schretzi.lsrules.plist` |
| config | `~/.config/lsrules/config.yaml` |
| log | `~/Library/Logs/lsrules.log` |
| launchd stderr | `~/Library/Logs/lsrules.err.log` (panics only) |
| control | `lsrules service install\|uninstall\|start\|stop\|restart\|status` |

`service` is the launchd job; `serve` is the foreground process it runs. The
two are never the same word.

## Development

```sh
make pipeline     # fmt, lint, security, test, build - what CI runs
make hooks        # lefthook install, once per clone
make docs         # regenerate docs/ from the command tree
```

Release: `git tag vX.Y.Z && git push origin vX.Y.Z`, then Actions → Release →
Run workflow against that tag. Never automatic on tag push.

`internal/service`, `internal/logfile` and `internal/version` are duplicated
verbatim across KerberosKeepAlive, OauthMailToken, macswitcher, tunneling and
this repository — five modules with no shared dependency. Keep the copies in
sync by hand.

## AI usage

Written with Claude Code. The architecture was decided jointly after checking
how Little Snitch actually behaves — that subscriptions are HTTPS-only, and
that a refresh is a conditional request — rather than from assumptions about
either. The code was written by the AI against an approved plan, and the
result was verified end to end: a real subscription against a real Little
Snitch installation, not a mock.
