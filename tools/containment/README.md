# Egress containment below the tool layer (`tools/containment/`)

The DSH enforcer intercepts egress **at the tool layer**: it scans command text and
denies known network binaries. Interpreter one-liners (`python3 -c`, node, php) and
bash-invoked CLIs bypass it — a documented, accepted limit. This directory adds the
layer below that one: wrap the agent host process tree in a macOS `sandbox-exec`
profile so the kernel refuses a non-loopback socket connect no matter who makes it.
With raw egress closed, the controlled executors (`research_os_request`,
`research_os_browser`) and the loopback-only proxy become the sole path off-host.

```text
agent host  ──run──▶  sandbox-exec -f tools/containment/macos-egress.sb -- <host command>
                        │
                        ├─ loopback / this host ................ allowed
                        └─ every other destination ............. denied (EPERM)
```

## Usage

```bash
# generate a profile for a workspace and inspect it
python3 tools/containment/generate_profile.py --print --workspace "$PWD" | head -30

# write it atomically next to the workspace
python3 tools/containment/generate_profile.py --out /tmp/research-os-egress.sb \
    --workspace "$PWD"

# wrap the agent host (the profile applies to the whole process tree)
sandbox-exec -f /tmp/research-os-egress.sb -- <host command>
```

- `--workspace DIR` (repeatable) restricts `file-write*` to those directories plus the
  user's temp dir (`$TMPDIR`, resolved) and the standard `/dev` streams. Without it,
  file writes are **unrestricted** and the profile header says so.
- `--allow IP:PORT` (repeatable, sorted) adds a literal-IP egress exception. Hostnames
  are rejected: the profile never uses DNS (SBPL has no resolution step, so a name would
  either be rejected by the parser or pin whatever it resolved to at compile time).
  IPv6 must be bracketed (`[::1]:8080`).
- `--broker-socket PATH` (repeatable, sorted, absolute) allows `AF_UNIX` connects to a
  policy-broker socket: `(allow network-outbound (remote unix-socket (path-literal …)))`.
  The path is symlink-resolved at generation time (SBPL literals match exactly what the
  kernel sees — a symlinked path never matches). Without it the broker socket is
  unreachable inside the sandbox, so wrap with the broker's socket to keep broker mode:
  `generate_profile.py --workspace "$PWD" --broker-socket ~/.dsh/research-os-broker/broker.sock`.
- `--print` (default) vs `--out PATH` (atomic temp + `os.replace`, no partial profiles).
- `--literal-ips` / `--no-literal-ips` force the emission mode; the default probes the
  host's SBPL parser with one compile check whose profile allows the exec plumbing
  (`(allow process*)`, `(allow file-read*)`) plus one literal-IP rule — so a non-zero exit
  means the parser rejected the literal-IP syntax, not that the probe command failed on
  its own. Output is deterministic for identical inputs and mode.

`generate_profile.py --help` documents the deprecation, the literal-IP pinning and the
DNS limit. The generated header records the generator and the workspace `OS_VERSION`.

## What the selftest proves

`python3 tools/containment/selftest.py [--json]` builds a real profile, runs an
in-process loopback listener plus a listener on this host's non-loopback IPv4, and
executes a Python child **under `sandbox-exec`**. Every probe is in-machine or a
zero-packet reserved-address connect; **no real egress is attempted**.

| probe | expectation | meaning |
| --- | --- | --- |
| `loopback_tcp` | `ok` | the agent host can still use its own loopback services |
| `local_address_tcp` | `ok` (localhost host spec) / `PermissionError` (literal pins) | follows the SBPL parser's meaning of `localhost`, recorded per mode |
| `off_host_udp` | `PermissionError` | UDP `connect()` to `192.0.2.1` (RFC 5737 TEST-NET-1, reserved; `connect()` sends no packet) is refused by the kernel |
| `write_workspace` | `ok` | writes inside `--workspace` are allowed |
| `write_tmp` | `ok` | writes inside `$TMPDIR` are allowed |
| `write_denied` | `PermissionError` | writes outside every allowed path are refused |

Exit 0 on PASS or SKIP (non-darwin platform or missing `sandbox-exec`, the only SKIP
cases), 1 on FAIL — including a generated profile the OS rejects while `sandbox-exec` is
present: a rejected profile means the containment does not work on this host, never a
silent skip.

`python3 tools/test_containment.py` covers the generator (determinism, `(deny default)`,
loopback allow, `--allow` validation and sorted pins, `--print`/`--out` equivalence,
workspace write rules, host profile compile) and the selftest (SKIP paths plus the real
machine run, reported as SKIP when the environment cannot run it).

## Limitations and threat model

- `sandbox-exec` is a **deprecated** macOS API. It enforces in the kernel and works, but
  it is not a supported interface and may change; this is a containment layer, not a
  hardened security boundary.
- **The allowlist is literal-IP only — never DNS.** On macOS builds whose SBPL parser
  accepts literal network hosts, each `--allow` entry is pinned to its literal IP and
  port. On this macOS (26.x) the parser accepts **only `*` and `localhost`** as network
  hosts, and `localhost` matches *every address of this host* (verified: a port-qualified
  `localhost` rule matches a non-loopback local connect). The generator therefore refuses
  a non-loopback `--allow` on such a host instead of emitting a profile the parser would
  reject wholesale; on such a host the guarantee is **"on-host only"**, not
  "127.0.0.1 only". Consequences: anything listening on one of this machine's addresses
  (including VM bridges) stays reachable from the wrapped tree.
- Protect the machine, not the user's other processes: the profile constrains **the
  network reachable by the wrapped process tree**. Other processes of the same user,
  processes outside the sandbox, and the user's own clients are untouched — the sandbox
  is not a network firewall for the account.
- Same-UID file protection is **not** the goal of this layer (the DSH plugin and the
  control plane own protected-path writes); `file-read*` stays unrestricted so tools and
  interpreters can load. Concretely, with `--workspace DIR` the profile denies writes to
  the policy broker's home (`~/.dsh/research-os-broker`, its `policies/` snapshots
  included) only because that home lies outside the wrapped tree's write paths; reads of
  it — `key` included — remain allowed. The broker home's own modes are the other half:
  the home is `0700`, `key`/policy files/ledger/audit are `0600`, and the `policies/`
  directory carries the process umask (typically `0755`) inside that `0700` home.
- Heavier alternatives when the literal-IP pin matters: run the agent host in a
  Lima/Colima VM or a network-namespace container and firewall its egress there. macOS
  `pf` rules require root and would need a root daemon; this profile needs neither.
- The profile grants process creation, `mach-lookup` and `file-read*` broadly, so a
  wrapped process can still read local files and talk to local daemons; treat the
  containment as the network boundary only.

## Files

| file | role |
| --- | --- |
| `generate_profile.py` | deterministic SBPL generator (`--print` / `--out`, `--allow`, `--workspace`, `--broker-socket`) |
| `selftest.py` | runs the real containment proof on this machine (`--json`) |
| `../test_containment.py` | generator + selftest suite (`check()` style, non-zero on failure) |
| `README.md` | this document |
