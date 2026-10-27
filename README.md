# KSP Gateway

KSP Gateway is a zero-trust pre-commit security gateway for AI-assisted
software engineering. Before a commit is created it scans the staged diff for
text aimed at AI coding agents and for committed secrets, runs policy checks
inside a Linux kernel sandbox against exactly the staged content, and signs an
Ed25519 attestation into the commit message. A server-side `pre-receive` hook
rejects any pushed commit without a valid attestation, so skipping the local
hooks with `git commit --no-verify` does not get code onto the server.

## Layers

| Layer | Module | Enforcement |
|---|---|---|
| Orchestrator | `src/orchestrator.rs` | In-process coordination of checks over disposable Git snapshots |
| Kernel sandbox | `src/sandbox.rs` | OS-enforced: no-new-privileges → Landlock → seccomp |
| Semantic firewall | `src/scanner.rs` | Heuristic, best-effort detection over added diff lines |
| Attestation | `src/attestation.rs`, `src/gateway.rs` | Local Ed25519 signature bound to tree, parents, policy, and checks |
| Server bouncer | `src/bouncer.rs` | Server-enforced: `pre-receive` rejects unattested commits |

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what each layer does and
does not guarantee, and [`docs/DEMO.md`](docs/DEMO.md) for a scripted demo.

## Quick start

```sh
cargo build --release --locked
gw="$PWD/target/release/ksp-gateway"

# Developer machine: create a key (kept outside the repository, mode 0600)
"$gw" keygen > my-public-key.txt
# Install the hooks and the default policy into an existing clone
"$gw" install --repo /path/to/clone

# Server: trust the developer key and install the verifier
cat my-public-key.txt >> /srv/ksp/trusted-keys
"$gw" install-server --repo /srv/git/project.git \
  --trusted-keys /srv/ksp/trusted-keys \
  --require-check semantic-scan --require-check secret-scan
```

After that, `git commit` runs the gateway automatically. Other commands:

- `ksp-gateway check` runs the checks on the staged tree without signing.
- `ksp-gateway scan [--diff FILE|-]` scans a diff (default: staged changes).
- `ksp-gateway reattest` re-checks and re-signs `HEAD` after `git commit --amend`,
  a rebase (`git rebase --exec "ksp-gateway reattest"`), or a cherry-pick, which
  do not run the commit hooks and therefore change the attested parents.
- `ksp-gateway verify-commit --trusted-keys FILE [REV...]` verifies locally.
- `ksp-gateway bench` measures pre-commit latency on the staged change.
- `ksp-gateway policy` prints the active policy digest and check list.

### Local policy

The policy lives at `.git/ksp/policy.toml`, inside the Git directory, so a
cloned repository cannot change which checks run on it. `ksp-gateway policy
--default` prints a commented template. Command checks run in the kernel
sandbox against a staged-index snapshot (unstaged edits and untracked files are
absent), with `PATH=/usr/bin:/bin`, an empty environment, no network unless
`network = "unix"` or `"all"`, and read-only access to any `read_paths`:

```toml
version = 1
[scanner]
exclude_paths = ["tests/fixtures/"]

[[check]]
name = "unit-tests"
command = ["/usr/bin/make", "test"]
timeout_secs = 300
```

The SHA-256 of the policy file is signed into each attestation. A server can
restrict accepted policies with `--allow-policy DIGEST` and require named checks
with `--require-check NAME`.

### Measured latency

Release build, WSL2 Linux 6.18, Intel i5-1135G7 (8 threads), `ksp-gateway
bench` on 2026-10-27. Times include the Git calls that compute the staged tree
and diff.

| Staged change | Checks | Median | p95 |
|---|---|---|---|
| 1 file, 1 line | built-in scanners | 10.2 ms | 11.6 ms |
| 290 KB, 7,849 lines | built-in scanners | 33.7 ms | 40.7 ms |
| 1 file, 1 line | scanners + one sandboxed `/bin/true` | 54.4 ms | 61.0 ms |

Sandboxed checks add snapshot creation (which grows with repository size) plus
the run time of the checked command itself.

## Orchestrator and snapshots

The `feature/orchestrator` branch adds an asynchronous check scheduler and an
in-process reader/writer lock manager rooted at a canonical repository
directory. Checks declare the paths they read or write. Independent checks can
run concurrently; conflicting access to a path and any ancestor or descendant
is serialized. Existing symlink aliases are resolved, and declared paths that
escape the repository root or contain `..` are rejected. Checks support
timeouts and explicit cancellation, with results returned in submission order.
Each check receives its own temporary copy of tracked and non-ignored untracked
files, so it can write without changing the live working tree.

These locks coordinate KSP Gateway tasks only. They cover only declared paths,
are not OS-level locks, and do not stop another process from changing files or
symlinks. They cannot detect undeclared file access. Temporary copies contain
private `.git` metadata and an index reconstructed from ordinary staged entries,
so Git-aware checks can inspect staged and unstaged diffs. Git hooks point to an
empty private directory, and source Git objects are borrowed read-only through
Git alternates. Snapshots omit ignored files, do not preserve special index
flags or custom filter/config behavior, and currently reject submodules.
Assume-unchanged, skip-worktree, intent-to-add, and unmerged index entries fail
snapshot creation rather than being silently misrepresented. Check-generated
changes are returned in each successful `CheckResult` as a binary Git diff
relative to the snapshot baseline. `FileLockManager::apply_changes` takes an
exclusive gateway lock, rechecks the patch against the current working tree,
then applies only to the worktree, preserving the Git index. This lock does not
coordinate external editors or Git processes, and patch application is not a
filesystem-wide transaction if an I/O failure happens midway.
Those guarantees require additional orchestration work and must not be inferred
from this module.

The sandbox is intended to enforce process access restrictions at the kernel
boundary. The AI semantic scanner, when added, will be heuristic
defense-in-depth and cannot guarantee detection of malicious instructions.

## Linux sandbox (current status)

`SandboxCommand` starts the private helper mode before the Tokio runtime. The
helper closes inherited descriptors above standard input/output/error, opens
and resolves the requested paths, changes into the workspace through its open
directory descriptor, and clears the child environment. It then applies the
required controls in this order:

1. `PR_SET_NO_NEW_PRIVS`
2. Landlock ABI V6 path restrictions, requiring full enforcement
3. seccomp-BPF syscall filtering

The command starts only after those setup steps succeed. If a required step
fails, the helper exits with code 125. Landlock restricts handled filesystem
operations to explicitly granted paths plus a small set of read-only runtime
paths and `/dev/null`. Writable grants must be inside the workspace. Explicit
read-only grants outside it are supported for inputs such as a Git object
store. The policy rejects grants overlapping the effective user's `.ssh` or
`.aws` paths, including detected symlink targets.

Socket access is controlled by `SocketPolicy`: `Deny` is the default,
`AllowDomains` permits selected domains such as `libc::AF_UNIX`, and `AllowAll`
permits socket creation in any domain. Domain filtering applies to
`socket`/`socketpair` creation; seccomp cannot inspect the pointed-to address
passed to `connect` or `bind`, so this is not destination filtering. [The Linux
seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
describes this BPF pointer limitation. Restricted socket policies also fail
closed if standard input/output/error is an inherited socket. Standard streams
are configurable through `SandboxCommand`; inherited regular files and terminal
streams remain caller-authorized I/O channels that Landlock cannot revoke after
they are open, as [Landlock documents](https://docs.kernel.org/userspace-api/landlock.html).

`SyscallPolicy::CompatibilityDenylist` is the default for ordinary tools. An
opt-in `SyscallPolicy::Allowlist` denies every syscall number not listed and
requires `execve` so the helper can start the requested command. Syscall numbers
are architecture-specific; the allowlist must be reviewed and tested for the
target architecture and command. The allowlist is configurable, but there is
not yet a curated profile for shell, Python, or Git.

**Security limits:** there are no resource limits or separate network
namespace. Opened paths are identified by device/inode in the gateway and
checked again by the helper before Landlock setup; a changed or replaced path
fails closed. Standard streams remain caller-authorized I/O channels as
described above. The sandbox depends on Landlock and seccomp support in the
running kernel and is not a guarantee against kernel vulnerabilities or
arbitrary hostile native code. Treat it as kernel-enforced reduction of access
under the configured policy, not complete containment.

Linux enforcement and policy regression tests are in
[`tests/sandbox_enforcement.rs`](tests/sandbox_enforcement.rs); the project
tracker records implemented work and remaining hardening tasks in
[`PROJECT_TRACKER.md`](PROJECT_TRACKER.md).
The Linux CI workflow runs tests on x86_64 and arm64 Ubuntu 24.04 hosted
runners. Successful runs are needed before claiming cross-architecture
compatibility.

## Development

From the WSL2/Ubuntu project directory, check host support and run a command
inside a temporary workspace:

```sh
cd /home/saurabhubuntu/ksp-gateway
cargo run --locked -- capabilities
demo_dir="$(mktemp -d)"
cargo run --locked -- sandbox --workspace "$demo_dir" -- /bin/sh -c 'printf "sandbox-ok\n" > result.txt; cat result.txt'
cat "$demo_dir/result.txt"
```

The command should print `sandbox-ok`; the result file is created inside the
workspace. By default the CLI denies socket syscalls and uses the compatibility
seccomp denylist. Run `cargo run --locked -- --help` to see options for
additional read-only paths, socket domains, and target-specific syscall
allowlists. Running `cargo run --locked` without a subcommand only prints the
current orchestrator readiness message; hooks are installed only by
`ksp-gateway install`.

Run the full suite, including real child-process sandbox checks and the
end-to-end commit/push flows, with:

```sh
cargo test --locked -- --test-threads=1
```

| Suite | Covers |
|---|---|
| `src/*` unit tests (70) | Git helpers, attestation encoding/signing/trust, bouncer decisions, scanner detections and false positives, policy parsing, staged snapshots, pipeline and hook installation |
| `tests/sandbox_enforcement.rs` (11) | Real Landlock/seccomp enforcement in child processes |
| `tests/end_to_end.rs` (6) | Real `git commit`/`git push` through installed hooks and a bare server with `pre-receive` |
