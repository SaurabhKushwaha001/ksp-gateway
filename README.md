# KSP Gateway

KSP Gateway is a zero-trust pre-commit security gateway for AI-assisted
software engineering. It is being built in phases so that the orchestration
spine is in place before sandboxing and policy checks are added.

## Build order

1. Orchestrator: coordinate checks and safe access to the working tree.
2. Linux kernel sandbox: Landlock path rules and seccomp syscall rules.
3. Commit attestation and a server-side receive hook.
4. Best-effort AI semantic scanning of diffs.
5. Integration, tests, latency measurement, and demo documentation.

## Current implementation

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
current orchestrator readiness message; the CLI does not install a Git hook.

Run the full suite, including real child-process sandbox checks, with:

```sh
cargo test --locked -- --test-threads=1
```
