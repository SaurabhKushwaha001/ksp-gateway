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

## Development

```sh
cargo test
```
