# KSP Gateway Project Tracker

This file is the durable handoff for the project. Update it whenever a feature,
decision, test result, or implementation status changes. It is written so a new
developer, platform, or coding session can resume without relying on chat history.

## Project identity

- **Project:** KSP-Gateway, a zero-trust pre-commit security gateway for
  AI-assisted software engineering.
- **Academic context:** Final-year B.Tech CSE project, IKGPTU; submitted to
  Mr. Sachin.
- **Team:** Saurabh Kushwaha, Aditya Chandel, Karan Paul.
- **Working directory:** `/home/saurabhubuntu/ksp-gateway` (WSL2 / Ubuntu).
- **Language/runtime:** Stable Rust, edition 2024; Tokio for async orchestration.
- **Current toolchain observed:** `rustc 1.98.0`, `cargo 1.98.0`.
- **Current branch:** `feature/orchestrator`, created from `develop`.
- **Current Git status at tracker creation:** implementation changes are
  uncommitted on the feature branch; no branch integration has happened.

## Why this project exists

AI coding agents can run shell commands and modify files with the developer's
local privileges. A hostile repository can exploit routine Git activity if
hooks or other repository-controlled scripts run without sufficient isolation.
KSP Gateway is intended to put local checks and kernel restrictions around the
pre-commit workflow, then let a server-side verifier reject commits that lack
valid local attestation.

The project description references CVE-2026-26268 as motivating context. Verify
the exact CVE details from primary sources before repeating them in public
documentation or the demo; this tracker does not independently validate that
claim.

## Architecture and security claims

| Layer | Planned implementation | Security role and limits |
|---|---|---|
| Orchestrator (spine) | Rust + Tokio; task/check coordination; per-path shared/exclusive access; safe working-tree change handling | Coordinates gateway tasks. A userspace lock alone cannot stop unrelated processes from changing files. |
| Kernel sandbox | Linux Landlock + seccomp-bpf; `landlock` and `seccompiler` crates | Intended OS-enforced restriction of filesystem and syscall access. Must fail closed when required setup cannot be applied. Required setup order: no-new-privileges, Landlock, then seccomp. |
| Attestation + server bouncer | `ed25519-dalek`; local signing after passing checks; server-side Git `pre-receive` verifier | Server-side enforcement can reject pushes without a valid signature. Local checks alone are bypassable (for example, `git commit --no-verify`). Key provisioning, revocation, and trust policy remain design tasks. |
| AI semantic firewall | Offline ONNX Runtime sidecar using `ort`, intended to inspect Git diffs for agent-targeting instructions | Best-effort heuristic defense-in-depth only. It cannot guarantee detection or replace the kernel sandbox. |

**Do not overstate security:** distinguish OS-enforced controls, server-enforced
signature policy, in-process coordination, and heuristic scanning in code,
documentation, and presentations.

## Feature inventory and status

Status meanings: **Done** means implemented and checked; **In progress** means a
partial implementation exists; **Planned** means not implemented; **Research**
means the design or feasibility still needs validation.

### 0. Setup and research

- [x] Minimal Rust project skeleton exists.
- [x] Verify Rust/Cargo availability on the current WSL environment.
- [ ] Add CI for formatting, linting, and tests.
- [ ] Record supported Linux kernel/distribution requirements and crate versions.
- [ ] Research Landlock ABI availability and seccomp behavior on supported WSL2
      kernels; document any WSL-specific limitations.
- [ ] Compile a primary-source reading list for the threat model and referenced
      vulnerability.

### 1. Orchestrator — current priority

- [x] Add Tokio runtime dependency and async binary entry point.
- [x] Add `FileLockManager` with shared and exclusive per-path locks.
- [x] Normalize absolute/relative paths under a canonical repository root; reject
      parent-directory components and paths that resolve outside the root.
- [x] Test concurrent shared access, writer exclusion, and independence of
      unrelated paths (3 tests passing on 2026-10-03).
- [x] Add a named async check/task model with declared read/write paths,
      success/failure/timeout results, and elapsed-time reporting.
- [x] Run independent checks concurrently and serialize overlapping path access
      (a directory conflicts with descendants); collapse overlapping declarations
      within one check and serialize lock state through a short registry mutex.
- [x] Apply per-check timeout to total time, including lock wait; timeout drops
      the in-flight check future and releases any locks already acquired.
- [x] Preserve submission order in returned check results.
- [x] Test independent concurrency, conflicting serialization, timeout lock
      release, reverse path declaration order, and action errors/panics (7 tests
      pass after this scheduler slice).
- [x] Test repository-root containment, symlink aliases/escapes, parent-child
      conflicts, per-check cancellation and lock release, and nested declarations
      in one check (12 tests currently pass).
- [x] Add a cloneable per-check cancellation handle and a `Cancelled` result;
      cancellation drops the check future and releases its gateway locks.
- [x] Resolve existing symlink ancestors, unify symlink aliases, and reject
      declared paths that escape the configured repository root.
- [x] Reject Unix hard-linked files from declared path locking, since distinct
      pathnames can identify the same inode. Other platform hard-link identity
      is not available through the current portable implementation.
- [ ] Define path identity on case-insensitive filesystems. Canonical paths and
      in-process locks do not close TOCTOU races against external processes.
- [x] Snapshot working-tree state before a check that may write.
- [x] Give each check a private temporary snapshot of tracked and non-ignored
      untracked working-tree files; omit `.git` and ignored files. Test that a
      check can write its snapshot without changing the source working tree.
- [x] Preserve worktree deletions in the candidate view and verify that
      non-ignored untracked files are included while ignored files are omitted.
- [x] Give snapshots private Git metadata and reconstruct the ordinary staged
      index so Git-aware checks can inspect staged and unstaged diffs. Snapshot
      hooks are redirected to a private empty directory; source Git objects are
      referenced read-only through Git alternates.
- [x] Return each successful check's candidate changes as a binary Git diff in
      `CheckResult`, relative to a captured snapshot baseline.
- [x] Preflight each patch against the live worktree and report `NoChanges`,
      `Applicable`, or `Conflict` in `CheckResult`; do not write to the live tree.
- [x] Add `FileLockManager::apply_changes`: take an exclusive repository lock,
      recheck against current files, apply only to the worktree, and leave the
      Git index untouched. Conflicts return an error.
- [x] Fail closed on assume-unchanged, skip-worktree, intent-to-add, and
      unmerged index entries because their semantics are not reconstructed.
- [x] Define snapshot policy: ignored files are excluded and submodules fail
      closed until their semantics are designed.
- [x] Test stale patch rejection, successful application, staged-index
      preservation, undeclared writes, and Unix hard-link rejection.
- [x] Keep reporting limited to check status, elapsed time, and returned diff;
      this module does not log source file contents.
- [x] Lock registry entries are removed when guards drop; no idle path entry is
      retained.

**Current module:** `src/orchestrator.rs`. The scheduler trusts checks to declare
all paths they access. The manager canonicalizes its root and locks overlapping
path prefixes, including a directory and its descendants. These locks are
in-process only; they do not lock files against editors or other processes,
cannot stop undeclared access, do not guarantee fair waiter scheduling, and do
not protect the filesystem from symlink replacement races. `FileLockManager`
accepts any existing directory; the caller must currently supply the intended
repository root. Each check receives a temporary Git snapshot with a private
index and isolated hooks path. Source Git objects are borrowed read-only.
Ignored files are excluded; submodules are rejected. Returned patches contain
only check-generated changes. `apply_changes` takes an exclusive gateway lock,
rechecks the patch, applies it to the working tree, and leaves the Git index
untouched. This cannot coordinate external editors or Git processes. Do not
start the sandbox phase until the orchestrator behavior needed by the next
layer is implemented and reviewed.

**Feature 1 progress estimate:** approximately 95% complete. The async scheduler,
path coordination, cancellation, containment checks, disposable Git snapshots,
baseline-relative patches, stale-patch rejection, and guarded worktree apply are
implemented. Remaining limitations are case-insensitive path identity,
non-Unix hard-link detection, custom filter semantics, and broader platform
integration coverage. This estimate is a planning aid, not an acceptance or
security-readiness claim.

**Working-tree safety direction (partially implemented):** each action gets a
separate temporary Git snapshot with private metadata and index. A separate
baseline tree records the initial snapshot files, so returned patches include
only check-generated changes. Source objects are borrowed read-only, and hooks
are redirected to an empty private directory. The snapshot includes tracked
and non-ignored untracked files, omits ignored files, rejects external symlinks,
and fails on submodules. Assume-unchanged, skip-worktree, intent-to-add, and
unmerged index states fail snapshot creation. Custom filter/config semantics
are not preserved. Applying a result reacquires the gateway root lock and
rechecks immediately before Git's worktree-only patch application. This protects
against concurrent gateway tasks, not external processes; it does not promise
filesystem-wide atomicity on an I/O failure.

### 2. Kernel sandbox — after orchestrator

- [ ] Establish a sandbox policy/config model (read/write paths, denied paths,
      network/socket policy, and required syscalls).
- [ ] Detect Linux and required kernel features/ABIs before launch.
- [ ] Apply `PR_SET_NO_NEW_PRIVS` before installing restrictions.
- [ ] Apply Landlock path rules after no-new-privileges.
- [ ] Apply seccomp-bpf rules after Landlock.
- [ ] Keep the order **no-new-privileges → Landlock → seccomp** explicit and
      covered by tests/review; do not reorder these setup steps.
- [ ] Restrict access to sensitive locations such as `~/.ssh` and `~/.aws`,
      and control unauthorized sockets according to the threat model.
- [ ] Launch untrusted hooks/checks only after all required rules are active.
- [ ] Fail closed when a required security control cannot be installed; report
      unsupported kernels/policies distinctly from a successful sandbox run.
- [ ] Add positive and negative integration tests in disposable environments.
- [ ] Document that the guarantee depends on the kernel, configured policy,
      and successful rule installation.

### 3. Attestation and server bouncer — after sandbox

- [ ] Define a versioned attestation payload (repository/commit identity,
      check results, policy version, timestamp, and relevant digest data).
- [ ] Generate/manage Ed25519 keys safely with `ed25519-dalek`; do not store a
      private key in the repository or logs.
- [ ] Sign locally only after required checks pass.
- [ ] Define key enrollment, identity binding, rotation, revocation, and recovery.
- [ ] Implement a Git server `pre-receive` hook that verifies signature,
      payload binding, and policy, and rejects missing/invalid attestations.
- [ ] Test tampered payloads, wrong keys, missing signatures, and bypass attempts
      such as local `--no-verify` followed by push.
- [ ] Document that server enforcement exists only where the hook and trust
      configuration are installed.

### 4. AI semantic firewall — after attestation

- [ ] Select and validate an offline model suitable for the available hardware;
      confirm the Phi-3-mini/ONNX Runtime feasibility before locking the design.
- [ ] Integrate ONNX Runtime with the `ort` crate and define a local sidecar
      protocol and lifecycle.
- [ ] Obtain changed content through Git diff handling coordinated by the spine.
- [ ] Detect text that appears to instruct an AI agent to take unsafe actions.
- [ ] Set resource limits and bound input sizes/model latency.
- [ ] Make timeout/model failures explicit and define whether policy treats them
      as warnings or blocks.
- [ ] Test expected detections, benign false positives, evasions, and offline
      operation.
- [ ] Label results heuristic; never claim complete prompt-injection detection.

### 5. Integration, measurement, and delivery

- [ ] Integrate the layers in the prescribed order without bypassing required
      sandbox setup or server-side signature enforcement.
- [ ] Measure local check latency and optimize toward the project target of
      sub-100 ms where the check/model workload makes that feasible; state the
      hardware, dataset, and measurement method.
- [ ] Add end-to-end tests for allowed and rejected commit/push flows.
- [ ] Add CI and a reproducible WSL2/Ubuntu setup guide.
- [ ] Prepare threat model, known limitations, demo scenario, and recovery steps.
- [ ] Keep synopsis/presentation deliverables separate; implementation is the
      priority in this repository.

## Decisions and implementation notes

- **Feature branches:** Before starting each feature, create a new branch from
  the latest `develop` (use names such as `feature/orchestrator` and
  `feature/kernel-sandbox`). Do not silently base a feature on `main` or an
  unrelated feature branch. Record the source commit and branch in this file.
- **Integration:** Finish and verify the feature branch, then let the team review
  and integrate it into `develop`. Start the next feature branch from the
  updated `develop`. Do not integrate or publish changes without an explicit
  team workflow decision.
- **Tests:** Add tests as each module is implemented. Run `cargo fmt --check`,
  `cargo test`, and suitable lint/integration checks for each feature and record
  results below.
- **Current lock implementation:** A short standard mutex protects an active
  lock registry; a Tokio `Notify` wakes waiters. Shared locks coexist; exclusive
  locks conflict with any overlapping path. `FileLockGuard::drop` removes the
  active lock and wakes waiters. It is in-process coordination, not an OS lock.
- **Current path model:** `FileLockManager::new(root)` canonicalizes an existing
  directory root. Declared paths must not contain `..`; existing symlink
  ancestors are canonicalized and the result must stay inside the root. Missing
  leaf paths are allowed after resolving their nearest existing ancestor. The
  constructor does not verify that the directory is a Git root. This check is
  still vulnerable to external path changes after validation and is not a
  sandbox boundary.
- **Check resource model:** Callers declare paths with `FileAccess::read` or
  `FileAccess::write`. Parent/child path overlap is treated as a conflict.
  Duplicate and nested declarations within a check are collapsed, with write
  access taking precedence. Undeclared file access is not detected.
- **Timeout behavior:** `CheckTask::with_timeout` covers lock acquisition and
  the check action. Expiry cancels the future and releases its acquired locks.
- **Result behavior:** Results are ordered like submitted checks. Action errors
  and panics become failed results. Dropping `run_checks` aborts child tasks;
  the caller then has no completed result vector to inspect.
- **Cancellation behavior:** A caller can clone `CheckTask::cancellation_handle`
  before submission and call `cancel()`. Cancellation drops the Rust future,
  yields `CheckStatus::Cancelled`, and releases acquired gateway locks. External
  subprocesses spawned by an action need their own explicit child-process
  cancellation and are not stopped automatically by dropping the Rust future.
- **Snapshot behavior:** Each check gets a unique owner-only temporary
  repository with private Git metadata and index, current bytes of tracked and
  non-ignored untracked files, and hooks redirected to an empty private
  directory. Source objects are borrowed read-only through Git alternates.
  Ignored files and submodule contents are omitted; external symlinks fail
  snapshot creation. Special index flags and custom filters/config are not
  preserved. Snapshot write-back is not implemented, so check-generated
  changes are thrown away when the check ends.
- **Rust learning notes:** Ownership means one value controls its lifetime and
  cleanup; the lock guard uses that rule to release access when it leaves
  scope. `async` functions can suspend while waiting; Tokio runs those futures
  so unrelated tasks can make progress.

## Current verification and handoff

- `cargo fmt` — applied to the current Rust files.
- `cargo test` — passed, 3 unit tests, 0 failures (2026-10-03).
- `cargo test` — passed, 5 unit tests after initial scheduler work (2026-10-03).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (14 tests), and `git diff --check` — passed after repository
  path validation, overlap-aware locks, cancellation, symlink handling, and an
  isolated snapshot write/cleanup and ignored/untracked/deletion tests
  (2026-10-19).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (14 tests), and `git diff --check` — passed after adding a
  private snapshot Git index, staged/unstaged diff coverage, and candidate
  patch reporting (2026-10-20).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (14 tests), and `git diff --check` — passed after making patches
  baseline-relative and adding conflict preflight coverage (2026-10-20).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (17 tests), and `git diff --check` — passed after guarded apply,
  stale-patch rejection, staged-index preservation, undeclared-write detection,
  Unix hard-link rejection, and fail-closed index flag handling (2026-10-20).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (7 tests), and `git diff --check` — passed after the latest
  scheduler changes (2026-10-03).
- `git diff --check` — passed after the first implementation slice.
- Current code/doc changes are uncommitted on `feature/orchestrator`.
- Next task: run the final validation, commit the orchestrator feature on
  `feature/orchestrator`, then push it. Remaining limitations are listed above;
  do not present these as kernel sandbox guarantees.

## How to resume

1. Read this file and inspect `git status --short --branch`.
2. Check `git branch --all` and confirm the feature base before starting work.
3. Run `cargo test` to establish the current baseline.
4. Continue the first unchecked item in the current phase, update its status,
   add focused tests, and record any changed design decision here.
5. Before a new feature, make a fresh branch from the latest `develop` as above.
