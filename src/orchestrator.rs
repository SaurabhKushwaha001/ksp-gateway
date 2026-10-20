//! Per-path coordination for checks that read or modify a working tree.
//!
//! This lock only coordinates KSP Gateway tasks in this process. It does not
//! prevent unrelated programs from changing files; later orchestration work
//! must detect and preserve external edits before applying any changes.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    future::Future,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    pin::Pin,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

type CheckFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
type CheckAction = Box<dyn FnOnce(CheckContext) -> CheckFuture + Send + 'static>;

/// Whether a task only inspects a file or may modify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Multiple readers can hold this lock at once.
    Shared,
    /// A writer holds this lock exclusively.
    Exclusive,
}

/// A file a check intends to read or modify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccess {
    path: PathBuf,
    mode: LockMode,
}

impl FileAccess {
    /// Declare that a check reads `path`; other readers may run concurrently.
    pub fn read(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: LockMode::Shared,
        }
    }

    /// Declare that a check may modify `path`; access is exclusive.
    pub fn write(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: LockMode::Exclusive,
        }
    }
}

/// One named asynchronous check and the paths it may access.
///
/// The action receives a [`CheckContext`] for a disposable workspace. Any file
/// changes it makes are discarded when the action completes until explicit
/// change reconciliation is implemented.
pub struct CheckTask {
    name: String,
    accesses: Vec<FileAccess>,
    timeout: Option<Duration>,
    cancellation: CheckCancellation,
    action: CheckAction,
}

impl CheckTask {
    /// Create a check. Its declared access locks are held until it finishes,
    /// fails, times out, or is cancelled by dropping the scheduler future.
    pub fn new<F, Fut>(name: impl Into<String>, accesses: Vec<FileAccess>, action: F) -> Self
    where
        F: FnOnce(CheckContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            name: name.into(),
            accesses,
            timeout: None,
            cancellation: CheckCancellation::default(),
            action: Box::new(move |context| Box::pin(action(context))),
        }
    }

    /// Set an optional wall-clock limit, including time waiting for file locks.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Get a handle that can cancel this check after it is submitted.
    pub fn cancellation_handle(&self) -> CheckCancellation {
        self.cancellation.clone()
    }
}

/// Paths supplied to one check. File operations should use `workspace_root`,
/// which is a private copy and is discarded when the check finishes.
#[derive(Debug, Clone)]
pub struct CheckContext {
    repository_root: PathBuf,
    workspace_root: PathBuf,
}

impl CheckContext {
    /// The check's isolated, writable workspace directory.
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Translate a repository path into the corresponding isolated path.
    pub fn workspace_path(&self, repository_path: impl AsRef<Path>) -> io::Result<PathBuf> {
        let source = resolve_repo_path(&self.repository_root, repository_path.as_ref())?;
        let relative = source.strip_prefix(&self.repository_root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path is outside repository",
            )
        })?;
        Ok(self.workspace_root.join(relative))
    }
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    changed: Notify,
}

/// A cloneable handle for requesting cooperative cancellation of one check.
#[derive(Clone, Default)]
pub struct CheckCancellation(Arc<CancellationState>);

impl CheckCancellation {
    /// Request cancellation. An already-finished check is unaffected.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            if self.0.cancelled.load(Ordering::Acquire) {
                return;
            }
            let notified = self.0.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// Final state of an executed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Passed,
    Failed(String),
    TimedOut,
    Cancelled,
}

/// Result of one check, in the submission order returned by [`run_checks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub elapsed: Duration,
    /// Binary Git patch from the captured worktree baseline to this candidate.
    pub changes: Vec<u8>,
    /// Whether a patch preflight accepted it against the live tree at check end.
    /// This is advisory and can become stale before a caller applies the patch.
    pub reconciliation: ReconciliationStatus,
}

/// Preflight result for applying a candidate patch to the live worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationStatus {
    NoChanges,
    Applicable,
    Conflict(String),
}

/// Result of applying a check's patch to the repository working tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStatus {
    Applied,
    NoChanges,
}

/// Runs checks concurrently while honoring their declared path access.
///
/// Each check receives a separate isolated snapshot. Checks also acquire their
/// declared path locks in normalized order. Dropping this future aborts its
/// child tasks; Tokio drops their lock guards and temporary workspaces as well.
pub async fn run_checks(
    lock_manager: Arc<FileLockManager>,
    checks: Vec<CheckTask>,
) -> Vec<CheckResult> {
    let count = checks.len();
    let mut results: Vec<Option<CheckResult>> = (0..count).map(|_| None).collect();
    let mut tasks = tokio::task::JoinSet::new();
    let mut task_indexes = HashMap::new();

    for (index, check) in checks.into_iter().enumerate() {
        let manager = Arc::clone(&lock_manager);
        let task_name = check.name.clone();
        let lookup_name = task_name.clone();
        let task = tasks.spawn(async move {
            let started = Instant::now();
            let timeout = check.timeout;
            let cancellation = check.cancellation.clone();
            let execution = execute_check(manager, check);
            let execution = async move {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => Err(CheckFailure::Cancelled),
                    result = execution => result,
                }
            };
            let result = match timeout {
                Some(limit) => tokio::time::timeout(limit, execution)
                    .await
                    .map_err(|_| CheckFailure::TimedOut)
                    .and_then(|result| result),
                None => execution.await,
            };
            let check_result = match result {
                Ok((changes, reconciliation)) => CheckResult {
                    name: task_name,
                    status: CheckStatus::Passed,
                    elapsed: started.elapsed(),
                    reconciliation,
                    changes,
                },
                Err(CheckFailure::Failed(message)) => CheckResult {
                    name: task_name,
                    status: CheckStatus::Failed(message),
                    elapsed: started.elapsed(),
                    changes: Vec::new(),
                    reconciliation: ReconciliationStatus::NoChanges,
                },
                Err(CheckFailure::TimedOut) => CheckResult {
                    name: task_name,
                    status: CheckStatus::TimedOut,
                    elapsed: started.elapsed(),
                    changes: Vec::new(),
                    reconciliation: ReconciliationStatus::NoChanges,
                },
                Err(CheckFailure::Cancelled) => CheckResult {
                    name: task_name,
                    status: CheckStatus::Cancelled,
                    elapsed: started.elapsed(),
                    changes: Vec::new(),
                    reconciliation: ReconciliationStatus::NoChanges,
                },
            };
            (index, check_result)
        });
        task_indexes.insert(task.id(), (index, lookup_name));
    }

    while let Some(joined) = tasks.join_next_with_id().await {
        match joined {
            Ok((_id, (index, result))) => results[index] = Some(result),
            Err(error) => {
                if let Some((index, name)) = task_indexes.get(&error.id()) {
                    results[*index] = Some(CheckResult {
                        name: name.clone(),
                        status: CheckStatus::Failed(format!(
                            "check task did not complete: {error}"
                        )),
                        elapsed: Duration::ZERO,
                        changes: Vec::new(),
                        reconciliation: ReconciliationStatus::NoChanges,
                    });
                }
            }
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.unwrap_or_else(|| CheckResult {
                name: format!("check-{index}"),
                status: CheckStatus::Failed("check task was cancelled".into()),
                elapsed: Duration::ZERO,
                changes: Vec::new(),
                reconciliation: ReconciliationStatus::NoChanges,
            })
        })
        .collect()
}

enum CheckFailure {
    Failed(String),
    TimedOut,
    Cancelled,
}

async fn execute_check(
    manager: Arc<FileLockManager>,
    check: CheckTask,
) -> Result<(Vec<u8>, ReconciliationStatus), CheckFailure> {
    // Merge duplicate declarations, with exclusive access taking precedence.
    let mut accesses = BTreeMap::<PathBuf, LockMode>::new();
    for access in check.accesses {
        let path = manager.resolve_path(&access.path).map_err(|error| {
            CheckFailure::Failed(format!("could not resolve declared path: {error}"))
        })?;
        accesses
            .entry(path)
            .and_modify(|mode| {
                if access.mode == LockMode::Exclusive {
                    *mode = LockMode::Exclusive;
                }
            })
            .or_insert(access.mode);
    }

    let accesses = collapse_overlapping_accesses(accesses);
    let writable_paths = accesses
        .iter()
        .filter(|(_, mode)| *mode == LockMode::Exclusive)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mut _guards = Vec::with_capacity(accesses.len());
    for (path, mode) in accesses {
        _guards.push(manager.acquire(path, mode).await.map_err(|error| {
            CheckFailure::Failed(format!("could not acquire file lock: {error}"))
        })?);
    }

    let root = manager.root.clone();
    let workspace = tokio::task::spawn_blocking(move || IsolatedWorkspace::create(&root))
        .await
        .map_err(|error| CheckFailure::Failed(format!("snapshot task failed: {error}")))?
        .map_err(|error| {
            CheckFailure::Failed(format!("could not create check snapshot: {error}"))
        })?;
    let context = CheckContext {
        repository_root: manager.root.clone(),
        workspace_root: workspace.path().to_path_buf(),
    };
    (check.action)(context)
        .await
        .map_err(CheckFailure::Failed)?;
    let repository_root = manager.root.clone();
    tokio::task::spawn_blocking(move || {
        let patch = workspace.candidate_patch(&writable_paths)?;
        let reconciliation = check_patch_against_live(&repository_root, &patch)?;
        Ok::<_, io::Error>((patch, reconciliation))
    })
    .await
    .map_err(|error| CheckFailure::Failed(format!("patch task failed: {error}")))?
    .map_err(|error| CheckFailure::Failed(format!("could not create candidate patch: {error}")))
}

static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary Git working tree with a private index and source objects read-only.
pub struct IsolatedWorkspace {
    container: PathBuf,
    path: PathBuf,
    baseline: Option<String>,
    repository_root: PathBuf,
}

impl IsolatedWorkspace {
    /// Copy the current working-tree view into a private temporary directory.
    pub fn create(repository_root: impl AsRef<Path>) -> io::Result<Self> {
        let repository_root = fs::canonicalize(repository_root)?;
        let (git_root, paths) = git_working_paths(&repository_root)?;
        if git_root != repository_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot root must be the Git working-tree root",
            ));
        }

        let mut workspace = Self::create_temp_dir()?;
        workspace.repository_root = repository_root.clone();
        let entries = git_output(
            &repository_root,
            ["ls-files", "--stage", "--full-name", "-z"],
        )?;
        validate_index_entries(&entries.stdout)?;
        let flags = git_output(&repository_root, ["ls-files", "-v", "--full-name", "-z"])?;
        for entry in flags
            .stdout
            .split(|byte| *byte == 0)
            .filter(|e| !e.is_empty())
        {
            if entry.len() < 2 || entry[1] != b' ' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Git returned an invalid index flag record",
                ));
            }
            let tag = entry[0];
            if tag.is_ascii_lowercase() || tag == b'S' {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "assume-unchanged and skip-worktree index flags are not supported",
                ));
            }
        }
        let object_path = git_output(&repository_root, ["rev-parse", "--git-path", "objects"])?;
        let object_path = trim_git_output(object_path.stdout);
        let object_path = os_path_from_bytes(object_path)?;
        let object_path = if object_path.is_absolute() {
            object_path
        } else {
            repository_root.join(object_path)
        };
        let object_path = fs::canonicalize(object_path)?;
        let head = git_optional_output(&repository_root, ["rev-parse", "--verify", "HEAD"])?;
        let template = workspace.container.join("empty-template");
        let hooks = workspace.container.join("empty-hooks");
        create_private_dir(&template)?;
        create_private_dir(&hooks)?;
        let mut init = git_command(&workspace.path);
        init.args(["init", "--quiet", "--template"])
            .arg(&template)
            .arg(&workspace.path);
        run_git(init)?;
        fs::remove_dir_all(&template)?;
        let mut config = git_command(&workspace.path);
        config.args(["config", "core.hooksPath"]).arg(&hooks);
        run_git(config)?;
        let info = workspace.path.join(".git/objects/info");
        fs::create_dir_all(&info)?;
        let object_path_string = object_path.to_string_lossy();
        if object_path_string.contains('\n') || object_path_string.contains('\r') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git object path contains a newline",
            ));
        }
        fs::write(info.join("alternates"), format!("{object_path_string}\n"))?;
        if let Some(head) = head {
            let head = trim_git_output(head.stdout);
            let head = String::from_utf8(head)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let mut update = git_command(&workspace.path);
            update.args(["update-ref", "refs/heads/ksp-snapshot", &head]);
            run_git(update)?;
            let mut symbolic = git_command(&workspace.path);
            symbolic.args(["symbolic-ref", "HEAD", "refs/heads/ksp-snapshot"]);
            run_git(symbolic)?;
        }
        let mut clear_index = git_command(&workspace.path);
        clear_index.args(["read-tree", "--empty"]);
        run_git(clear_index)?;
        let mut update_index = git_command(&workspace.path);
        update_index
            .args(["update-index", "-z", "--index-info"])
            .stdin(Stdio::piped());
        let mut child = update_index.spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("could not open snapshot index input"))?
            .write_all(&entries.stdout)?;
        let status = child.wait()?;
        if !status.success() {
            return Err(io::Error::other("could not reconstruct isolated Git index"));
        }
        for relative in paths {
            if !is_safe_relative_path(&relative) || relative.components().any(is_git_metadata) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Git returned a path that cannot be copied into a snapshot",
                ));
            }
            let source = repository_root.join(&relative);
            let destination = workspace.path.join(&relative);
            match fs::symlink_metadata(&source) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
                Ok(_) => {}
            }
            copy_snapshot_entry(&repository_root, &workspace.path, &source, &destination)?;
        }
        workspace.baseline = Some(create_snapshot_baseline(&workspace.path)?);
        Ok(workspace)
    }

    /// The root of this snapshot. Check actions may modify files here.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn candidate_patch(&self, writable_paths: &[PathBuf]) -> io::Result<Vec<u8>> {
        // Intent-to-add makes non-ignored untracked files visible to `git diff`
        // without adding their contents to the private index.
        let mut add = git_command(&self.path);
        add.args(["add", "--intent-to-add", "--", "."]);
        run_git(add)?;
        let baseline = self
            .baseline
            .as_deref()
            .ok_or_else(|| io::Error::other("snapshot baseline is unavailable"))?;
        let changed = git_output(
            &self.path,
            ["diff", "--name-only", "--no-renames", "-z", baseline, "--"],
        )?;
        for bytes in changed
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let relative = os_path_from_bytes(bytes.to_vec())?;
            if !is_safe_relative_path(&relative) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "candidate patch contains an unsafe path",
                ));
            }
            let absolute = self.repository_root.join(&relative);
            if !writable_paths
                .iter()
                .any(|allowed| absolute.starts_with(allowed))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "check modified a path without exclusive access: {}",
                        relative.display()
                    ),
                ));
            }
        }
        let diff = git_output(
            &self.path,
            [
                "-c",
                "core.quotePath=false",
                "diff",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
                baseline,
                "--",
            ],
        )?;
        Ok(diff.stdout)
    }

    fn create_temp_dir() -> io::Result<Self> {
        let temp_root = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..100 {
            let id = SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let container =
                temp_root.join(format!("ksp-gateway-check-{}-{id}", std::process::id()));
            match create_private_dir(&container) {
                Ok(()) => {
                    let path = container.join("workspace");
                    create_private_dir(&path)?;
                    return Ok(Self {
                        container,
                        path,
                        baseline: None,
                        repository_root: PathBuf::new(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique check snapshot directory",
        ))
    }
}

impl Drop for IsolatedWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.container);
    }
}

fn git_working_paths(root: &Path) -> io::Result<(PathBuf, Vec<PathBuf>)> {
    let top_level = git_output(root, ["rev-parse", "--show-toplevel"])?;
    let mut top_level = top_level.stdout;
    while top_level.last() == Some(&b'\n') || top_level.last() == Some(&b'\r') {
        top_level.pop();
    }
    let git_root = fs::canonicalize(os_path_from_bytes(top_level)?)?;
    let listing = git_output(
        root,
        [
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotePath=false",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--full-name",
            "-z",
        ],
    )?;
    let paths = listing
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| os_path_from_bytes(bytes.to_vec()))
        .collect::<io::Result<Vec<_>>>()?;
    Ok((git_root, paths))
}

fn trim_git_output(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.last() == Some(&b'\n') || bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    bytes
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_OBJECT_DIRECTORY");
    command
}

fn run_git(mut command: Command) -> io::Result<()> {
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn git_optional_output<const N: usize>(
    root: &Path,
    args: [&str; N],
) -> io::Result<Option<std::process::Output>> {
    let output = git_command(root).args(args).output()?;
    if output.status.success() {
        Ok(Some(output))
    } else if String::from_utf8_lossy(&output.stderr).contains("Needed a single revision")
        || String::from_utf8_lossy(&output.stderr)
            .contains("unknown revision or path not in the working tree")
    {
        Ok(None)
    } else {
        Err(io::Error::other(format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn create_snapshot_baseline(root: &Path) -> io::Result<String> {
    let index = root.join(".git/ksp-baseline-index");
    let _ = fs::remove_file(&index);
    let mut add = git_command(root);
    add.env("GIT_INDEX_FILE", &index)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["add", "--all", "--", "."]);
    run_git(add)?;
    let mut write_tree = git_command(root);
    write_tree
        .env("GIT_INDEX_FILE", &index)
        .args(["write-tree"]);
    let tree = String::from_utf8(trim_git_output(write_tree.output()?.stdout))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut commit = git_command(root);
    commit.args([
        "-c",
        "user.name=KSP Gateway",
        "-c",
        "user.email=ksp-gateway@localhost",
        "commit-tree",
        &tree,
        "-m",
        "KSP snapshot baseline",
    ]);
    let output = commit.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "could not write snapshot baseline: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let baseline = String::from_utf8(trim_git_output(output.stdout))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let _ = fs::remove_file(index);
    Ok(baseline)
}

fn validate_index_entries(entries: &[u8]) -> io::Result<()> {
    for record in entries.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Git returned an invalid index record",
                )
            })?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || fields[2] != "0" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unmerged Git index entries are not supported in snapshots",
            ));
        }
        if fields[1].bytes().all(|byte| byte == b'0') {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "intent-to-add Git index entries are not supported in snapshots",
            ));
        }
    }
    Ok(())
}

fn check_patch_against_live(root: &Path, patch: &[u8]) -> io::Result<ReconciliationStatus> {
    if patch.is_empty() {
        return Ok(ReconciliationStatus::NoChanges);
    }
    let mut command = git_command(root);
    command
        .args(["apply", "--check", "--binary"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("could not open patch preflight input"))?
        .write_all(patch)?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(ReconciliationStatus::Applicable)
    } else {
        Ok(ReconciliationStatus::Conflict(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

fn apply_patch_checked(root: &Path, patch: &[u8]) -> io::Result<ApplyStatus> {
    match check_patch_against_live(root, patch)? {
        ReconciliationStatus::NoChanges => return Ok(ApplyStatus::NoChanges),
        ReconciliationStatus::Conflict(message) => {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, message));
        }
        ReconciliationStatus::Applicable => {}
    }
    let mut command = git_command(root);
    command
        .args(["apply", "--binary"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("could not open patch apply input"))?
        .write_all(patch)?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(ApplyStatus::Applied)
    } else {
        Err(io::Error::other(format!(
            "git apply failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn git_output<const N: usize>(root: &Path, args: [&str; N]) -> io::Result<std::process::Output> {
    let mut command = git_command(root);
    command.args(args);
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output)
}

#[cfg(unix)]
fn os_path_from_bytes(bytes: Vec<u8>) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
fn os_path_from_bytes(bytes: Vec<u8>) -> io::Result<PathBuf> {
    String::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn is_git_metadata(component: Component<'_>) -> bool {
    matches!(component, Component::Normal(name) if name == ".git")
}

fn copy_snapshot_entry(
    repository_root: &Path,
    workspace_root: &Path,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        let target = fs::canonicalize(source)?;
        if !target.starts_with(repository_root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "snapshot contains a symlink that escapes the repository",
            ));
        }
        let relative_target = target.strip_prefix(repository_root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "symlink target is outside root",
            )
        })?;
        let snapshot_target = workspace_root.join(relative_target);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        create_snapshot_symlink(&snapshot_target, destination, target.is_dir())?;
    } else if file_type.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
        make_snapshot_writable(destination, false)?;
    } else if file_type.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Git submodule snapshots are not implemented yet",
        ));
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "snapshot contains an unsupported filesystem entry",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn create_snapshot_symlink(target: &Path, link: &Path, is_dir: bool) -> io::Result<()> {
    let _ = is_dir;
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_snapshot_symlink(target: &Path, link: &Path, is_dir: bool) -> io::Result<()> {
    if is_dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(not(any(unix, windows)))]
fn create_snapshot_symlink(_target: &Path, _link: &Path, _is_dir: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlinks are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn make_snapshot_writable(path: &Path, is_directory: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    let needed = if is_directory { 0o700 } else { 0o200 };
    permissions.set_mode(permissions.mode() | needed);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn make_snapshot_writable(path: &Path, _is_directory: bool) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
}

struct ActiveLock {
    id: u64,
    path: PathBuf,
    mode: LockMode,
}

#[derive(Default)]
struct LockRegistry {
    active: Mutex<Vec<ActiveLock>>,
    changed: Notify,
    next_id: AtomicU64,
}

/// Coordinates repository-scoped path access among asynchronous gateway tasks.
pub struct FileLockManager {
    root: PathBuf,
    registry: Arc<LockRegistry>,
}

/// A held repository path lock. Dropping it wakes checks waiting on overlapping paths.
pub struct FileLockGuard {
    path: PathBuf,
    mode: LockMode,
    id: u64,
    registry: Arc<LockRegistry>,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.registry.active.lock() {
            active.retain(|lock| lock.id != self.id);
            self.registry.changed.notify_waiters();
        }
    }
}

impl FileLockGuard {
    /// The canonical repository path this guard protects.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The access mode held by this guard.
    pub fn mode(&self) -> LockMode {
        self.mode
    }
}

impl FileLockManager {
    /// Create a lock manager rooted at an existing repository directory.
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository root must be a directory",
            ));
        }
        Ok(Self {
            root,
            registry: Arc::new(LockRegistry::default()),
        })
    }

    /// The canonical repository root used to validate declared paths.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Apply a successful check's patch after rechecking it under an exclusive
    /// repository lock. The Git index is not changed. External processes do not
    /// participate in this lock registry, so avoid concurrent external writes.
    pub async fn apply_changes(&self, result: &CheckResult) -> io::Result<ApplyStatus> {
        if result.status != CheckStatus::Passed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only successful checks can be applied",
            ));
        }
        if result.changes.is_empty() {
            return Ok(ApplyStatus::NoChanges);
        }
        let _guard = self.acquire(".", LockMode::Exclusive).await?;
        let root = self.root.clone();
        let patch = result.changes.clone();
        tokio::task::spawn_blocking(move || apply_patch_checked(&root, &patch))
            .await
            .map_err(|error| io::Error::other(format!("patch apply task failed: {error}")))?
    }

    fn resolve_path(&self, path: &Path) -> io::Result<PathBuf> {
        let resolved = resolve_repo_path(&self.root, path)?;
        reject_hard_link_file(&resolved)?;
        Ok(resolved)
    }

    /// Acquire access to a repository-relative path. Existing symlinks are
    /// resolved and paths that escape the repository root are rejected.
    pub async fn acquire(
        &self,
        path: impl AsRef<Path>,
        mode: LockMode,
    ) -> io::Result<FileLockGuard> {
        let path = self.resolve_path(path.as_ref())?;
        loop {
            let notified = self.registry.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let id = {
                let mut active = self
                    .registry
                    .active
                    .lock()
                    .map_err(|_| io::Error::other("file lock registry is poisoned"))?;
                let conflict = active.iter().any(|current| {
                    paths_overlap(&path, &current.path)
                        && (mode == LockMode::Exclusive || current.mode == LockMode::Exclusive)
                });
                if conflict {
                    None
                } else {
                    let id = self.registry.next_id.fetch_add(1, Ordering::Relaxed);
                    active.push(ActiveLock {
                        id,
                        path: path.clone(),
                        mode,
                    });
                    Some(id)
                }
            };
            if let Some(id) = id {
                return Ok(FileLockGuard {
                    path,
                    mode,
                    id,
                    registry: Arc::clone(&self.registry),
                });
            } else {
                notified.await;
            }
        }
    }
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

fn resolve_repo_path(root: &Path, path: &Path) -> io::Result<PathBuf> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "parent-directory components are not allowed in declared paths",
        ));
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let mut lexical = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                lexical.pop();
            }
            other => lexical.push(other.as_os_str()),
        }
    }
    if !lexical.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "declared path escapes the repository root",
        ));
    }

    let mut probe = lexical.clone();
    let mut missing = Vec::new();
    let resolved_ancestor = loop {
        match fs::symlink_metadata(&probe) {
            Ok(_) => break fs::canonicalize(&probe)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = probe.file_name().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no existing path ancestor found")
                })?;
                missing.push(name.to_os_string());
                if !probe.pop() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no existing path ancestor found",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    };
    if !resolved_ancestor.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "declared path resolves outside the repository root",
        ));
    }
    let mut resolved = resolved_ancestor;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(unix)]
fn reject_hard_link_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.is_file() && metadata.nlink() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hard-linked files cannot be declared for orchestrated access",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_hard_link_file(_path: &Path) -> io::Result<()> {
    // The standard library has no portable hard-link count API. Platforms that
    // cannot report it retain this documented limitation.
    Ok(())
}

fn collapse_overlapping_accesses(
    accesses: BTreeMap<PathBuf, LockMode>,
) -> Vec<(PathBuf, LockMode)> {
    let mut collapsed = Vec::<(PathBuf, LockMode)>::new();
    for (path, mode) in accesses {
        if let Some((_, ancestor_mode)) = collapsed
            .iter_mut()
            .find(|(ancestor, _)| path.starts_with(ancestor.as_path()))
        {
            if mode == LockMode::Exclusive {
                *ancestor_mode = LockMode::Exclusive;
            }
            continue;
        }

        let mut effective_mode = mode;
        collapsed.retain(|(existing, existing_mode)| {
            if existing.starts_with(&path) {
                if *existing_mode == LockMode::Exclusive {
                    effective_mode = LockMode::Exclusive;
                }
                false
            } else {
                true
            }
        });
        collapsed.push((path, effective_mode));
    }
    collapsed.sort_by(|a, b| a.0.cmp(&b.0));
    collapsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::{Barrier, oneshot};

    fn manager() -> FileLockManager {
        FileLockManager::new(std::env::current_dir().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn shared_locks_can_be_held_together() {
        let manager = Arc::new(manager());
        let first = manager
            .acquire("src/main.rs", LockMode::Shared)
            .await
            .unwrap();
        let second = manager
            .acquire("./src/main.rs", LockMode::Shared)
            .await
            .unwrap();
        assert_eq!(first.path(), second.path());
        assert_eq!(first.mode(), LockMode::Shared);
        assert_eq!(second.mode(), LockMode::Shared);
    }

    #[tokio::test]
    async fn exclusive_lock_waits_until_shared_lock_is_dropped() {
        let manager = Arc::new(manager());
        let reader = manager
            .acquire("Cargo.toml", LockMode::Shared)
            .await
            .unwrap();
        let (started_tx, started_rx) = oneshot::channel();
        let writer_manager = Arc::clone(&manager);
        let writer = tokio::spawn(async move {
            let _ = started_tx.send(());
            writer_manager
                .acquire("Cargo.toml", LockMode::Exclusive)
                .await
                .unwrap()
        });

        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!writer.is_finished(), "writer passed an active reader");
        drop(reader);
        assert_eq!(writer.await.unwrap().mode(), LockMode::Exclusive);
    }

    #[tokio::test]
    async fn unrelated_paths_do_not_block_each_other() {
        let manager = manager();
        let _first = manager
            .acquire("src/main.rs", LockMode::Exclusive)
            .await
            .unwrap();
        let second = manager
            .acquire("Cargo.toml", LockMode::Exclusive)
            .await
            .unwrap();
        assert_eq!(second.mode(), LockMode::Exclusive);
    }

    #[tokio::test]
    async fn parent_and_child_paths_conflict() {
        let manager = Arc::new(manager());
        let parent = manager.acquire("src", LockMode::Shared).await.unwrap();
        let child_manager = Arc::clone(&manager);
        let child = tokio::spawn(async move {
            child_manager
                .acquire("src/main.rs", LockMode::Exclusive)
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(
            !child.is_finished(),
            "child writer passed an active parent reader"
        );
        drop(parent);
        assert_eq!(child.await.unwrap().mode(), LockMode::Exclusive);
    }

    #[tokio::test]
    async fn overlapping_accesses_from_one_check_are_collapsed() {
        let checks = vec![CheckTask::new(
            "nested-access",
            vec![FileAccess::read("src"), FileAccess::write("src/main.rs")],
            |_| async { Ok(()) },
        )];
        let results = tokio::time::timeout(
            Duration::from_secs(1),
            run_checks(Arc::new(manager()), checks),
        )
        .await
        .expect("a check blocked on its own overlapping declarations");
        assert_eq!(results[0].status, CheckStatus::Passed);
    }

    #[tokio::test]
    async fn check_writes_are_confined_to_a_private_snapshot() {
        let root = std::env::current_dir().unwrap();
        let original_manifest = fs::read(root.join("Cargo.toml")).unwrap();
        let (snapshot_tx, snapshot_rx) = oneshot::channel();
        let check = CheckTask::new(
            "isolated-write",
            vec![FileAccess::write("Cargo.toml")],
            move |context| async move {
                let manifest = context.workspace_path("Cargo.toml").unwrap();
                assert!(context.workspace_root().starts_with(std::env::temp_dir()));
                assert!(manifest.exists());
                assert!(context.workspace_root().join(".git").exists());
                assert!(!context.workspace_root().join("target").exists());
                let _ = snapshot_tx.send(context.workspace_root().to_path_buf());
                fs::write(manifest, b"changed only in the snapshot").unwrap();
                Ok(())
            },
        );

        let results = run_checks(Arc::new(manager()), vec![check]).await;
        assert_eq!(results[0].status, CheckStatus::Passed);
        assert_eq!(results[0].reconciliation, ReconciliationStatus::Applicable);
        assert!(
            String::from_utf8_lossy(&results[0].changes).contains("changed only in the snapshot")
        );
        let snapshot_path = snapshot_rx.await.unwrap();
        assert!(
            !snapshot_path.exists(),
            "temporary snapshot was not cleaned up"
        );
        assert_eq!(
            fs::read(root.join("Cargo.toml")).unwrap(),
            original_manifest
        );

        let undeclared = CheckTask::new(
            "undeclared-write",
            vec![FileAccess::write("Cargo.toml")],
            |context| async move {
                fs::write(context.workspace_path("README.md").unwrap(), "not allowed").unwrap();
                Ok(())
            },
        );
        let results = run_checks(Arc::new(manager()), vec![undeclared]).await;
        assert!(matches!(results[0].status, CheckStatus::Failed(_)));
    }

    #[tokio::test]
    async fn applying_a_check_patch_rechecks_conflicts_and_preserves_the_index() {
        let repository = IsolatedWorkspace::create_temp_dir().unwrap();
        let root = repository.path().to_path_buf();
        git_output(&root, ["init", "-q"]).unwrap();
        git_output(&root, ["config", "user.name", "KSP test"]).unwrap();
        git_output(&root, ["config", "user.email", "ksp-test@example.invalid"]).unwrap();
        fs::write(root.join("file.txt"), "base\n").unwrap();
        git_output(&root, ["add", "file.txt"]).unwrap();
        git_output(&root, ["commit", "-qm", "initial file"]).unwrap();
        fs::write(root.join("file.txt"), "staged version\n").unwrap();
        git_output(&root, ["add", "file.txt"]).unwrap();
        fs::write(root.join("file.txt"), "current local version\n").unwrap();

        let manager = Arc::new(FileLockManager::new(&root).unwrap());
        let check = CheckTask::new(
            "candidate-edit",
            vec![FileAccess::write("file.txt")],
            |context| async move {
                let path = context
                    .workspace_path("file.txt")
                    .map_err(|error| error.to_string())?;
                fs::write(path, "check output\n").map_err(|error| error.to_string())?;
                Ok(())
            },
        );
        let results = run_checks(Arc::clone(&manager), vec![check]).await;
        assert_eq!(results[0].reconciliation, ReconciliationStatus::Applicable);
        assert_eq!(
            fs::read_to_string(root.join("file.txt")).unwrap(),
            "current local version\n"
        );

        fs::write(root.join("file.txt"), "external concurrent edit\n").unwrap();
        assert_eq!(
            manager.apply_changes(&results[0]).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            fs::read_to_string(root.join("file.txt")).unwrap(),
            "external concurrent edit\n"
        );

        let fresh_check = CheckTask::new(
            "fresh-candidate-edit",
            vec![FileAccess::write("file.txt")],
            |context| async move {
                let path = context
                    .workspace_path("file.txt")
                    .map_err(|error| error.to_string())?;
                fs::write(path, "check output\n").map_err(|error| error.to_string())?;
                Ok(())
            },
        );
        let fresh_results = run_checks(Arc::clone(&manager), vec![fresh_check]).await;
        assert_eq!(
            fresh_results[0].reconciliation,
            ReconciliationStatus::Applicable
        );
        assert_eq!(
            manager.apply_changes(&fresh_results[0]).await.unwrap(),
            ApplyStatus::Applied
        );
        assert_eq!(
            fs::read_to_string(root.join("file.txt")).unwrap(),
            "check output\n"
        );
        let staged = git_output(&root, ["diff", "--cached", "--", "file.txt"]).unwrap();
        assert!(String::from_utf8_lossy(&staged.stdout).contains("staged version"));
    }

    #[test]
    fn snapshot_includes_untracked_and_deletions_but_excludes_ignored_files() {
        let repository = IsolatedWorkspace::create_temp_dir().unwrap();
        let root = repository.path();
        git_output(root, ["init", "-q"]).unwrap();
        git_output(root, ["config", "user.name", "KSP test"]).unwrap();
        git_output(root, ["config", "user.email", "ksp-test@example.invalid"]).unwrap();
        fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(root.join("removed.txt"), "initial").unwrap();
        fs::write(root.join("tracked.txt"), "base content\n").unwrap();
        git_output(root, ["add", ".gitignore", "removed.txt", "tracked.txt"]).unwrap();
        git_output(root, ["commit", "-qm", "initial file"]).unwrap();
        fs::remove_file(root.join("removed.txt")).unwrap();
        fs::write(root.join("untracked.txt"), "new local file").unwrap();
        fs::write(root.join("ignored.txt"), "private ignored file").unwrap();
        fs::write(root.join("tracked.txt"), "staged content\n").unwrap();
        git_output(root, ["add", "tracked.txt"]).unwrap();
        fs::write(root.join("tracked.txt"), "unstaged content\n").unwrap();

        let snapshot = IsolatedWorkspace::create(root).unwrap();
        assert!(!snapshot.path().join("removed.txt").exists());
        assert!(snapshot.path().join("untracked.txt").exists());
        assert!(!snapshot.path().join("ignored.txt").exists());
        assert!(snapshot.path().join(".gitignore").exists());
        let staged_diff =
            git_output(snapshot.path(), ["diff", "--cached", "--", "tracked.txt"]).unwrap();
        let unstaged_diff = git_output(snapshot.path(), ["diff", "--", "tracked.txt"]).unwrap();
        assert!(String::from_utf8_lossy(&staged_diff.stdout).contains("staged content"));
        assert!(String::from_utf8_lossy(&unstaged_diff.stdout).contains("unstaged content"));
        assert!(
            String::from_utf8_lossy(
                &git_output(snapshot.path(), ["status", "--short"])
                    .unwrap()
                    .stdout
            )
            .contains("untracked.txt")
        );
        fs::write(
            snapshot.path().join("untracked.txt"),
            "check-generated content",
        )
        .unwrap();
        fs::write(snapshot.path().join("tracked.txt"), "candidate update\n").unwrap();
        let patch = String::from_utf8_lossy(
            &snapshot
                .candidate_patch(&[root.join("tracked.txt"), root.join("untracked.txt")])
                .unwrap(),
        )
        .into_owned();
        assert!(patch.contains("untracked.txt"));
        assert!(patch.contains("check-generated content"));
        let patch = patch.into_bytes();
        assert_eq!(
            check_patch_against_live(root, &patch).unwrap(),
            ReconciliationStatus::Applicable
        );
        fs::write(root.join("tracked.txt"), "concurrent local edit\n").unwrap();
        assert!(matches!(
            check_patch_against_live(root, &patch).unwrap(),
            ReconciliationStatus::Conflict(_)
        ));
    }

    #[test]
    fn snapshots_reject_index_flags_that_cannot_be_preserved() {
        let repository = IsolatedWorkspace::create_temp_dir().unwrap();
        let root = repository.path();
        git_output(root, ["init", "-q"]).unwrap();
        git_output(root, ["config", "user.name", "KSP test"]).unwrap();
        git_output(root, ["config", "user.email", "ksp-test@example.invalid"]).unwrap();
        fs::write(root.join("tracked.txt"), "tracked").unwrap();
        git_output(root, ["add", "tracked.txt"]).unwrap();
        git_output(root, ["commit", "-qm", "initial file"]).unwrap();
        git_output(root, ["update-index", "--assume-unchanged", "tracked.txt"]).unwrap();
        assert!(IsolatedWorkspace::create(root).is_err());
    }

    #[tokio::test]
    async fn declared_paths_outside_repository_are_rejected() {
        let manager = manager();
        assert!(
            manager
                .acquire(std::env::temp_dir(), LockMode::Shared)
                .await
                .is_err()
        );
        assert!(
            manager
                .acquire("../../outside-repository", LockMode::Exclusive)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_linked_files_are_rejected_for_path_locking() {
        let base = std::env::temp_dir().join(format!(
            "ksp-gateway-hardlink-test-{}-{}",
            std::process::id(),
            SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&base).unwrap();
        let first = base.join("first.txt");
        let alias = base.join("alias.txt");
        fs::write(&first, "shared inode").unwrap();
        fs::hard_link(&first, &alias).unwrap();
        let manager = FileLockManager::new(&base).unwrap();
        assert!(
            manager
                .acquire("first.txt", LockMode::Exclusive)
                .await
                .is_err()
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_aliases_share_identity_and_external_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "ksp-gateway-path-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("repo");
        let outside = base.join("outside");
        fs::create_dir_all(root.join("real")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        let manager = FileLockManager::new(&root).unwrap();

        let real = manager.resolve_path(Path::new("real/new-file")).unwrap();
        let alias = manager.resolve_path(Path::new("alias/new-file")).unwrap();
        assert_eq!(real, alias);
        assert!(
            manager
                .acquire("escape/secret", LockMode::Shared)
                .await
                .is_err()
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn checks_on_different_paths_run_concurrently_and_keep_input_order() {
        let manager = Arc::new(manager());
        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let checks = vec![
            CheckTask::new(
                "first",
                vec![FileAccess::read("one.rs")],
                move |_| async move {
                    first_barrier.wait().await;
                    Ok(())
                },
            ),
            CheckTask::new(
                "second",
                vec![FileAccess::read("two.rs")],
                move |_| async move {
                    second_barrier.wait().await;
                    Ok(())
                },
            ),
        ];

        let results = tokio::time::timeout(Duration::from_secs(1), run_checks(manager, checks))
            .await
            .expect("independent checks did not overlap");
        assert_eq!(results[0].name, "first");
        assert_eq!(results[1].name, "second");
        assert!(
            results
                .iter()
                .all(|result| result.status == CheckStatus::Passed)
        );
    }

    #[tokio::test]
    async fn conflicting_checks_serialize_and_timeout_releases_locks() {
        let manager = Arc::new(manager());
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let second_started = Arc::new(AtomicBool::new(false));
        let second_started_action = Arc::clone(&second_started);
        let checks = vec![
            CheckTask::new(
                "writer",
                vec![FileAccess::write("same.rs")],
                move |_| async move {
                    let _ = entered_tx.send(());
                    let _ = release_rx.await;
                    Ok(())
                },
            ),
            CheckTask::new(
                "reader",
                vec![FileAccess::read("same.rs")],
                move |_| async move {
                    second_started_action.store(true, Ordering::SeqCst);
                    Ok(())
                },
            ),
        ];
        let run_manager = Arc::clone(&manager);
        let runner = tokio::spawn(async move { run_checks(run_manager, checks).await });
        entered_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!second_started.load(Ordering::SeqCst));
        let _ = release_tx.send(());
        let results = runner.await.unwrap();
        assert!(
            results
                .iter()
                .all(|result| result.status == CheckStatus::Passed)
        );

        let timed_out = CheckTask::new("slow", vec![FileAccess::write("same.rs")], |_| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        })
        .with_timeout(Duration::from_millis(1));
        let results = run_checks(Arc::clone(&manager), vec![timed_out]).await;
        assert_eq!(results[0].status, CheckStatus::TimedOut);
        let lock = tokio::time::timeout(
            Duration::from_secs(1),
            manager.acquire("same.rs", LockMode::Exclusive),
        )
        .await
        .expect("timed out task retained its lock")
        .unwrap();
        assert_eq!(lock.mode(), LockMode::Exclusive);
    }

    #[tokio::test]
    async fn cancelling_a_check_reports_status_and_releases_its_lock() {
        let manager = Arc::new(manager());
        let (started_tx, started_rx) = oneshot::channel();
        let check = CheckTask::new(
            "cancel-me",
            vec![FileAccess::write("src/main.rs")],
            move |_| async move {
                let _ = started_tx.send(());
                std::future::pending::<Result<(), String>>().await
            },
        );
        let cancellation = check.cancellation_handle();
        let run_manager = Arc::clone(&manager);
        let runner = tokio::spawn(async move { run_checks(run_manager, vec![check]).await });

        started_rx.await.unwrap();
        cancellation.cancel();
        let results = runner.await.unwrap();
        assert_eq!(results[0].status, CheckStatus::Cancelled);
        let lock = tokio::time::timeout(
            Duration::from_secs(1),
            manager.acquire("src/main.rs", LockMode::Exclusive),
        )
        .await
        .expect("cancelled check retained its lock")
        .unwrap();
        assert_eq!(lock.mode(), LockMode::Exclusive);
    }

    #[tokio::test]
    async fn reverse_declared_path_orders_do_not_deadlock() {
        let manager = Arc::new(manager());
        let checks = vec![
            CheckTask::new(
                "alpha-first",
                vec![FileAccess::write("alpha"), FileAccess::write("beta")],
                |_| async { Ok(()) },
            ),
            CheckTask::new(
                "beta-first",
                vec![FileAccess::write("beta"), FileAccess::write("alpha")],
                |_| async { Ok(()) },
            ),
        ];
        let results = tokio::time::timeout(Duration::from_secs(1), run_checks(manager, checks))
            .await
            .expect("checks deadlocked while acquiring paths");
        assert!(
            results
                .iter()
                .all(|result| result.status == CheckStatus::Passed)
        );
    }

    #[tokio::test]
    async fn action_errors_and_panics_are_reported_as_failed_checks() {
        let manager = Arc::new(manager());
        let checks = vec![
            CheckTask::new("error", vec![], |_| async { Err("lint failed".to_owned()) }),
            CheckTask::new("panic", vec![], |_| async {
                panic!("unexpected check panic")
            }),
        ];
        let results = run_checks(manager, checks).await;
        assert_eq!(results[0].status, CheckStatus::Failed("lint failed".into()));
        assert!(matches!(results[1].status, CheckStatus::Failed(_)));
        assert_eq!(results[1].name, "panic");
    }
}
