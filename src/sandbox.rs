//! Linux sandbox policy and host capability reporting.
//!
//! Untrusted commands are relaunched in a helper mode before Tokio starts.
//! Restrictions are installed in that single-threaded helper and inherited by
//! the command it execs. The seccomp policy is currently a targeted denylist,
//! not a complete syscall allowlist; unlisted syscalls remain available.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, RestrictionStatus,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// Filesystem access requested by a sandbox policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAccess {
    ReadOnly,
    ReadWrite,
}

/// A filesystem path and the access a child process needs to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    pub path: PathBuf,
    pub access: PathAccess,
}

/// Socket families the child may create. Seccomp can inspect the socket domain
/// passed to `socket`/`socketpair`, but cannot dereference a sockaddr to filter
/// a destination passed to `connect` or `bind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketPolicy {
    Deny,
    AllowDomains(BTreeSet<i32>),
    AllowAll,
}

/// Seccomp syscall policy. `Allowlist` is architecture-specific because Linux
/// syscall numbers differ by target architecture. Include `execve` so the
/// helper can launch the requested command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallPolicy {
    /// Preserve compatibility with ordinary tools using a targeted denylist.
    CompatibilityDenylist,
    /// Permit only the listed syscall numbers.
    Allowlist(BTreeSet<i64>),
}

/// Requested permissions for one untrusted child process.
///
/// Writable paths must stay under `workspace_root`. Read-only paths may be
/// explicitly allowlisted outside it, such as a Git object store. Network
/// access defaults to denied by the initial seccomp policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub workspace_root: PathBuf,
    pub paths: Vec<PathRule>,
    pub socket_policy: SocketPolicy,
    pub syscall_policy: SyscallPolicy,
}

impl SandboxPolicy {
    /// Create a policy that grants read-write access to the workspace only.
    pub fn workspace_only(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            workspace_root: workspace_root.as_ref().to_path_buf(),
            paths: vec![PathRule {
                path: workspace_root.as_ref().to_path_buf(),
                access: PathAccess::ReadWrite,
            }],
            socket_policy: SocketPolicy::Deny,
            syscall_policy: SyscallPolicy::CompatibilityDenylist,
        }
    }

    /// Ensure writable paths stay under the workspace and no grant overlaps
    /// protected credential paths.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.validate_with_protected_paths(&protected_secret_paths()?)
    }

    fn validate_with_protected_paths(
        &self,
        protected_paths: &[PathBuf],
    ) -> Result<(), PolicyError> {
        validate_syscall_policy(&self.syscall_policy)?;
        validate_socket_policy(&self.socket_policy)?;
        let workspace =
            self.workspace_root
                .canonicalize()
                .map_err(|source| PolicyError::InvalidPath {
                    path: self.workspace_root.clone(),
                    source,
                })?;
        if !workspace.is_dir() {
            return Err(PolicyError::WorkspaceNotDirectory(workspace));
        }
        for protected in protected_paths {
            if paths_overlap(&workspace, protected) {
                return Err(PolicyError::ProtectedPathGrant {
                    path: workspace.clone(),
                    protected: protected.clone(),
                });
            }
        }

        let canonical_rules =
            self.paths
                .iter()
                .map(|rule| {
                    Ok(PathRule {
                        path: rule.path.canonicalize().map_err(|source| {
                            PolicyError::InvalidPath {
                                path: rule.path.clone(),
                                source,
                            }
                        })?,
                        access: rule.access,
                    })
                })
                .collect::<Result<Vec<_>, PolicyError>>()?;
        for rule in &canonical_rules {
            if rule.access == PathAccess::ReadWrite && !rule.path.starts_with(&workspace) {
                return Err(PolicyError::PathOutsideWorkspace {
                    path: rule.path.clone(),
                    workspace: workspace.clone(),
                });
            }
            for protected in protected_paths {
                if paths_overlap(&rule.path, protected) {
                    return Err(PolicyError::ProtectedPathGrant {
                        path: rule.path.clone(),
                        protected: protected.clone(),
                    });
                }
            }
        }
        for parent in &canonical_rules {
            if parent.access == PathAccess::ReadWrite
                && let Some(child) = canonical_rules.iter().find(|child| {
                    child.access == PathAccess::ReadOnly && child.path.starts_with(&parent.path)
                })
            {
                return Err(PolicyError::ConflictingAccess {
                    writable_parent: parent.path.clone(),
                    read_only_child: child.path.clone(),
                });
            }
        }
        Ok(())
    }
}

struct ResolvedPathRule {
    path: PathBuf,
    access: PathAccess,
    fd: PathFd,
    identity: PathIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathIdentity {
    device: u64,
    inode: u64,
}

struct ResolvedPolicy {
    workspace_fd: PathFd,
    workspace_identity: PathIdentity,
    paths: Vec<ResolvedPathRule>,
    socket_policy: SocketPolicy,
    syscall_policy: SyscallPolicy,
}

fn resolve_policy(policy: SandboxPolicy) -> Result<ResolvedPolicy, SandboxError> {
    validate_syscall_policy(&policy.syscall_policy).map_err(SandboxError::Policy)?;
    validate_socket_policy(&policy.socket_policy).map_err(SandboxError::Policy)?;
    let workspace_fd = PathFd::new(&policy.workspace_root)
        .map_err(|error| SandboxError::Landlock(error.to_string()))?;
    let workspace_root = path_for_fd(&workspace_fd)?;
    let workspace_identity = identity_for_fd(&workspace_fd)?;
    if !workspace_root.is_dir() {
        return Err(SandboxError::Policy(PolicyError::WorkspaceNotDirectory(
            workspace_root,
        )));
    }
    let protected_paths = protected_secret_paths().map_err(SandboxError::Policy)?;
    if let Some(protected) = protected_paths
        .iter()
        .find(|protected| paths_overlap(&workspace_root, protected))
    {
        return Err(SandboxError::Policy(PolicyError::ProtectedPathGrant {
            path: workspace_root,
            protected: protected.clone(),
        }));
    }

    let mut paths = Vec::with_capacity(policy.paths.len());
    for rule in policy.paths {
        let fd =
            PathFd::new(&rule.path).map_err(|error| SandboxError::Landlock(error.to_string()))?;
        let path = path_for_fd(&fd)?;
        let identity = identity_for_fd(&fd)?;
        if rule.access == PathAccess::ReadWrite && !path.starts_with(&workspace_root) {
            return Err(SandboxError::Policy(PolicyError::PathOutsideWorkspace {
                path,
                workspace: workspace_root,
            }));
        }
        if let Some(protected) = protected_paths
            .iter()
            .find(|protected| paths_overlap(&path, protected))
        {
            return Err(SandboxError::Policy(PolicyError::ProtectedPathGrant {
                path,
                protected: protected.clone(),
            }));
        }
        paths.push(ResolvedPathRule {
            path,
            access: rule.access,
            fd,
            identity,
        });
    }
    for parent in &paths {
        if parent.access == PathAccess::ReadWrite
            && let Some(child) = paths.iter().find(|child| {
                child.access == PathAccess::ReadOnly && child.path.starts_with(&parent.path)
            })
        {
            return Err(SandboxError::Policy(PolicyError::ConflictingAccess {
                writable_parent: parent.path.clone(),
                read_only_child: child.path.clone(),
            }));
        }
    }
    Ok(ResolvedPolicy {
        workspace_fd,
        workspace_identity,
        paths,
        socket_policy: policy.socket_policy,
        syscall_policy: policy.syscall_policy,
    })
}

fn identity_for_fd(fd: &PathFd) -> Result<PathIdentity, SandboxError> {
    // SAFETY: fstat writes to a valid stack-allocated structure and the fd is
    // owned by the PathFd passed to this function.
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd.as_fd().as_raw_fd(), &mut metadata) } != 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    Ok(PathIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn verify_path_identity(
    path: &Path,
    expected: PathIdentity,
    actual: PathIdentity,
) -> Result<(), SandboxError> {
    if expected == actual {
        Ok(())
    } else {
        Err(SandboxError::PathChanged(path.to_path_buf()))
    }
}

fn validate_syscall_policy(policy: &SyscallPolicy) -> Result<(), PolicyError> {
    if let SyscallPolicy::Allowlist(syscalls) = policy {
        if !syscalls.contains(&libc::SYS_execve) {
            return Err(PolicyError::AllowlistMissingExecve);
        }
        if syscalls.iter().any(|syscall| *syscall < 0) {
            return Err(PolicyError::InvalidSyscallNumber);
        }
    }
    Ok(())
}

fn validate_socket_policy(policy: &SocketPolicy) -> Result<(), PolicyError> {
    if let SocketPolicy::AllowDomains(domains) = policy
        && (domains.is_empty() || domains.iter().any(|domain| *domain < 0))
    {
        return Err(PolicyError::InvalidSocketDomains);
    }
    Ok(())
}

fn path_for_fd(fd: &PathFd) -> Result<PathBuf, SandboxError> {
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()));
    std::fs::canonicalize(proc_path).map_err(SandboxError::Io)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn protected_secret_paths() -> Result<Vec<PathBuf>, PolicyError> {
    let home_path = current_home_directory()?;
    protected_secret_paths_for_home(&home_path)
}

fn protected_secret_paths_for_home(home_path: &Path) -> Result<Vec<PathBuf>, PolicyError> {
    let home = home_path
        .canonicalize()
        .map_err(|source| PolicyError::InvalidPath {
            path: home_path.to_path_buf(),
            source,
        })?;
    let mut protected = Vec::with_capacity(4);
    for name in [".ssh", ".aws"] {
        let path = home.join(name);
        // Keep the configured path as well as its resolved target. This
        // protects both a normal credential directory and a symlink to one.
        protected.push(path.clone());
        if let Ok(target) = path.canonicalize() {
            protected.push(target);
        }
    }
    protected.sort();
    protected.dedup();
    Ok(protected)
}

fn current_home_directory() -> Result<PathBuf, PolicyError> {
    // Use the effective UID's passwd entry instead of HOME, which can be
    // overridden by the caller or by repository-controlled command setup.
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buffer = vec![0u8; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: getpwuid_r receives valid output structures and a live buffer.
    let code = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if code != 0 || result.is_null() {
        return Err(PolicyError::HomeDirectory(
            std::io::Error::from_raw_os_error(if code == 0 { libc::ENOENT } else { code }),
        ));
    }
    // SAFETY: a non-null result points into the passwd entry filled above.
    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes();
    Ok(PathBuf::from(OsStr::from_bytes(home)))
}

/// Launch a command through the private helper path so restrictions do not
/// affect the orchestrator or its Tokio worker threads.
pub struct SandboxCommand {
    policy: SandboxPolicy,
    program: OsString,
    args: Vec<OsString>,
    helper_executable: Option<OsString>,
    stdin: std::process::Stdio,
    stdout: std::process::Stdio,
    stderr: std::process::Stdio,
}

impl SandboxCommand {
    pub fn new(policy: SandboxPolicy, program: impl AsRef<OsStr>) -> Self {
        Self {
            policy,
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            helper_executable: None,
            stdin: std::process::Stdio::inherit(),
            stdout: std::process::Stdio::inherit(),
            stderr: std::process::Stdio::inherit(),
        }
    }

    /// Override the helper binary path. Normally the current executable runs
    /// its private helper mode; this is useful when the caller is a test harness.
    pub fn helper_executable(mut self, path: impl AsRef<OsStr>) -> Self {
        self.helper_executable = Some(path.as_ref().to_os_string());
        self
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
        self
    }

    /// Configure standard input. Inherited input is a caller-authorized
    /// capability and is not restricted by Landlock after it is opened.
    pub fn stdin(mut self, stdin: std::process::Stdio) -> Self {
        self.stdin = stdin;
        self
    }

    /// Configure standard output. Inherited output is an intentional data
    /// channel and is not restricted by Landlock after it is opened.
    pub fn stdout(mut self, stdout: std::process::Stdio) -> Self {
        self.stdout = stdout;
        self
    }

    /// Configure standard error. Inherited output is an intentional data
    /// channel and is not restricted by Landlock after it is opened.
    pub fn stderr(mut self, stderr: std::process::Stdio) -> Self {
        self.stderr = stderr;
        self
    }

    /// Run the command. Standard input/output/error are inherited unless
    /// changed with `stdin`, `stdout`, or `stderr`.
    pub async fn status(self) -> Result<ExitStatus, SandboxError> {
        let resolved_policy = resolve_policy(self.policy)?;
        let executable = match self.helper_executable {
            Some(path) => path,
            None => std::env::current_exe()
                .map_err(SandboxError::Io)?
                .into_os_string(),
        };
        let mut command = tokio::process::Command::new(executable);
        command
            .stdin(self.stdin)
            .stdout(self.stdout)
            .stderr(self.stderr);
        command.process_group(0);
        command.arg("__ksp_sandbox_child");
        command
            .arg("--workspace")
            .arg(path_for_fd(&resolved_policy.workspace_fd)?)
            .arg(resolved_policy.workspace_identity.device.to_string())
            .arg(resolved_policy.workspace_identity.inode.to_string());
        match &resolved_policy.socket_policy {
            SocketPolicy::Deny => {
                command.arg("--socket-deny");
            }
            SocketPolicy::AllowAll => {
                command.arg("--socket-all");
            }
            SocketPolicy::AllowDomains(domains) => {
                for domain in domains {
                    command.arg("--socket-domain").arg(domain.to_string());
                }
            }
        }
        match &resolved_policy.syscall_policy {
            SyscallPolicy::CompatibilityDenylist => {
                command.arg("--syscall-compat");
            }
            SyscallPolicy::Allowlist(syscalls) => {
                for syscall in syscalls {
                    command.arg("--syscall-allow").arg(syscall.to_string());
                }
            }
        }
        for rule in &resolved_policy.paths {
            command
                .arg(match rule.access {
                    PathAccess::ReadOnly => "--read",
                    PathAccess::ReadWrite => "--write",
                })
                .arg(&rule.path)
                .arg(rule.identity.device.to_string())
                .arg(rule.identity.inode.to_string());
        }
        command.arg("--").arg(&self.program).args(&self.args);
        let mut child = command.spawn().map_err(SandboxError::Io)?;
        let process_group = child.id().ok_or(SandboxError::MissingChildId)? as libc::pid_t;
        let mut group_guard = ProcessGroupGuard {
            process_group,
            active: true,
        };
        let status = child.wait().await.map_err(SandboxError::Io);
        group_guard.kill_and_disarm();
        status
    }
}

/// Entry point used only by `main` before the Tokio runtime is initialized.
pub fn child_entry(args: impl IntoIterator<Item = OsString>) -> i32 {
    match child_entry_inner(args) {
        Ok(()) => 127,
        Err(error) => {
            eprintln!("KSP sandbox setup failed: {error}");
            125
        }
    }
}

struct ProcessGroupGuard {
    process_group: libc::pid_t,
    active: bool,
}

impl ProcessGroupGuard {
    fn kill_and_disarm(&mut self) {
        self.kill_group();
        self.active = false;
    }

    fn kill_group(&self) {
        // A negative PID targets the helper's dedicated process group.
        // SAFETY: kill receives a process-group ID and a valid signal number.
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.active {
            self.kill_group();
        }
    }
}

fn child_entry_inner(args: impl IntoIterator<Item = OsString>) -> Result<(), SandboxError> {
    let parsed = parse_child_args(args)?;
    let policy = parsed.policy;
    let workspace_identity = parsed.workspace_identity;
    let path_identities = parsed.path_identities;
    close_inherited_descriptors(&policy.socket_policy)?;
    let policy = resolve_policy(policy)?;
    verify_path_identity(
        &path_for_fd(&policy.workspace_fd)?,
        workspace_identity,
        policy.workspace_identity,
    )?;
    if path_identities.len() != policy.paths.len() {
        return Err(SandboxError::InvalidArguments);
    }
    for (rule, expected) in policy.paths.iter().zip(path_identities) {
        verify_path_identity(&rule.path, expected, rule.identity)?;
    }
    // SAFETY: workspace_fd is an open directory descriptor, checked above.
    if unsafe { libc::fchdir(policy.workspace_fd.as_fd().as_raw_fd()) } != 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }

    // Prepare both rule sets before restricting the process. The actual
    // enforcement calls below stay in the required NNP -> Landlock -> seccomp order.
    let socket_policy = policy.socket_policy.clone();
    let syscall_policy = policy.syscall_policy.clone();
    let landlock_ruleset = build_landlock_ruleset(policy)?;
    let seccomp_programs = build_seccomp_programs(&syscall_policy, &socket_policy)?;

    set_no_new_privileges()?;
    let status = landlock_ruleset
        .no_new_privs(false)
        .restrict_self()
        .map_err(|error| SandboxError::Landlock(error.to_string()))?;
    ensure_fully_enforced(status)?;
    for program in &seccomp_programs {
        apply_seccomp_filter(program)?;
    }

    let mut command = Command::new(parsed.program);
    command
        .args(parsed.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("LANG", "C");
    let error = command.exec();
    Err(SandboxError::Io(error))
}

struct ParsedChildArgs {
    policy: SandboxPolicy,
    workspace_identity: PathIdentity,
    path_identities: Vec<PathIdentity>,
    program: OsString,
    args: Vec<OsString>,
}

fn parse_child_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<ParsedChildArgs, SandboxError> {
    let mut args = args.into_iter();
    let mut workspace_root = None;
    let mut workspace_identity = None;
    let mut paths = Vec::new();
    let mut path_identities = Vec::new();
    let mut socket_policy = SocketPolicy::Deny;
    let mut socket_policy_seen = false;
    let mut syscall_policy = SyscallPolicy::CompatibilityDenylist;
    let mut syscall_allowlist = BTreeSet::new();
    let mut syscall_policy_seen = false;
    let mut program = None;

    while let Some(option) = args.next() {
        if option == OsStr::new("--") {
            program = args.next();
            break;
        }
        match option.to_str() {
            Some("--workspace") => {
                workspace_root = args.next().map(PathBuf::from);
                workspace_identity = Some(parse_identity(&mut args)?);
            }
            Some("--read") | Some("--write") => {
                let access = if option == OsStr::new("--read") {
                    PathAccess::ReadOnly
                } else {
                    PathAccess::ReadWrite
                };
                paths.push(PathRule {
                    path: args.next().ok_or(SandboxError::InvalidArguments)?.into(),
                    access,
                });
                path_identities.push(parse_identity(&mut args)?);
            }
            Some("--socket-deny") => {
                if socket_policy_seen {
                    return Err(SandboxError::InvalidArguments);
                }
                socket_policy_seen = true;
                socket_policy = SocketPolicy::Deny;
            }
            Some("--socket-all") => {
                if socket_policy_seen {
                    return Err(SandboxError::InvalidArguments);
                }
                socket_policy_seen = true;
                socket_policy = SocketPolicy::AllowAll;
            }
            Some("--socket-domain") => {
                if !socket_policy_seen {
                    socket_policy_seen = true;
                    socket_policy = SocketPolicy::AllowDomains(BTreeSet::new());
                }
                let domain = args
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse::<i32>().ok()))
                    .ok_or(SandboxError::InvalidArguments)?;
                let SocketPolicy::AllowDomains(domains) = &mut socket_policy else {
                    return Err(SandboxError::InvalidArguments);
                };
                domains.insert(domain);
            }
            Some("--syscall-compat") => {
                if syscall_policy_seen {
                    return Err(SandboxError::InvalidArguments);
                }
                syscall_policy_seen = true;
                syscall_policy = SyscallPolicy::CompatibilityDenylist;
            }
            Some("--syscall-allow") => {
                if !syscall_policy_seen {
                    syscall_policy_seen = true;
                    syscall_policy = SyscallPolicy::Allowlist(BTreeSet::new());
                }
                if !matches!(&syscall_policy, SyscallPolicy::Allowlist(_)) {
                    return Err(SandboxError::InvalidArguments);
                }
                let syscall = args
                    .next()
                    .and_then(|value| value.to_str().and_then(|value| value.parse::<i64>().ok()))
                    .ok_or(SandboxError::InvalidArguments)?;
                syscall_allowlist.insert(syscall);
            }
            _ => return Err(SandboxError::InvalidArguments),
        }
    }

    let program = program.ok_or(SandboxError::InvalidArguments)?;
    if matches!(&syscall_policy, SyscallPolicy::Allowlist(_)) {
        syscall_policy = SyscallPolicy::Allowlist(syscall_allowlist);
    }
    let policy = SandboxPolicy {
        workspace_root: workspace_root.ok_or(SandboxError::InvalidArguments)?,
        paths,
        socket_policy,
        syscall_policy,
    };
    Ok(ParsedChildArgs {
        policy,
        workspace_identity: workspace_identity.ok_or(SandboxError::InvalidArguments)?,
        path_identities,
        program,
        args: args.collect(),
    })
}

fn parse_identity(args: &mut impl Iterator<Item = OsString>) -> Result<PathIdentity, SandboxError> {
    let mut parse_number = || {
        args.next()
            .and_then(|value| value.to_str().and_then(|value| value.parse::<u64>().ok()))
            .ok_or(SandboxError::InvalidArguments)
    };
    Ok(PathIdentity {
        device: parse_number()?,
        inode: parse_number()?,
    })
}

fn build_landlock_ruleset(
    policy: ResolvedPolicy,
) -> Result<landlock::RulesetCreated, SandboxError> {
    // ABI V6 is required so write/truncate and device ioctl access are handled.
    // Older kernels fail closed instead of silently leaving newer rights open.
    const ABI: ABI = ABI::V6;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI))
        .map_err(|error| SandboxError::Landlock(error.to_string()))?
        .set_compatibility(CompatLevel::HardRequirement)
        .create()
        .map_err(|error| SandboxError::Landlock(error.to_string()))?;

    let mut read_only_paths = runtime_read_only_paths()?;
    let mut read_write_paths = Vec::new();
    for rule in policy.paths {
        match rule.access {
            PathAccess::ReadOnly => read_only_paths.push((rule.path, rule.fd)),
            PathAccess::ReadWrite => read_write_paths.push((rule.path, rule.fd)),
        }
    }
    read_only_paths.sort_by(|left, right| left.0.cmp(&right.0));
    read_only_paths.dedup_by(|left, right| left.0 == right.0);

    for (path, fd) in read_only_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                fd,
                access_for_path(&path, PathAccess::ReadOnly),
            ))
            .map_err(|error| SandboxError::Landlock(error.to_string()))?;
    }
    // POSIX shells commonly redirect background-job stdin to /dev/null.
    // Granting this one harmless device avoids needing broader /dev access.
    let null_path = Path::new("/dev/null")
        .canonicalize()
        .map_err(SandboxError::Io)?;
    let null_fd =
        PathFd::new(&null_path).map_err(|error| SandboxError::Landlock(error.to_string()))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(
            null_fd,
            access_for_path(&null_path, PathAccess::ReadWrite),
        ))
        .map_err(|error| SandboxError::Landlock(error.to_string()))?;
    for (path, fd) in read_write_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                fd,
                access_for_path(&path, PathAccess::ReadWrite),
            ))
            .map_err(|error| SandboxError::Landlock(error.to_string()))?;
    }
    Ok(ruleset)
}

fn access_for_path(path: &Path, access: PathAccess) -> landlock::BitFlags<AccessFs> {
    const ABI: ABI = ABI::V6;
    if path.is_dir() {
        match access {
            PathAccess::ReadOnly => AccessFs::from_read(ABI),
            PathAccess::ReadWrite => AccessFs::from_all(ABI),
        }
    } else {
        let file_access = AccessFs::from_file(ABI);
        match access {
            PathAccess::ReadOnly => file_access & AccessFs::from_read(ABI),
            PathAccess::ReadWrite => file_access,
        }
    }
}

fn runtime_read_only_paths() -> Result<Vec<(PathBuf, PathFd)>, SandboxError> {
    let paths = [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
    ]
    .into_iter()
    .filter_map(|path| Path::new(path).canonicalize().ok())
    .collect::<Vec<_>>();
    let mut opened = Vec::with_capacity(paths.len());
    for path in paths {
        let fd = PathFd::new(&path).map_err(|error| SandboxError::Landlock(error.to_string()))?;
        opened.push((path, fd));
    }
    Ok(opened)
}

fn build_seccomp_programs(
    syscall_policy: &SyscallPolicy,
    socket_policy: &SocketPolicy,
) -> Result<Vec<BpfProgram>, SandboxError> {
    let architecture = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|error| SandboxError::Seccomp(error.to_string()))?;
    let mut programs = Vec::new();
    match syscall_policy {
        SyscallPolicy::CompatibilityDenylist => {
            let mut denied_syscalls = vec![
                libc::SYS_ptrace,
                libc::SYS_process_vm_readv,
                libc::SYS_process_vm_writev,
                libc::SYS_pidfd_getfd,
                libc::SYS_name_to_handle_at,
                libc::SYS_open_by_handle_at,
                libc::SYS_mount,
                libc::SYS_umount2,
                libc::SYS_pivot_root,
                libc::SYS_unshare,
                libc::SYS_setns,
                libc::SYS_setsid,
                libc::SYS_setpgid,
                libc::SYS_bpf,
                libc::SYS_perf_event_open,
                libc::SYS_kexec_load,
                libc::SYS_init_module,
                libc::SYS_finit_module,
                libc::SYS_delete_module,
                libc::SYS_keyctl,
                libc::SYS_add_key,
                libc::SYS_request_key,
                libc::SYS_userfaultfd,
                libc::SYS_io_uring_setup,
                libc::SYS_io_uring_enter,
                libc::SYS_io_uring_register,
            ];
            if matches!(socket_policy, SocketPolicy::Deny) {
                denied_syscalls.extend(network_syscalls());
            }
            let rules = denied_syscalls
                .into_iter()
                .map(|syscall| (syscall, Vec::new()))
                .collect();
            programs.push(compile_filter(
                rules,
                SeccompAction::Allow,
                SeccompAction::Errno(libc::EPERM as u32),
                architecture,
            )?);

            if let SocketPolicy::AllowDomains(domains) = socket_policy {
                let conditions = domains
                    .iter()
                    .map(|domain| {
                        SeccompCondition::new(
                            0,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Ne,
                            *domain as u64,
                        )
                        .map_err(|error| SandboxError::Seccomp(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let rule = SeccompRule::new(conditions)
                    .map_err(|error| SandboxError::Seccomp(error.to_string()))?;
                let rules = [libc::SYS_socket, libc::SYS_socketpair]
                    .into_iter()
                    .map(|syscall| (syscall, vec![rule.clone()]))
                    .collect();
                programs.push(compile_filter(
                    rules,
                    SeccompAction::Allow,
                    SeccompAction::Errno(libc::EPERM as u32),
                    architecture,
                )?);
            }
        }
        SyscallPolicy::Allowlist(allowlist) => {
            let mut rules = allowlist
                .iter()
                .copied()
                .map(|syscall| (syscall, Vec::new()))
                .collect::<BTreeMap<_, _>>();
            match socket_policy {
                SocketPolicy::Deny => {
                    for syscall in network_syscalls() {
                        rules.remove(&syscall);
                    }
                }
                SocketPolicy::AllowDomains(domains) => {
                    let conditions = domains
                        .iter()
                        .map(|domain| {
                            SeccompCondition::new(
                                0,
                                SeccompCmpArgLen::Dword,
                                SeccompCmpOp::Eq,
                                *domain as u64,
                            )
                            .map_err(|error| SandboxError::Seccomp(error.to_string()))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let domain_rules = conditions
                        .into_iter()
                        .map(|condition| {
                            SeccompRule::new(vec![condition])
                                .map_err(|error| SandboxError::Seccomp(error.to_string()))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for syscall in [libc::SYS_socket, libc::SYS_socketpair] {
                        if rules.contains_key(&syscall) {
                            rules.insert(syscall, domain_rules.clone());
                        }
                    }
                }
                SocketPolicy::AllowAll => {}
            }
            programs.push(compile_filter(
                rules,
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                architecture,
            )?);
        }
    }

    Ok(programs)
}

fn compile_filter(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    mismatch_action: SeccompAction,
    match_action: SeccompAction,
    architecture: TargetArch,
) -> Result<BpfProgram, SandboxError> {
    let filter = SeccompFilter::new(rules, mismatch_action, match_action, architecture)
        .map_err(|error| SandboxError::Seccomp(error.to_string()))?;
    BpfProgram::try_from(filter).map_err(|error| SandboxError::Seccomp(error.to_string()))
}

fn network_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
    ]
}

fn set_no_new_privileges() -> Result<(), SandboxError> {
    // SAFETY: prctl receives the documented PR_SET_NO_NEW_PRIVS arguments.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(SandboxError::NoNewPrivileges(
            std::io::Error::last_os_error(),
        ))
    }
}

fn close_inherited_descriptors(socket_policy: &SocketPolicy) -> Result<(), SandboxError> {
    if !matches!(socket_policy, SocketPolicy::AllowAll) {
        let mut socket_fds = Vec::new();
        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            // SAFETY: fstat writes metadata to a valid stack-allocated structure.
            let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
            // SAFETY: fd is one of the standard descriptor numbers.
            if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                return Err(SandboxError::Io(error));
            }
            if (metadata.st_mode & libc::S_IFMT) == libc::S_IFSOCK {
                socket_fds.push(fd);
            }
        }
        if let Some(first_socket) = socket_fds.first().copied() {
            // Close every inherited socket before the setup error is reported;
            // in particular, do not print the error text through a socket on
            // standard error.
            for fd in socket_fds {
                // SAFETY: these are the helper's standard descriptors identified
                // by fstat above as sockets, and the helper owns these copies.
                unsafe {
                    libc::close(fd);
                }
            }
            return Err(SandboxError::InheritedSocket(first_socket));
        }
    }
    // The helper starts before Tokio and has no application-owned descriptors
    // that need preserving. Drop ambient descriptors above standard I/O.
    // SAFETY: close_range receives a valid inclusive descriptor range.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if result == 0 {
        Ok(())
    } else {
        Err(SandboxError::Io(std::io::Error::last_os_error()))
    }
}

fn apply_seccomp_filter(program: &BpfProgram) -> Result<(), SandboxError> {
    if program.is_empty() {
        return Err(SandboxError::Seccomp(
            "refusing to install an empty filter".into(),
        ));
    }
    let len = u16::try_from(program.len())
        .map_err(|_| SandboxError::Seccomp("BPF program exceeds kernel length limit".into()))?;
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const seccompiler::sock_filter,
    }
    let filter = SockFprog {
        len,
        filter: program.as_ptr(),
    };
    // Use seccompiler for BPF generation, then install the verified program
    // directly. Its convenience installer repeats PR_SET_NO_NEW_PRIVS; the
    // direct syscall keeps the requested NNP -> Landlock -> seccomp sequence
    // explicit and performs no extra privilege-state transition.
    // SAFETY: SockFprog has the Linux `sock_fprog` C layout and both it and the
    // BPF instructions remain alive until the kernel copies the program.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &filter,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(SandboxError::Seccomp(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn ensure_fully_enforced(status: RestrictionStatus) -> Result<(), SandboxError> {
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(SandboxError::IncompleteLandlock(status));
    }
    // Landlock was configured not to repeat PR_SET_NO_NEW_PRIVS because the
    // helper already applied it explicitly as the first enforcement step.
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no additional pointer arguments.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privileges == 1 {
        Ok(())
    } else if no_new_privileges < 0 {
        Err(SandboxError::NoNewPrivileges(
            std::io::Error::last_os_error(),
        ))
    } else {
        Err(SandboxError::NoNewPrivileges(std::io::Error::other(
            "PR_GET_NO_NEW_PRIVS reported disabled",
        )))
    }
}

#[derive(Debug)]
pub enum SandboxError {
    InvalidArguments,
    Policy(PolicyError),
    Io(std::io::Error),
    Landlock(String),
    Seccomp(String),
    NoNewPrivileges(std::io::Error),
    IncompleteLandlock(RestrictionStatus),
    InheritedSocket(i32),
    PathChanged(PathBuf),
    MissingChildId,
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArguments => write!(f, "invalid private sandbox helper arguments"),
            Self::Policy(error) => write!(f, "invalid sandbox policy: {error}"),
            Self::Io(error) => write!(f, "sandbox process I/O error: {error}"),
            Self::Landlock(error) => write!(f, "Landlock setup failed: {error}"),
            Self::Seccomp(error) => write!(f, "seccomp setup failed: {error}"),
            Self::NoNewPrivileges(error) => {
                write!(f, "PR_SET_NO_NEW_PRIVS failed: {error}")
            }
            Self::IncompleteLandlock(status) => {
                write!(f, "Landlock did not report full enforcement: {status:?}")
            }
            Self::InheritedSocket(fd) => write!(
                f,
                "socket-restricted child cannot inherit socket file descriptor {fd}"
            ),
            Self::PathChanged(path) => write!(
                f,
                "sandbox path identity changed between gateway resolution and helper opening: {}",
                path.display()
            ),
            Self::MissingChildId => {
                write!(f, "sandbox helper exited before its PID was available")
            }
        }
    }
}

impl std::error::Error for SandboxError {}

/// A preflight observation, not proof that restrictions can be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    pub landlock: LandlockProbe,
    /// Whether seccompiler can build filters for this target architecture.
    /// This does not prove that a filter can be installed in a child process.
    pub seccomp_arch_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandlockProbe {
    RulesetCreationAvailable,
    Unavailable { detail: String },
}

impl HostCapabilities {
    pub fn probe() -> Self {
        // Create, but do not install, a ruleset. HardRequirement prevents a
        // best-effort no-op from being mistaken for kernel support.
        let landlock = match Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V6))
            .and_then(|ruleset| {
                ruleset
                    .set_compatibility(CompatLevel::HardRequirement)
                    .create()
            }) {
            Ok(_ruleset) => LandlockProbe::RulesetCreationAvailable,
            Err(error) => LandlockProbe::Unavailable {
                detail: error.to_string(),
            },
        };
        let seccomp_arch_supported =
            matches!(std::env::consts::ARCH, "x86_64" | "aarch64" | "riscv64");
        Self {
            landlock,
            seccomp_arch_supported,
        }
    }
}

#[derive(Debug)]
pub enum PolicyError {
    InvalidPath {
        path: PathBuf,
        source: std::io::Error,
    },
    WorkspaceNotDirectory(PathBuf),
    HomeDirectory(std::io::Error),
    PathOutsideWorkspace {
        path: PathBuf,
        workspace: PathBuf,
    },
    ConflictingAccess {
        writable_parent: PathBuf,
        read_only_child: PathBuf,
    },
    ProtectedPathGrant {
        path: PathBuf,
        protected: PathBuf,
    },
    AllowlistMissingExecve,
    InvalidSyscallNumber,
    InvalidSocketDomains,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath { path, source } => {
                write!(f, "cannot resolve policy path {}: {source}", path.display())
            }
            Self::WorkspaceNotDirectory(path) => {
                write!(f, "workspace root is not a directory: {}", path.display())
            }
            Self::HomeDirectory(error) => {
                write!(
                    f,
                    "cannot determine the current user's home directory: {error}"
                )
            }
            Self::PathOutsideWorkspace { path, workspace } => write!(
                f,
                "policy path {} is outside workspace {}",
                path.display(),
                workspace.display()
            ),
            Self::ConflictingAccess {
                writable_parent,
                read_only_child,
            } => write!(
                f,
                "read-only path {} is inside writable path {}; Landlock cannot revoke the parent's access",
                read_only_child.display(),
                writable_parent.display()
            ),
            Self::ProtectedPathGrant { path, protected } => write!(
                f,
                "sandbox path {} overlaps protected credential path {}",
                path.display(),
                protected.display()
            ),
            Self::AllowlistMissingExecve => {
                write!(
                    f,
                    "syscall allowlist must include execve to launch the command"
                )
            }
            Self::InvalidSyscallNumber => write!(f, "syscall numbers must be non-negative"),
            Self::InvalidSocketDomains => {
                write!(
                    f,
                    "socket domain allowlist must be non-empty and non-negative"
                )
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_only_policy_validates() {
        let root = std::env::current_dir().expect("current directory");
        SandboxPolicy::workspace_only(root).validate().unwrap();
    }

    #[test]
    fn policy_rejects_a_writable_path_outside_workspace() {
        let root = std::env::current_dir().expect("current directory");
        let outside = root.parent().expect("parent directory").to_path_buf();
        let policy = SandboxPolicy {
            workspace_root: root,
            paths: vec![PathRule {
                path: outside,
                access: PathAccess::ReadWrite,
            }],
            socket_policy: SocketPolicy::Deny,
            syscall_policy: SyscallPolicy::CompatibilityDenylist,
        };
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::PathOutsideWorkspace { .. })
        ));
    }

    #[test]
    fn policy_allows_an_explicit_external_read_only_path() {
        let root = std::env::current_dir().expect("current directory");
        let policy = SandboxPolicy {
            workspace_root: root,
            paths: vec![PathRule {
                path: PathBuf::from("/usr"),
                access: PathAccess::ReadOnly,
            }],
            socket_policy: SocketPolicy::Deny,
            syscall_policy: SyscallPolicy::CompatibilityDenylist,
        };
        policy.validate().unwrap();
    }

    #[test]
    fn policy_rejects_a_read_only_child_under_a_writable_parent() {
        let root = std::env::current_dir().expect("current directory");
        let policy = SandboxPolicy {
            workspace_root: root.clone(),
            paths: vec![
                PathRule {
                    path: root,
                    access: PathAccess::ReadWrite,
                },
                PathRule {
                    path: std::env::current_dir()
                        .expect("current directory")
                        .join("src"),
                    access: PathAccess::ReadOnly,
                },
            ],
            socket_policy: SocketPolicy::Deny,
            syscall_policy: SyscallPolicy::CompatibilityDenylist,
        };
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::ConflictingAccess { .. })
        ));
    }

    #[test]
    fn policy_never_grants_a_user_home_containing_secret_directories() {
        let home = current_home_directory().expect("passwd home directory");
        let policy = SandboxPolicy::workspace_only(home);
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::ProtectedPathGrant { .. })
        ));
    }

    #[test]
    fn strict_allowlist_must_include_execve() {
        let root = std::env::current_dir().expect("current directory");
        let mut policy = SandboxPolicy::workspace_only(root);
        policy.syscall_policy = SyscallPolicy::Allowlist(BTreeSet::from([libc::SYS_read]));
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::AllowlistMissingExecve)
        ));
    }

    #[test]
    fn socket_domain_allowlist_must_not_be_empty() {
        let root = std::env::current_dir().expect("current directory");
        let mut policy = SandboxPolicy::workspace_only(root);
        policy.socket_policy = SocketPolicy::AllowDomains(BTreeSet::new());
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::InvalidSocketDomains)
        ));
    }

    #[test]
    fn policy_rejects_credential_grants_and_symlinks_to_credential_storage() {
        use std::os::unix::fs::symlink;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let fake_home = std::env::temp_dir().join(format!(
            "ksp-gateway-credential-policy-{}-{nonce}",
            std::process::id()
        ));
        let aws = fake_home.join(".aws");
        let ssh_target = fake_home.join("credential-store");
        std::fs::create_dir_all(&aws).expect("create fake AWS credentials directory");
        std::fs::create_dir_all(&ssh_target).expect("create credential store target");
        symlink(&ssh_target, fake_home.join(".ssh")).expect("link .ssh to credential store");
        let protected = protected_secret_paths_for_home(&fake_home).expect("resolve fake secrets");
        let workspace = std::env::current_dir().expect("current directory");

        for grant in [&aws, &fake_home.join(".ssh")] {
            let policy = SandboxPolicy {
                workspace_root: workspace.clone(),
                paths: vec![PathRule {
                    path: grant.to_path_buf(),
                    access: PathAccess::ReadOnly,
                }],
                socket_policy: SocketPolicy::Deny,
                syscall_policy: SyscallPolicy::CompatibilityDenylist,
            };
            assert!(matches!(
                policy.validate_with_protected_paths(&protected),
                Err(PolicyError::ProtectedPathGrant { .. })
            ));
        }

        std::fs::remove_dir_all(fake_home).expect("remove fake credential tree");
    }

    #[test]
    fn resolved_read_only_grant_keeps_opened_directory_after_path_replacement() {
        use std::os::unix::fs::MetadataExt;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ksp-gateway-path-replacement-{}-{nonce}",
            std::process::id()
        ));
        let workspace = root.join("workspace");
        let grant = root.join("objects");
        let moved = root.join("objects-original");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        std::fs::create_dir(&grant).expect("create original grant directory");
        std::fs::write(grant.join("marker"), "original").expect("mark original grant");

        let policy = SandboxPolicy {
            workspace_root: workspace.clone(),
            paths: vec![PathRule {
                path: grant.clone(),
                access: PathAccess::ReadOnly,
            }],
            socket_policy: SocketPolicy::Deny,
            syscall_policy: SyscallPolicy::CompatibilityDenylist,
        };
        let resolved = resolve_policy(policy).expect("open policy paths");
        std::fs::rename(&grant, &moved).expect("rename original grant path");
        std::fs::create_dir(&grant).expect("replace grant pathname");
        std::fs::write(grant.join("marker"), "replacement").expect("mark replacement");

        let opened_path = path_for_fd(&resolved.paths[0].fd).expect("resolve retained descriptor");
        let opened_inode = std::fs::metadata(&opened_path)
            .expect("stat retained directory")
            .ino();
        let original_inode = std::fs::metadata(&moved)
            .expect("stat renamed original directory")
            .ino();
        let replacement_inode = std::fs::metadata(&grant)
            .expect("stat replacement directory")
            .ino();

        assert_eq!(opened_inode, original_inode);
        assert_ne!(opened_inode, replacement_inode);

        let replacement_policy = SandboxPolicy {
            workspace_root: workspace,
            paths: vec![PathRule {
                path: grant.clone(),
                access: PathAccess::ReadOnly,
            }],
            socket_policy: SocketPolicy::Deny,
            syscall_policy: SyscallPolicy::CompatibilityDenylist,
        };
        let replacement_resolved =
            resolve_policy(replacement_policy).expect("open replaced grant path");
        assert!(matches!(
            verify_path_identity(
                &grant,
                resolved.paths[0].identity,
                replacement_resolved.paths[0].identity
            ),
            Err(SandboxError::PathChanged(_))
        ));

        drop(replacement_resolved);
        drop(resolved);
        std::fs::remove_dir_all(root).expect("remove path-replacement test tree");
    }

    #[test]
    fn capability_probe_reports_landlock_without_enforcing_it() {
        let capabilities = HostCapabilities::probe();
        assert!(matches!(
            capabilities.landlock,
            LandlockProbe::RulesetCreationAvailable | LandlockProbe::Unavailable { .. }
        ));
    }
}
