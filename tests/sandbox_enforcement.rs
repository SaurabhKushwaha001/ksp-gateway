#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ksp_gateway::{
    orchestrator::{
        CheckStatus, CheckTask, FileAccess, FileLockManager, IsolatedWorkspace, run_checks,
    },
    sandbox::{PathAccess, PathRule, SandboxCommand, SandboxPolicy, SocketPolicy, SyscallPolicy},
};

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ksp-gateway-sandbox-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temporary test directory");
        Self(path)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn child_gets_workspace_access_but_not_host_files_or_sockets() {
    let temporary = TemporaryDirectory::new();
    let workspace = &temporary.0;
    fs::write(workspace.join("input.txt"), "workspace data").expect("create input in workspace");

    let script = r#"
import socket
import sys

root = sys.argv[1]
with open(root + "/input.txt", "r", encoding="utf-8") as source:
    assert source.read() == "workspace data"
with open(root + "/output.txt", "w", encoding="utf-8") as output:
    output.write("allowed")
try:
    open("/etc/passwd", "r", encoding="utf-8")
except PermissionError:
    pass
else:
    raise AssertionError("Landlock allowed access to /etc/passwd")
try:
    socket.socket()
except PermissionError:
    pass
else:
    raise AssertionError("seccomp allowed socket creation")
"#;

    let helper = env!("CARGO_BIN_EXE_ksp-gateway");
    let status = SandboxCommand::new(SandboxPolicy::workspace_only(workspace), "/usr/bin/python3")
        .args(["-c", script, workspace.to_str().expect("UTF-8 temp path")])
        .helper_executable(helper)
        .status()
        .await
        .expect("launch sandbox helper");

    assert!(status.success(), "sandbox child exited with {status}");
    assert_eq!(
        fs::read_to_string(workspace.join("output.txt")).expect("read child output"),
        "allowed"
    );
    // The caller remains unrestricted; applying the child policy did not
    // constrain the orchestrator process.
    assert!(fs::read("/etc/passwd").is_ok());
}

#[tokio::test]
async fn workspace_symlink_cannot_escape_landlock_boundary() {
    let temporary = TemporaryDirectory::new();
    let workspace = &temporary.0;
    symlink("/etc/passwd", workspace.join("host-file")).expect("create symlink to a host file");

    let script = r#"
import sys

try:
    open(sys.argv[1], "r", encoding="utf-8").read()
except PermissionError:
    pass
else:
    raise AssertionError("Landlock allowed following a workspace symlink outside")
"#;

    let status = SandboxCommand::new(SandboxPolicy::workspace_only(workspace), "/usr/bin/python3")
        .args([
            "-c",
            script,
            workspace
                .join("host-file")
                .to_str()
                .expect("UTF-8 temporary path"),
        ])
        .helper_executable(env!("CARGO_BIN_EXE_ksp-gateway"))
        .status()
        .await
        .expect("launch sandbox helper");

    assert!(status.success(), "sandbox child exited with {status}");
}

#[tokio::test]
async fn explicitly_allowed_network_policy_permits_socket_creation() {
    let temporary = TemporaryDirectory::new();
    let mut policy = SandboxPolicy::workspace_only(&temporary.0);
    policy.socket_policy = SocketPolicy::AllowAll;

    let status = SandboxCommand::new(policy, "/usr/bin/python3")
        .args([
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.close()",
        ])
        .helper_executable(env!("CARGO_BIN_EXE_ksp-gateway"))
        .status()
        .await
        .expect("launch network-enabled sandbox helper");

    assert!(status.success(), "sandbox child exited with {status}");
}

#[tokio::test]
async fn command_line_can_launch_a_sandboxed_command() {
    let temporary = TemporaryDirectory::new();
    let workspace = temporary.0.to_str().expect("UTF-8 temporary path");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_ksp-gateway"))
        .args([
            "sandbox",
            "--workspace",
            workspace,
            "--",
            "/bin/sh",
            "-c",
            "printf cli-ok > cli-result.txt; cat cli-result.txt",
        ])
        .output()
        .await
        .expect("launch sandbox CLI");

    assert!(
        output.status.success(),
        "sandbox CLI exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"cli-ok");
    assert_eq!(
        fs::read_to_string(temporary.0.join("cli-result.txt")).expect("read sandboxed result"),
        "cli-ok"
    );
}

#[tokio::test]
async fn socket_policy_can_allow_unix_domain_but_block_inet_sockets() {
    let temporary = TemporaryDirectory::new();
    let mut policy = SandboxPolicy::workspace_only(&temporary.0);
    policy.socket_policy = SocketPolicy::AllowDomains(BTreeSet::from([libc::AF_UNIX]));
    let script = r#"
import socket

unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
unix_socket.close()
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except PermissionError:
    pass
else:
    raise AssertionError("AF_INET socket was allowed by an AF_UNIX-only policy")
"#;

    let status = SandboxCommand::new(policy, "/usr/bin/python3")
        .args(["-c", script])
        .helper_executable(env!("CARGO_BIN_EXE_ksp-gateway"))
        .status()
        .await
        .expect("launch Unix-domain-only sandbox helper");

    assert!(status.success(), "sandbox child exited with {status}");
}

#[tokio::test]
async fn socket_restricted_policy_rejects_an_inherited_socket_stream() {
    let temporary = TemporaryDirectory::new();
    let (stream, _peer) = UnixStream::pair().expect("create inherited socket pair");

    let status = SandboxCommand::new(SandboxPolicy::workspace_only(&temporary.0), "/bin/true")
        .stdout(Stdio::from(OwnedFd::from(stream)))
        .helper_executable(env!("CARGO_BIN_EXE_ksp-gateway"))
        .status()
        .await
        .expect("launch sandbox helper");

    assert_eq!(status.code(), Some(125));
}

#[tokio::test]
async fn helper_fails_closed_if_a_granted_path_is_replaced_before_it_opens_it() {
    let temporary = TemporaryDirectory::new();
    let workspace = temporary.0.join("workspace");
    let grant = temporary.0.join("source-objects");
    let moved = temporary.0.join("source-objects-original");
    fs::create_dir(&workspace).expect("create workspace");
    fs::create_dir(&grant).expect("create original read-only grant");

    let ready = temporary.0.join("wrapper-ready");
    let proceed = temporary.0.join("wrapper-proceed");
    let wrapper = temporary.0.join("delayed-helper.sh");
    let real_helper = env!("CARGO_BIN_EXE_ksp-gateway");
    let script = format!(
        "#!/bin/sh\ntouch '{}'\nwhile [ ! -e '{}' ]; do sleep 0.01; done\nexec '{}' \"$@\"\n",
        ready.display(),
        proceed.display(),
        real_helper
    );
    fs::write(&wrapper, script).expect("write delayed helper wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))
        .expect("make helper wrapper executable");

    let mut policy = SandboxPolicy::workspace_only(&workspace);
    policy.paths.push(PathRule {
        path: grant.clone(),
        access: PathAccess::ReadOnly,
    });
    let launch = tokio::spawn(async move {
        SandboxCommand::new(policy, "/bin/true")
            .helper_executable(wrapper)
            .status()
            .await
    });

    for _ in 0..200 {
        if ready.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(ready.exists(), "delayed helper did not start");

    fs::rename(&grant, &moved).expect("rename original granted path");
    fs::create_dir(&grant).expect("replace granted path");
    fs::write(grant.join("marker"), "replacement").expect("mark replacement directory");
    fs::write(&proceed, "continue").expect("release delayed helper");

    let status = launch
        .await
        .expect("join sandbox launch task")
        .expect("run sandbox launch");
    assert_eq!(status.code(), Some(125));
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn explicit_syscall_allowlist_rejects_an_unlisted_syscall() {
    let temporary = TemporaryDirectory::new();
    let mut policy = SandboxPolicy::workspace_only(&temporary.0);
    policy.syscall_policy = SyscallPolicy::Allowlist(BTreeSet::from([
        libc::SYS_access,
        libc::SYS_arch_prctl,
        libc::SYS_brk,
        libc::SYS_close,
        libc::SYS_execve,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_newfstatat,
        libc::SYS_openat,
        libc::SYS_pread64,
        libc::SYS_prlimit64,
        libc::SYS_read,
        libc::SYS_rseq,
        libc::SYS_set_robust_list,
        libc::SYS_set_tid_address,
        libc::SYS_write,
    ]));

    let status = SandboxCommand::new(policy, "/usr/bin/uname")
        .arg("-s")
        .helper_executable(env!("CARGO_BIN_EXE_ksp-gateway"))
        .status()
        .await
        .expect("launch strict-allowlist sandbox helper");

    assert!(
        !status.success(),
        "unlisted uname syscall unexpectedly worked"
    );
}

#[tokio::test]
async fn dropping_a_timed_out_launch_kills_its_child() {
    let temporary = TemporaryDirectory::new();
    let helper = env!("CARGO_BIN_EXE_ksp-gateway");
    let child_pid_file = temporary.0.join("descendant.pid");
    let command = SandboxCommand::new(SandboxPolicy::workspace_only(&temporary.0), "/bin/sh")
        .args(["-c", "sleep 10 & echo $! > descendant.pid; wait"])
        .helper_executable(helper);

    let result =
        tokio::time::timeout(std::time::Duration::from_millis(500), command.status()).await;
    assert!(
        result.is_err(),
        "the child unexpectedly exited before timeout"
    );
    let child_pid: u32 = fs::read_to_string(child_pid_file)
        .expect("descendant PID file")
        .trim()
        .parse()
        .expect("numeric descendant PID");

    // A killed process may remain briefly as a zombie until the system reaps it.
    for _ in 0..20 {
        match fs::read_to_string(format!("/proc/{child_pid}/stat")) {
            Ok(stat) => {
                let state = stat
                    .rsplit_once(')')
                    .expect("proc stat command field")
                    .1
                    .trim_start()
                    .chars()
                    .next()
                    .expect("proc stat state");
                if state == 'Z' {
                    return;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                return;
            }
            Err(error) => panic!("read descendant state: {error}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("sandbox cancellation left the descendant process running");
}

#[tokio::test]
async fn sandboxed_git_can_read_snapshot_objects_without_repository_access() {
    let snapshot = IsolatedWorkspace::create(env!("CARGO_MANIFEST_DIR"))
        .expect("create isolated Git snapshot");
    let mut policy = SandboxPolicy::workspace_only(snapshot.path());
    policy.paths.push(PathRule {
        path: snapshot.git_objects_path().to_path_buf(),
        access: PathAccess::ReadOnly,
    });

    let status = SandboxCommand::new(policy, "git")
        .args(["status", "--short"])
        .helper_executable(env!("CARGO_BIN_EXE_ksp-gateway"))
        .status()
        .await
        .expect("launch sandboxed Git");
    assert!(status.success(), "git status exited with {status}");
}

#[tokio::test]
async fn orchestrator_can_run_a_git_check_through_the_sandbox() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manager = Arc::new(FileLockManager::new(root).expect("create lock manager"));
    let check = CheckTask::sandboxed_command_with_helper(
        "sandboxed-git-status",
        vec![FileAccess::read("Cargo.toml")],
        env!("CARGO_BIN_EXE_ksp-gateway"),
        "git",
        ["status", "--short"],
    );

    let results = run_checks(manager, vec![check]).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, CheckStatus::Passed);
}
