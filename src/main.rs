use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let mut args = std::env::args_os();
        let _binary = args.next();
        if args.next().as_deref() == Some(std::ffi::OsStr::new("__ksp_sandbox_child")) {
            std::process::exit(ksp_gateway::sandbox::child_entry(args));
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("create Tokio runtime");
    runtime.block_on(run_gateway(std::env::args_os().skip(1)))
}

async fn run_gateway(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    match args.next() {
        None => {
            println!("KSP Gateway orchestrator ready");
            ExitCode::SUCCESS
        }
        Some(command) if command == OsStr::new("--help") || command == OsStr::new("-h") => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(command) if command == OsStr::new("capabilities") => print_capabilities(),
        Some(command) if command == OsStr::new("sandbox") => run_sandbox(args).await,
        Some(command) => {
            eprintln!("unknown command: {}", command.to_string_lossy());
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "linux")]
fn print_capabilities() -> ExitCode {
    println!("{:#?}", ksp_gateway::sandbox::HostCapabilities::probe());
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn print_capabilities() -> ExitCode {
    eprintln!("the kernel sandbox is available only on Linux");
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
async fn run_sandbox(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    use std::collections::BTreeSet;

    use ksp_gateway::sandbox::{
        PathAccess, PathRule, SandboxCommand, SandboxPolicy, SocketPolicy, SyscallPolicy,
    };

    let mut workspace = None;
    let mut paths = Vec::new();
    let mut socket_policy = SocketPolicy::Deny;
    let mut socket_policy_selected = false;
    let mut syscall_policy = SyscallPolicy::CompatibilityDenylist;
    let mut syscall_allowlist = BTreeSet::new();
    let mut syscall_policy_selected = false;
    let mut program = None;

    while let Some(option) = args.next() {
        if option == OsStr::new("--") {
            program = args.next();
            break;
        }
        match option.to_str() {
            Some("--workspace") => workspace = args.next().map(PathBuf::from),
            Some("--read") => {
                let Some(path) = args.next() else {
                    eprintln!("--read requires a path");
                    return ExitCode::from(2);
                };
                paths.push(PathRule {
                    path: path.into(),
                    access: PathAccess::ReadOnly,
                });
            }
            Some("--network") => {
                let Some(value) = args.next() else {
                    eprintln!("--network requires 'deny' or 'all'");
                    return ExitCode::from(2);
                };
                if socket_policy_selected {
                    eprintln!("choose only one of --network and --socket-domain");
                    return ExitCode::from(2);
                }
                socket_policy_selected = true;
                socket_policy = match value.to_str() {
                    Some("deny") => SocketPolicy::Deny,
                    Some("all") => SocketPolicy::AllowAll,
                    _ => {
                        eprintln!("--network accepts only 'deny' or 'all'");
                        return ExitCode::from(2);
                    }
                };
            }
            Some("--socket-domain") => {
                let Some(value) = args.next() else {
                    eprintln!("--socket-domain requires unix, inet, or inet6");
                    return ExitCode::from(2);
                };
                if socket_policy_selected
                    && !matches!(&socket_policy, SocketPolicy::AllowDomains(_))
                {
                    eprintln!("choose either --network or --socket-domain");
                    return ExitCode::from(2);
                }
                socket_policy_selected = true;
                let domain = match value.to_str() {
                    Some("unix") => libc::AF_UNIX,
                    Some("inet") => libc::AF_INET,
                    Some("inet6") => libc::AF_INET6,
                    _ => {
                        eprintln!("--socket-domain accepts unix, inet, or inet6");
                        return ExitCode::from(2);
                    }
                };
                match &mut socket_policy {
                    SocketPolicy::Deny => {
                        socket_policy = SocketPolicy::AllowDomains(BTreeSet::from([domain]));
                    }
                    SocketPolicy::AllowDomains(domains) => {
                        domains.insert(domain);
                    }
                    SocketPolicy::AllowAll => unreachable!("conflicting policy rejected above"),
                }
            }
            Some("--allow-syscall") => {
                let Some(value) = args.next() else {
                    eprintln!("--allow-syscall requires a syscall number");
                    return ExitCode::from(2);
                };
                let Ok(number) = value.to_string_lossy().parse::<i64>() else {
                    eprintln!("syscall number must be a non-negative integer");
                    return ExitCode::from(2);
                };
                if syscall_policy_selected
                    && !matches!(&syscall_policy, SyscallPolicy::Allowlist(_))
                {
                    eprintln!("choose either --allow-syscall or --syscall-compat");
                    return ExitCode::from(2);
                }
                syscall_policy_selected = true;
                syscall_allowlist.insert(number);
                syscall_policy = SyscallPolicy::Allowlist(syscall_allowlist.clone());
            }
            Some("--syscall-compat") => {
                if syscall_policy_selected {
                    eprintln!("choose either --allow-syscall or --syscall-compat");
                    return ExitCode::from(2);
                }
                syscall_policy_selected = true;
                syscall_policy = SyscallPolicy::CompatibilityDenylist;
            }
            _ => {
                eprintln!("unknown sandbox option: {}", option.to_string_lossy());
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    let Some(workspace) = workspace else {
        eprintln!("sandbox requires --workspace PATH");
        print_usage();
        return ExitCode::from(2);
    };
    let Some(program) = program else {
        eprintln!("sandbox requires -- PROGRAM [ARGS...]");
        print_usage();
        return ExitCode::from(2);
    };

    let mut policy = SandboxPolicy::workspace_only(workspace);
    policy.paths.extend(paths);
    policy.socket_policy = socket_policy;
    policy.syscall_policy = syscall_policy;

    match SandboxCommand::new(policy, program)
        .args(args)
        .status()
        .await
    {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("sandbox launch failed: {error}");
            ExitCode::from(125)
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_sandbox(_args: impl Iterator<Item = OsString>) -> ExitCode {
    eprintln!("the kernel sandbox is available only on Linux");
    ExitCode::from(2)
}

fn print_usage() {
    println!(
        "KSP Gateway\n\
         Usage:\n\
           ksp-gateway [--help]\n\
           ksp-gateway capabilities\n\
           ksp-gateway sandbox --workspace PATH [OPTIONS] -- PROGRAM [ARGS...]\n\
         Sandbox options:\n\
           --read PATH                       grant an extra read-only path\n\
           --network deny|all                choose socket access (default: deny)\n\
           --socket-domain unix|inet|inet6   allow selected socket domains\n\
           --allow-syscall NUMBER            opt into a target-specific allowlist\n\
           --syscall-compat                  use the default compatibility denylist"
    );
}
