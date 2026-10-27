use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ksp_gateway::{
    attestation::{SigningIdentity, TrustStore},
    bouncer::{self, ServerPolicy},
    gateway::{self, GatewayConfig, Subject},
    git::Repository,
    policy::{DEFAULT_POLICY, GatewayPolicy},
    scanner::{ScanLimits, Severity, default_detectors, scan_diff},
};

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
        Some(command) => match command.to_str() {
            Some(
                name @ ("keygen" | "pubkey" | "install" | "install-server" | "hook" | "check"
                | "reattest" | "scan" | "verify-commit" | "pre-receive" | "policy"
                | "bench"),
            ) => {
                let args = args.map(|arg| arg.to_string_lossy().into_owned()).collect();
                match run_command(name, args).await {
                    Ok(code) => code,
                    Err(CliError::Usage(message)) => {
                        eprintln!("ksp-gateway: {message}");
                        eprintln!("run `ksp-gateway --help` for usage");
                        ExitCode::from(2)
                    }
                    Err(CliError::Failed(message)) => {
                        eprintln!("ksp-gateway: {message}");
                        ExitCode::from(1)
                    }
                }
            }
            _ => unknown_command(&command),
        },
    }
}

fn unknown_command(command: &OsStr) -> ExitCode {
    eprintln!("unknown command: {}", command.to_string_lossy());
    print_usage();
    ExitCode::from(2)
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Failed(String),
}

impl<E: std::error::Error> From<E> for CliError {
    fn from(error: E) -> Self {
        Self::Failed(error.to_string())
    }
}

/// Parsed `--flag value`, `--switch`, and positional arguments.
struct Parsed {
    values: BTreeMap<String, Vec<String>>,
    switches: BTreeSet<String>,
    positionals: Vec<String>,
}

impl Parsed {
    fn new(args: Vec<String>, value_flags: &[&str], switches: &[&str]) -> Result<Self, CliError> {
        let mut parsed = Self {
            values: BTreeMap::new(),
            switches: BTreeSet::new(),
            positionals: Vec::new(),
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            if arg == "--" {
                parsed.positionals.extend(args);
                break;
            } else if value_flags.contains(&arg.as_str()) {
                let value = args
                    .next()
                    .ok_or_else(|| CliError::Usage(format!("{arg} requires a value")))?;
                parsed.values.entry(arg).or_default().push(value);
            } else if switches.contains(&arg.as_str()) {
                parsed.switches.insert(arg);
            } else if arg.starts_with("--") {
                return Err(CliError::Usage(format!("unknown option {arg}")));
            } else {
                parsed.positionals.push(arg);
            }
        }
        Ok(parsed)
    }

    fn value(&self, flag: &str) -> Option<&str> {
        self.values
            .get(flag)
            .and_then(|values| values.last())
            .map(String::as_str)
    }

    fn all(&self, flag: &str) -> Vec<String> {
        self.values.get(flag).cloned().unwrap_or_default()
    }

    fn switch(&self, flag: &str) -> bool {
        self.switches.contains(flag)
    }

    fn repo(&self) -> PathBuf {
        PathBuf::from(self.value("--repo").unwrap_or("."))
    }

    fn key(&self) -> PathBuf {
        self.value("--key")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("KSP_GATEWAY_KEY").map(PathBuf::from))
            .unwrap_or_else(gateway::default_key_path)
    }
}

fn server_policy(parsed: &Parsed) -> Result<ServerPolicy, CliError> {
    let keys = parsed
        .value("--trusted-keys")
        .ok_or_else(|| CliError::Usage("--trusted-keys FILE is required".into()))?;
    Ok(ServerPolicy {
        trust: TrustStore::load(Path::new(keys))?,
        required_checks: parsed.all("--require-check").into_iter().collect(),
        allowed_policy_digests: parsed.all("--allow-policy").into_iter().collect(),
    })
}

fn current_executable() -> Result<PathBuf, CliError> {
    Ok(std::fs::canonicalize(std::env::current_exe()?)?)
}

fn staged_subject(repo: &Repository) -> Result<Subject, CliError> {
    Ok(Subject {
        tree: repo.staged_tree()?,
        parents: repo.pending_parents()?,
        diff: repo.staged_diff()?,
    })
}

async fn run_command(name: &str, args: Vec<String>) -> Result<ExitCode, CliError> {
    const SERVER_FLAGS: [&str; 4] = [
        "--trusted-keys",
        "--require-check",
        "--allow-policy",
        "--repo",
    ];
    match name {
        "keygen" => {
            let parsed = Parsed::new(args, &["--key"], &[])?;
            let path = parsed.key();
            let identity = SigningIdentity::generate()?;
            identity.save(&path)?;
            eprintln!("ksp-gateway: wrote signing key {}", path.display());
            eprintln!("ksp-gateway: add this public key to the server's trusted-keys file:");
            println!("{} {}", identity.public_key().to_text(), whoami_label());
            Ok(ExitCode::SUCCESS)
        }
        "pubkey" => {
            let parsed = Parsed::new(args, &["--key"], &[])?;
            let identity = SigningIdentity::load(&parsed.key())?;
            println!("{}", identity.public_key().to_text());
            Ok(ExitCode::SUCCESS)
        }
        "install" => {
            let parsed = Parsed::new(args, &["--repo", "--key", "--policy"], &["--force"])?;
            let repo = Repository::new(Repository::new(parsed.repo()).top_level()?);
            let ksp = gateway::ksp_dir(&repo)?;
            std::fs::create_dir_all(&ksp)?;
            let policy_path = ksp.join("policy.toml");
            let policy_text = match parsed.value("--policy") {
                Some(source) => std::fs::read_to_string(source)?,
                None => std::fs::read_to_string(&policy_path)
                    .unwrap_or_else(|_| DEFAULT_POLICY.to_string()),
            };
            let policy = GatewayPolicy::parse(&policy_text)?;
            std::fs::write(&policy_path, &policy_text)?;
            if let Some(key) = parsed.value("--key") {
                let key = std::path::absolute(key)?;
                std::fs::write(ksp.join("key-path"), format!("{}\n", key.display()))?;
            }
            let hooks =
                gateway::install_hooks(&repo, &current_executable()?, parsed.switch("--force"))?;
            for hook in hooks {
                eprintln!("ksp-gateway: installed {}", hook.display());
            }
            eprintln!("ksp-gateway: policy {}", policy_path.display());
            println!("policy-digest {}", policy.digest);
            Ok(ExitCode::SUCCESS)
        }
        "install-server" => {
            let parsed = Parsed::new(args, &SERVER_FLAGS, &["--force"])?;
            let repo_dir = parsed
                .value("--repo")
                .ok_or_else(|| CliError::Usage("--repo DIR is required".into()))?;
            server_policy(&parsed)?;
            let keys = std::path::absolute(parsed.value("--trusted-keys").unwrap_or_default())?;
            let mut hook_args = vec![
                "--trusted-keys".to_string(),
                keys.to_string_lossy().into_owned(),
            ];
            for check in parsed.all("--require-check") {
                hook_args.extend(["--require-check".into(), check]);
            }
            for digest in parsed.all("--allow-policy") {
                hook_args.extend(["--allow-policy".into(), digest]);
            }
            let hook = gateway::install_server_hook(
                &Repository::new(repo_dir),
                &current_executable()?,
                &hook_args,
                parsed.switch("--force"),
            )?;
            eprintln!("ksp-gateway: installed {}", hook.display());
            Ok(ExitCode::SUCCESS)
        }
        "hook" => {
            let mut args = args.into_iter();
            let config = GatewayConfig::from_environment(".")?;
            match args.next().as_deref() {
                Some("pre-commit") => {
                    let report = gateway::pre_commit(&config).await?;
                    eprint!("{}", report.render());
                    Ok(if report.passed() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    })
                }
                Some("commit-msg") => {
                    let file = args.next().ok_or_else(|| {
                        CliError::Usage("hook commit-msg needs the message file".into())
                    })?;
                    gateway::commit_msg(&config, Path::new(&file))?;
                    Ok(ExitCode::SUCCESS)
                }
                _ => Err(CliError::Usage(
                    "hook expects pre-commit or commit-msg".into(),
                )),
            }
        }
        "check" => {
            let parsed = Parsed::new(args, &["--repo"], &[])?;
            let config = GatewayConfig::from_environment(parsed.repo())?;
            let repo = Repository::new(&config.repo_root);
            let policy = gateway::load_policy(&repo)?;
            let report = gateway::run_pipeline(&config, &policy, &staged_subject(&repo)?).await;
            print!("{}", report.render());
            Ok(if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        "reattest" => {
            let parsed = Parsed::new(args, &["--repo"], &[])?;
            let config = GatewayConfig::from_environment(parsed.repo())?;
            let report = gateway::reattest(&config).await?;
            eprint!("{}", report.render());
            Ok(if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        "scan" => {
            let parsed = Parsed::new(args, &["--repo", "--diff", "--exclude"], &[])?;
            let diff = match parsed.value("--diff") {
                Some("-") => {
                    let mut buffer = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer)?;
                    buffer
                }
                Some(path) => std::fs::read(path)?,
                None => Repository::new(parsed.repo()).staged_diff()?,
            };
            let report = scan_diff(
                &diff,
                &default_detectors(),
                ScanLimits::default(),
                &parsed.all("--exclude"),
            );
            for finding in &report.findings {
                println!("{finding}");
            }
            println!(
                "scanned {} added line(s) in {} ms; {} finding(s)",
                report.lines_scanned,
                report.elapsed.as_millis(),
                report.findings.len()
            );
            Ok(if report.highest_severity() == Some(Severity::Block) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        "verify-commit" => {
            let parsed = Parsed::new(args, &SERVER_FLAGS, &[])?;
            let policy = server_policy(&parsed)?;
            let repo = Repository::new(parsed.repo());
            let revisions = if parsed.positionals.is_empty() {
                vec!["HEAD".to_string()]
            } else {
                parsed.positionals.clone()
            };
            let mut ok = true;
            for revision in revisions {
                let oid = String::from_utf8_lossy(&repo.output([
                    "rev-parse",
                    "--verify",
                    &format!("{revision}^{{commit}}"),
                ])?)
                .trim()
                .to_string();
                match bouncer::verify_commit(&repo, &oid, &policy) {
                    Ok(attestation) => {
                        println!("ok       {} key {}", &oid[..12], attestation.key_id)
                    }
                    Err(rejection) => {
                        ok = false;
                        println!("REJECTED {}: {rejection}", &oid[..12]);
                    }
                }
            }
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        "pre-receive" => {
            let parsed = Parsed::new(args, &SERVER_FLAGS, &[])?;
            let policy = server_policy(&parsed)?;
            let repo = Repository::for_receive_hook(parsed.repo());
            let report = bouncer::run_pre_receive(&repo, &mut std::io::stdin(), &policy);
            for line in report.lines() {
                eprintln!("{line}");
            }
            Ok(if report.accepted() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        "policy" => {
            let parsed = Parsed::new(args, &["--repo"], &["--default"])?;
            if parsed.switch("--default") {
                print!("{DEFAULT_POLICY}");
                return Ok(ExitCode::SUCCESS);
            }
            let repo = Repository::new(parsed.repo());
            let policy = gateway::load_policy(&repo)?;
            println!("policy-digest {}", policy.digest);
            println!("checks {}", policy.check_names().join(" "));
            Ok(ExitCode::SUCCESS)
        }
        "bench" => {
            let parsed = Parsed::new(args, &["--repo", "--iterations"], &[])?;
            let iterations = parsed
                .value("--iterations")
                .map(str::parse::<usize>)
                .transpose()
                .map_err(|_| CliError::Usage("--iterations must be a positive integer".into()))?
                .unwrap_or(50)
                .max(1);
            let config = GatewayConfig::from_environment(parsed.repo())?;
            let repo = Repository::new(&config.repo_root);
            let policy = gateway::load_policy(&repo)?;
            let mut samples = Vec::with_capacity(iterations);
            let mut subject_size = (0, 0);
            for _ in 0..iterations {
                let started = std::time::Instant::now();
                let subject = staged_subject(&repo)?;
                subject_size = (
                    subject.diff.len(),
                    subject.diff.split(|b| *b == b'\n').count(),
                );
                gateway::run_pipeline(&config, &policy, &subject).await;
                samples.push(started.elapsed());
            }
            samples.sort();
            let percentile = |p: usize| samples[((samples.len() - 1) * p) / 100];
            let ms = |d: Duration| d.as_secs_f64() * 1000.0;
            println!("checks: {}", policy.check_names().join(", "));
            println!(
                "staged diff: {} bytes, {} lines; iterations: {iterations}",
                subject_size.0, subject_size.1
            );
            println!(
                "latency ms (git + checks): min {:.2}  median {:.2}  p95 {:.2}  max {:.2}",
                ms(samples[0]),
                ms(percentile(50)),
                ms(percentile(95)),
                ms(samples[samples.len() - 1])
            );
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(CliError::Usage(format!("unknown command {name}"))),
    }
}

fn whoami_label() -> String {
    std::env::var("USER").unwrap_or_else(|_| "developer".into())
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
        "KSP Gateway: zero-trust pre-commit security gateway\n\
         Usage:\n\
           ksp-gateway [--help]\n\
           ksp-gateway keygen [--key PATH]             create an Ed25519 signing key\n\
           ksp-gateway pubkey [--key PATH]             print the public key\n\
           ksp-gateway install [--repo DIR] [--key PATH] [--policy FILE] [--force]\n\
                                                       install pre-commit/commit-msg hooks\n\
           ksp-gateway check [--repo DIR]              run the checks on the staged tree\n\
           ksp-gateway reattest [--repo DIR]           re-check and re-sign HEAD (after amend/rebase)\n\
           ksp-gateway scan [--diff FILE|-] [--exclude PREFIX]...\n\
                                                       scan a diff (default: staged changes)\n\
           ksp-gateway policy [--repo DIR] [--default] show the active policy digest\n\
           ksp-gateway bench [--repo DIR] [--iterations N]\n\
                                                       measure pre-commit latency\n\
           ksp-gateway verify-commit --trusted-keys FILE [SERVER OPTIONS] [REV...]\n\
           ksp-gateway pre-receive --trusted-keys FILE [SERVER OPTIONS]\n\
           ksp-gateway install-server --repo DIR --trusted-keys FILE [SERVER OPTIONS] [--force]\n\
           ksp-gateway hook pre-commit | hook commit-msg FILE   (called by Git)\n\
           ksp-gateway capabilities\n\
           ksp-gateway sandbox --workspace PATH [OPTIONS] -- PROGRAM [ARGS...]\n\
         Server options:\n\
           --require-check NAME              every commit must attest this check\n\
           --allow-policy DIGEST             accept only these gateway policy digests\n\
         Sandbox options:\n\
           --read PATH                       grant an extra read-only path\n\
           --network deny|all                choose socket access (default: deny)\n\
           --socket-domain unix|inet|inet6   allow selected socket domains\n\
           --allow-syscall NUMBER            opt into a target-specific allowlist\n\
           --syscall-compat                  use the default compatibility denylist"
    );
}
