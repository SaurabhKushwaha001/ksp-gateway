//! The local gateway policy: which checks run before a commit is attested.
//!
//! The policy is stored in the Git directory (`.git/ksp/policy.toml`), not in
//! the tracked tree, so a cloned repository cannot weaken the checks that run
//! on it. Its SHA-256 digest is signed into every attestation so a server can
//! accept only approved policies.

use std::{collections::BTreeSet, fmt, path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::attestation::{is_valid_check_name, sha256_hex};

/// Name of the built-in agent-targeting text check.
pub const SEMANTIC_CHECK: &str = "semantic-scan";
/// Name of the built-in committed-secret check.
pub const SECRET_CHECK: &str = "secret-scan";

/// Policy used when no policy file is installed.
pub const DEFAULT_POLICY: &str = r#"# KSP Gateway policy. Installed in .git/ksp/policy.toml; not tracked by Git.
version = 1

[scanner]
enabled = true
# Diffs larger than this fail closed.
max_diff_bytes = 4194304
# Repository path prefixes the scanner skips (for example test fixtures).
exclude_paths = []
# Treat warnings as blocking findings.
block_on_warnings = false

# Sandboxed command checks run against the staged snapshot. Example:
# [[check]]
# name = "unit-tests"
# command = ["cargo", "test", "--offline"]
# timeout_secs = 300
# network = "deny"          # deny | unix | all
# read_paths = ["/home/me/.cargo", "/home/me/.rustup"]
"#;

/// Socket access granted to a sandboxed check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAccess {
    #[default]
    Deny,
    Unix,
    All,
}

/// Built-in scanner settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScannerPolicy {
    pub enabled: bool,
    pub max_diff_bytes: usize,
    pub exclude_paths: Vec<String>,
    pub block_on_warnings: bool,
}

impl Default for ScannerPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_diff_bytes: 4 * 1024 * 1024,
            exclude_paths: Vec::new(),
            block_on_warnings: false,
        }
    }
}

/// One sandboxed command check.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCheck {
    pub name: String,
    pub command: Vec<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub network: NetworkAccess,
    #[serde(default)]
    pub read_paths: Vec<PathBuf>,
}

fn default_timeout_secs() -> u64 {
    120
}

impl CommandCheck {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    scanner: ScannerPolicy,
    #[serde(default, rename = "check")]
    checks: Vec<CommandCheck>,
}

/// A parsed, validated policy and the digest of its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPolicy {
    pub scanner: ScannerPolicy,
    pub checks: Vec<CommandCheck>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid gateway policy: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

impl GatewayPolicy {
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile =
            toml::from_str(text).map_err(|error| PolicyError(error.message().to_string()))?;
        if file.version != 1 {
            return Err(PolicyError(format!(
                "unsupported policy version {}",
                file.version
            )));
        }
        let mut names = BTreeSet::from([SEMANTIC_CHECK, SECRET_CHECK]);
        for check in &file.checks {
            if !is_valid_check_name(&check.name) {
                return Err(PolicyError(format!(
                    "check name '{}' must use letters, digits, '-', '_' or '.'",
                    check.name
                )));
            }
            if check.name == SEMANTIC_CHECK || check.name == SECRET_CHECK {
                return Err(PolicyError(format!(
                    "check name '{}' is reserved for a built-in check",
                    check.name
                )));
            }
            if !names.insert(check.name.as_str()) {
                return Err(PolicyError(format!(
                    "duplicate check name '{}'",
                    check.name
                )));
            }
            if check
                .command
                .first()
                .is_none_or(|program| program.is_empty())
            {
                return Err(PolicyError(format!(
                    "check '{}' needs a non-empty command",
                    check.name
                )));
            }
            if !(1..=3600).contains(&check.timeout_secs) {
                return Err(PolicyError(format!(
                    "check '{}' timeout must be 1..=3600 seconds",
                    check.name
                )));
            }
            if let Some(path) = check.read_paths.iter().find(|path| !path.is_absolute()) {
                return Err(PolicyError(format!(
                    "check '{}' read path {} must be absolute",
                    check.name,
                    path.display()
                )));
            }
        }
        Ok(Self {
            scanner: file.scanner,
            checks: file.checks,
            digest: sha256_hex(text.as_bytes()),
        })
    }

    pub fn default_policy() -> Self {
        Self::parse(DEFAULT_POLICY).expect("built-in policy is valid")
    }

    /// Names of every check this policy runs, in attestation order.
    pub fn check_names(&self) -> Vec<String> {
        let built_in = if self.scanner.enabled {
            vec![SEMANTIC_CHECK.to_string(), SECRET_CHECK.to_string()]
        } else {
            Vec::new()
        };
        built_in
            .into_iter()
            .chain(self.checks.iter().map(|check| check.name.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_runs_the_built_in_scanners() {
        let policy = GatewayPolicy::default_policy();
        assert!(policy.scanner.enabled);
        assert!(policy.checks.is_empty());
        assert_eq!(policy.check_names(), vec![SEMANTIC_CHECK, SECRET_CHECK]);
        assert_eq!(policy.digest, sha256_hex(DEFAULT_POLICY.as_bytes()));
    }

    #[test]
    fn parses_command_checks_with_defaults() {
        let policy = GatewayPolicy::parse(
            r#"
version = 1
[scanner]
exclude_paths = ["tests/fixtures/"]

[[check]]
name = "unit-tests"
command = ["cargo", "test"]
network = "unix"
read_paths = ["/opt/toolchain"]

[[check]]
name = "lint"
command = ["sh", "-c", "true"]
timeout_secs = 5
"#,
        )
        .unwrap();
        assert_eq!(policy.scanner.exclude_paths, vec!["tests/fixtures/"]);
        assert_eq!(policy.checks[0].timeout(), Duration::from_secs(120));
        assert_eq!(policy.checks[0].network, NetworkAccess::Unix);
        assert_eq!(policy.checks[1].network, NetworkAccess::Deny);
        assert_eq!(
            policy.check_names(),
            vec![SEMANTIC_CHECK, SECRET_CHECK, "unit-tests", "lint"]
        );
    }

    #[test]
    fn disabling_the_scanner_removes_its_checks() {
        let policy = GatewayPolicy::parse("version = 1\n[scanner]\nenabled = false\n").unwrap();
        assert!(policy.check_names().is_empty());
    }

    #[test]
    fn rejects_invalid_policies() {
        for (text, reason) in [
            ("version = 2\n", "version"),
            ("version = 1\nunknown = true\n", "unknown field"),
            (
                "version = 1\n[[check]]\nname = \"bad name\"\ncommand = [\"true\"]\n",
                "name",
            ),
            (
                "version = 1\n[[check]]\nname = \"empty\"\ncommand = []\n",
                "command",
            ),
            (
                "version = 1\n[[check]]\nname = \"slow\"\ncommand = [\"true\"]\ntimeout_secs = 0\n",
                "timeout",
            ),
            (
                "version = 1\n[[check]]\nname = \"semantic-scan\"\ncommand = [\"true\"]\n",
                "reserved",
            ),
            (
                "version = 1\n[[check]]\nname = \"a\"\ncommand = [\"true\"]\n[[check]]\nname = \"a\"\ncommand = [\"true\"]\n",
                "duplicate",
            ),
            (
                "version = 1\n[[check]]\nname = \"rel\"\ncommand = [\"true\"]\nread_paths = [\"relative\"]\n",
                "absolute",
            ),
            (
                "version = 1\n[[check]]\nname = \"n\"\ncommand = [\"true\"]\nnetwork = \"some\"\n",
                "unknown variant",
            ),
        ] {
            let error = GatewayPolicy::parse(text).unwrap_err();
            assert!(
                error.0.contains(reason),
                "expected '{reason}' in error: {error}"
            );
        }
    }
}
