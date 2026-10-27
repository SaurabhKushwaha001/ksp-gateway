//! Server-side verification of pushed commits (a Git `pre-receive` hook).
//!
//! Every commit a push introduces must carry exactly one `KSP-Attestation`
//! trailer that is signed by a trusted, unrevoked key and that binds the
//! commit's own tree and parents. This is the enforcement point that local
//! `git commit --no-verify` cannot bypass, but it only exists on servers where
//! the hook and trust file are installed.

use std::{collections::BTreeSet, fmt, io};

use crate::{
    attestation::{Attestation, TrustStore, extract_trailers},
    git::{Repository, is_full_oid, is_null_oid},
};

/// Server trust and policy configuration.
#[derive(Debug, Clone, Default)]
pub struct ServerPolicy {
    pub trust: TrustStore,
    /// Check names that every attestation must report as passed or warned.
    pub required_checks: BTreeSet<String>,
    /// Gateway policy digests the server accepts; empty accepts any digest.
    pub allowed_policy_digests: BTreeSet<String>,
}

/// One line of `pre-receive` standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub refname: String,
}

/// Why a commit was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    MissingAttestation,
    MultipleAttestations,
    InvalidAttestation(String),
    TreeMismatch,
    ParentMismatch,
    MissingCheck(String),
    PolicyNotAllowed(String),
    Git(String),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAttestation => write!(f, "no KSP-Attestation trailer"),
            Self::MultipleAttestations => write!(f, "more than one KSP-Attestation trailer"),
            Self::InvalidAttestation(reason) => write!(f, "{reason}"),
            Self::TreeMismatch => write!(f, "attestation was signed for a different tree"),
            Self::ParentMismatch => write!(f, "attestation was signed for different parents"),
            Self::MissingCheck(name) => write!(f, "required check '{name}' is not attested"),
            Self::PolicyNotAllowed(digest) => {
                write!(f, "gateway policy {digest} is not approved by this server")
            }
            Self::Git(reason) => write!(f, "could not inspect commit: {reason}"),
        }
    }
}

/// Outcome for one commit in a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitVerdict {
    pub refname: String,
    pub commit: String,
    pub result: Result<Attestation, Rejection>,
}

/// Outcome for a whole push.
#[derive(Debug, Clone, Default)]
pub struct PushReport {
    pub verdicts: Vec<CommitVerdict>,
    pub errors: Vec<String>,
}

impl PushReport {
    pub fn accepted(&self) -> bool {
        self.errors.is_empty() && self.verdicts.iter().all(|verdict| verdict.result.is_ok())
    }

    /// Human-readable lines suitable for the hook's stderr.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = self
            .errors
            .iter()
            .map(|error| format!("ksp-gateway: error: {error}"))
            .collect::<Vec<_>>();
        for verdict in &self.verdicts {
            let short = &verdict.commit[..verdict.commit.len().min(12)];
            lines.push(match &verdict.result {
                Ok(attestation) => format!(
                    "ksp-gateway: ok       {short} {} (key {})",
                    verdict.refname, attestation.key_id
                ),
                Err(rejection) => format!(
                    "ksp-gateway: REJECTED {short} {}: {rejection}",
                    verdict.refname
                ),
            });
        }
        lines.push(if self.accepted() {
            "ksp-gateway: push accepted".to_string()
        } else {
            "ksp-gateway: push rejected; commit through the gateway hooks and push again"
                .to_string()
        });
        lines
    }
}

/// Parse `pre-receive` input: `<old-oid> <new-oid> <refname>` per line.
pub fn parse_updates(input: &str) -> Result<Vec<RefUpdate>, String> {
    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let [old, new, refname] = fields[..] else {
                return Err(format!("malformed ref update: {line}"));
            };
            if !is_full_oid(old) || !is_full_oid(new) {
                return Err(format!("ref update has an invalid object id: {line}"));
            }
            Ok(RefUpdate {
                old: old.to_string(),
                new: new.to_string(),
                refname: refname.to_string(),
            })
        })
        .collect()
}

/// Verify a single commit against the server policy.
pub fn verify_commit(
    repo: &Repository,
    commit: &str,
    policy: &ServerPolicy,
) -> Result<Attestation, Rejection> {
    let info = repo
        .commit_info(commit)
        .map_err(|error| Rejection::Git(error.to_string()))?;
    let trailers = extract_trailers(&info.message);
    let envelope = match trailers.as_slice() {
        [] => return Err(Rejection::MissingAttestation),
        [envelope] => envelope,
        _ => return Err(Rejection::MultipleAttestations),
    };
    let attestation = policy
        .trust
        .verify(envelope)
        .map_err(|error| Rejection::InvalidAttestation(error.to_string()))?;
    if attestation.tree != info.tree {
        return Err(Rejection::TreeMismatch);
    }
    if attestation.parents != info.parents {
        return Err(Rejection::ParentMismatch);
    }
    if !policy.allowed_policy_digests.is_empty()
        && !policy
            .allowed_policy_digests
            .contains(&attestation.policy_digest)
    {
        return Err(Rejection::PolicyNotAllowed(attestation.policy_digest));
    }
    for required in &policy.required_checks {
        if !attestation
            .checks
            .iter()
            .any(|check| &check.name == required)
        {
            return Err(Rejection::MissingCheck(required.clone()));
        }
    }
    Ok(attestation)
}

/// Verify every commit introduced by `updates`.
pub fn verify_push(repo: &Repository, updates: &[RefUpdate], policy: &ServerPolicy) -> PushReport {
    let mut report = PushReport::default();
    let mut seen = BTreeSet::new();
    for update in updates {
        if is_null_oid(&update.new) {
            continue;
        }
        let commits = match repo.new_commits(&update.new) {
            Ok(commits) => commits,
            Err(error) => {
                report.errors.push(format!(
                    "could not list commits for {}: {error}",
                    update.refname
                ));
                continue;
            }
        };
        for commit in commits {
            if !seen.insert(commit.clone()) {
                continue;
            }
            report.verdicts.push(CommitVerdict {
                refname: update.refname.clone(),
                result: verify_commit(repo, &commit, policy),
                commit,
            });
        }
    }
    report
}

/// Read `pre-receive` updates from `input` and verify them.
pub fn run_pre_receive(
    repo: &Repository,
    input: &mut impl io::Read,
    policy: &ServerPolicy,
) -> PushReport {
    let mut text = String::new();
    if let Err(error) = input.read_to_string(&mut text) {
        return PushReport {
            errors: vec![format!("could not read ref updates: {error}")],
            ..PushReport::default()
        };
    }
    match parse_updates(&text) {
        Ok(updates) => verify_push(repo, &updates, policy),
        Err(error) => PushReport {
            errors: vec![error],
            ..PushReport::default()
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        attestation::{CheckOutcome, CheckRecord, SigningIdentity, append_trailer, sha256_hex},
        git::test_support::*,
    };
    use std::fs;

    const ZERO: &str = "0000000000000000000000000000000000000000";

    /// Commit the current index with a trailer signed for its tree and parents.
    pub(crate) fn attested_commit(
        repo: &Repository,
        identity: &SigningIdentity,
        message: &str,
        checks: &[&str],
    ) -> String {
        let attestation = Attestation {
            tree: repo.staged_tree().unwrap(),
            parents: repo.pending_parents().unwrap(),
            policy_digest: sha256_hex(b"test policy"),
            timestamp: 1_790_000_000,
            key_id: identity.public_key().key_id(),
            checks: checks
                .iter()
                .map(|name| CheckRecord {
                    name: name.to_string(),
                    outcome: CheckOutcome::Pass,
                })
                .collect(),
        };
        let envelope = identity.sign(&attestation).unwrap();
        let file = repo.root().join(".git/KSP_TEST_MSG");
        fs::write(&file, append_trailer(message, &envelope)).unwrap();
        repo.output([
            "commit".as_ref(),
            "-q".as_ref(),
            "--no-verify".as_ref(),
            "--allow-empty".as_ref(),
            "-F".as_ref(),
            file.as_os_str(),
        ])
        .unwrap();
        repo.head().unwrap().unwrap()
    }

    fn stage(repo: &Repository, path: &str, contents: &str) {
        fs::write(repo.root().join(path), contents).unwrap();
        repo.output(["add", path]).unwrap();
    }

    fn policy_for(identity: &SigningIdentity) -> ServerPolicy {
        let mut policy = ServerPolicy::default();
        policy.trust.trust(identity.public_key(), "dev");
        policy.required_checks.insert("semantic-scan".into());
        policy
    }

    #[test]
    fn parses_pre_receive_input() {
        let updates = parse_updates(&format!(
            "{ZERO} 0123456789abcdef0123456789abcdef01234567 refs/heads/main\n\n"
        ))
        .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].refname, "refs/heads/main");
        assert!(parse_updates("too few fields\n").is_err());
        assert!(parse_updates(&format!("{ZERO} nothex refs/heads/main\n")).is_err());
    }

    #[test]
    fn accepts_a_correctly_attested_commit() {
        let (_dir, repo) = init_repo("bouncer-ok");
        let identity = SigningIdentity::generate().unwrap();
        stage(&repo, "a.txt", "hello\n");
        let commit = attested_commit(&repo, &identity, "add a", &["semantic-scan"]);
        let attestation = verify_commit(&repo, &commit, &policy_for(&identity)).unwrap();
        assert_eq!(attestation.checks[0].name, "semantic-scan");
    }

    #[test]
    fn rejects_unattested_untrusted_and_rebound_commits() {
        let (_dir, repo) = init_repo("bouncer-reject");
        let identity = SigningIdentity::generate().unwrap();
        let policy = policy_for(&identity);

        let plain = commit_file(&repo, "a.txt", "1\n", "plain --no-verify commit");
        assert_eq!(
            verify_commit(&repo, &plain, &policy),
            Err(Rejection::MissingAttestation)
        );

        let stranger = SigningIdentity::generate().unwrap();
        stage(&repo, "a.txt", "2\n");
        let foreign = attested_commit(&repo, &stranger, "foreign", &["semantic-scan"]);
        assert!(matches!(
            verify_commit(&repo, &foreign, &policy),
            Err(Rejection::InvalidAttestation(_))
        ));

        // Reuse a valid trailer on a commit with different content.
        stage(&repo, "a.txt", "3\n");
        let good = attested_commit(&repo, &identity, "good", &["semantic-scan"]);
        let message = repo.commit_info(&good).unwrap().message;
        stage(&repo, "a.txt", "4 - smuggled change\n");
        let file = repo.root().join(".git/KSP_REUSE");
        fs::write(&file, &message).unwrap();
        repo.output([
            "commit".as_ref(),
            "-q".as_ref(),
            "--no-verify".as_ref(),
            "--amend".as_ref(),
            "-F".as_ref(),
            file.as_os_str(),
        ])
        .unwrap();
        let amended = repo.head().unwrap().unwrap();
        assert_eq!(
            verify_commit(&repo, &amended, &policy),
            Err(Rejection::TreeMismatch)
        );

        // Same tree but replayed onto a different parent.
        repo.output(["reset", "-q", "--hard", &good]).unwrap();
        let tree = repo.commit_info(&good).unwrap().tree;
        let replayed = String::from_utf8(
            repo.output_with_input(["commit-tree", &tree, "-p", &plain], message.as_bytes())
                .unwrap(),
        )
        .unwrap()
        .trim()
        .to_string();
        assert_eq!(
            verify_commit(&repo, &replayed, &policy),
            Err(Rejection::ParentMismatch)
        );

        let doubled = format!("{message}KSP-Attestation: another.one.here\n");
        let doubled_commit = String::from_utf8(
            repo.output_with_input(["commit-tree", &tree, "-p", &plain], doubled.as_bytes())
                .unwrap(),
        )
        .unwrap()
        .trim()
        .to_string();
        assert_eq!(
            verify_commit(&repo, &doubled_commit, &policy),
            Err(Rejection::MultipleAttestations)
        );
    }

    #[test]
    fn enforces_required_checks_and_policy_digests() {
        let (_dir, repo) = init_repo("bouncer-policy");
        let identity = SigningIdentity::generate().unwrap();
        stage(&repo, "a.txt", "1\n");
        let commit = attested_commit(&repo, &identity, "only tests", &["unit-tests"]);
        assert_eq!(
            verify_commit(&repo, &commit, &policy_for(&identity)),
            Err(Rejection::MissingCheck("semantic-scan".into()))
        );

        let mut policy = policy_for(&identity);
        policy.required_checks.clear();
        policy
            .allowed_policy_digests
            .insert(sha256_hex(b"some other policy"));
        assert!(matches!(
            verify_commit(&repo, &commit, &policy),
            Err(Rejection::PolicyNotAllowed(_))
        ));
        policy
            .allowed_policy_digests
            .insert(sha256_hex(b"test policy"));
        assert!(verify_commit(&repo, &commit, &policy).is_ok());
    }

    #[test]
    fn verify_push_checks_every_new_commit_and_allows_deletions() {
        let (_dir, repo) = init_repo("bouncer-push");
        let identity = SigningIdentity::generate().unwrap();
        let policy = policy_for(&identity);
        stage(&repo, "a.txt", "1\n");
        let first = attested_commit(&repo, &identity, "one", &["semantic-scan"]);
        stage(&repo, "a.txt", "2\n");
        let second = attested_commit(&repo, &identity, "two", &["semantic-scan"]);
        // Simulate the server's pre-push state: no refs know these commits.
        repo.output(["update-ref", "-d", "refs/heads/main"])
            .unwrap();

        let updates = vec![RefUpdate {
            old: ZERO.into(),
            new: second.clone(),
            refname: "refs/heads/main".into(),
        }];
        let report = verify_push(&repo, &updates, &policy);
        assert!(report.accepted(), "{:?}", report.lines());
        assert_eq!(
            report
                .verdicts
                .iter()
                .map(|v| v.commit.as_str())
                .collect::<Vec<_>>(),
            vec![first.as_str(), second.as_str()]
        );

        repo.output(["update-ref", "refs/heads/main", &second])
            .unwrap();
        let bad = commit_file(&repo, "a.txt", "3\n", "skipped the gateway");
        repo.output(["update-ref", "refs/heads/main", &second])
            .unwrap();
        let report = verify_push(
            &repo,
            &[RefUpdate {
                old: second.clone(),
                new: bad.clone(),
                refname: "refs/heads/main".into(),
            }],
            &policy,
        );
        assert!(!report.accepted());
        assert!(report.lines().iter().any(|line| line.contains(&bad[..12])));

        let deletion = verify_push(
            &repo,
            &[RefUpdate {
                old: second,
                new: ZERO.into(),
                refname: "refs/heads/old".into(),
            }],
            &policy,
        );
        assert!(deletion.accepted());
        assert!(deletion.verdicts.is_empty());
    }

    #[test]
    fn merge_commits_bind_both_parents() {
        let (_dir, repo) = init_repo("bouncer-merge");
        let identity = SigningIdentity::generate().unwrap();
        let policy = policy_for(&identity);
        stage(&repo, "a.txt", "base\n");
        attested_commit(&repo, &identity, "base", &["semantic-scan"]);
        repo.output(["checkout", "-q", "-b", "topic"]).unwrap();
        stage(&repo, "b.txt", "topic\n");
        attested_commit(&repo, &identity, "topic", &["semantic-scan"]);
        repo.output(["checkout", "-q", "main"]).unwrap();
        stage(&repo, "c.txt", "main\n");
        attested_commit(&repo, &identity, "main", &["semantic-scan"]);
        repo.output(["merge", "-q", "--no-commit", "--no-ff", "topic"])
            .unwrap();
        assert_eq!(repo.pending_parents().unwrap().len(), 2);
        let merge = attested_commit(&repo, &identity, "merge topic", &["semantic-scan"]);
        let info = repo.commit_info(&merge).unwrap();
        assert_eq!(info.parents.len(), 2);
        assert!(verify_commit(&repo, &merge, &policy).is_ok());
    }
}
