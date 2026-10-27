//! Read-mostly Git helpers used by the gateway pipeline and the server verifier.
//!
//! Commands scrub Git's repository-selection environment variables, disable
//! the filesystem monitor and hooks, and never run external diff or textconv
//! drivers, so repository configuration cannot turn a read into code execution
//! through those mechanisms. Repository-local configuration is still read; it
//! is created locally by `git clone`/`git init` rather than by the repository.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// The all-zero object ID Git uses for created or deleted refs.
pub fn is_null_oid(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|byte| byte == b'0')
}

/// Whether `oid` looks like a full SHA-1 or SHA-256 object ID.
pub fn is_full_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parsed contents of a commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub tree: String,
    pub parents: Vec<String>,
    pub message: String,
}

/// A Git repository (working tree or bare) addressed by directory.
#[derive(Debug, Clone)]
pub struct Repository {
    root: PathBuf,
}

impl Repository {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(&self.root)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_PREFIX")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_EXTERNAL_DIFF")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.quotePath=false",
            ])
            .stdin(Stdio::null());
        command
    }

    /// Run Git and return stdout, failing on a non-zero exit.
    pub fn output<I, S>(&self, args: I) -> io::Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let output = self.command().args(args).output()?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(io::Error::other(format!(
                "git command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    /// Run Git with `input` on stdin and return stdout.
    pub fn output_with_input<I, S>(&self, args: I, input: &[u8]) -> io::Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut child = self
            .command()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("could not open git stdin"))?
            .write_all(input)?;
        let output = child.wait_with_output()?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(io::Error::other(format!(
                "git command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    fn text<I, S>(&self, args: I) -> io::Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let bytes = self.output(args)?;
        let text = String::from_utf8(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(text.trim_end_matches(['\n', '\r']).to_string())
    }

    /// The working-tree top level, canonicalized.
    pub fn top_level(&self) -> io::Result<PathBuf> {
        let top = self.text(["rev-parse", "--show-toplevel"])?;
        std::fs::canonicalize(top)
    }

    /// Resolve a path inside the Git directory, such as `hooks` or `MERGE_HEAD`.
    pub fn git_path(&self, name: &str) -> io::Result<PathBuf> {
        let path = PathBuf::from(self.text(["rev-parse", "--git-path", name])?);
        Ok(if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        })
    }

    /// The tree object that the current index would commit.
    pub fn staged_tree(&self) -> io::Result<String> {
        self.text(["write-tree"])
    }

    /// The current `HEAD` commit, or `None` on an unborn branch.
    pub fn head(&self) -> io::Result<Option<String>> {
        let output = self
            .command()
            .args(["rev-parse", "-q", "--verify", "HEAD^{commit}"])
            .output()?;
        if output.status.success() {
            Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
            ))
        } else {
            Ok(None)
        }
    }

    /// Parents the next `git commit` will record: `HEAD` plus any merge heads.
    pub fn pending_parents(&self) -> io::Result<Vec<String>> {
        let mut parents = Vec::new();
        if let Some(head) = self.head()? {
            parents.push(head);
        }
        match std::fs::read_to_string(self.git_path("MERGE_HEAD")?) {
            Ok(contents) => parents.extend(
                contents
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_string),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(parents)
    }

    /// The staged change set as a zero-context unified diff, without external
    /// diff drivers or text conversion. Binary files are reported, not dumped.
    pub fn staged_diff(&self) -> io::Result<Vec<u8>> {
        self.output([
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--unified=0",
            "--diff-filter=ACMRT",
        ])
    }

    /// Diff between two commits (`from` may be `None` for a root commit).
    pub fn commit_diff(&self, from: Option<&str>, to: &str) -> io::Result<Vec<u8>> {
        let empty_tree;
        let from = match from {
            Some(from) => from,
            None => {
                // The empty tree for this repository's hash algorithm.
                empty_tree = self.text(["hash-object", "-t", "tree", "/dev/null"])?;
                &empty_tree
            }
        };
        self.output([
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--unified=0",
            "--diff-filter=ACMRT",
            from,
            to,
        ])
    }

    /// Read and parse a commit object.
    pub fn commit_info(&self, oid: &str) -> io::Result<CommitInfo> {
        let raw = self.output(["cat-file", "commit", oid])?;
        parse_commit(&raw)
    }

    /// Commits reachable from `new` that are not reachable from any existing ref,
    /// oldest first. In a `pre-receive` hook the existing refs are the pre-push
    /// state, so this lists exactly the commits being introduced.
    pub fn new_commits(&self, new: &str) -> io::Result<Vec<String>> {
        let text = self.text([
            "rev-list",
            "--reverse",
            "--topo-order",
            new,
            "--not",
            "--all",
        ])?;
        Ok(text
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect())
    }
}

/// Parse the raw bytes of `git cat-file commit`.
pub fn parse_commit(raw: &[u8]) -> io::Result<CommitInfo> {
    let text = String::from_utf8_lossy(raw);
    let (headers, message) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut tree = None;
    let mut parents = Vec::new();
    for line in headers.lines() {
        if let Some(value) = line.strip_prefix("tree ") {
            tree = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("parent ") {
            parents.push(value.trim().to_string());
        }
    }
    let tree = tree.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "commit object has no tree header",
        )
    })?;
    Ok(CommitInfo {
        tree,
        parents,
        message: message.to_string(),
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::Repository;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A temporary directory removed on drop.
    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ksp-unit-{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Initialize a repository with a deterministic identity.
    pub fn init_repo(label: &str) -> (TempDir, Repository) {
        let dir = TempDir::new(label);
        let repo = Repository::new(dir.path());
        repo.output(["init", "-q", "-b", "main"]).unwrap();
        repo.output(["config", "user.name", "KSP test"]).unwrap();
        repo.output(["config", "user.email", "ksp-test@example.invalid"])
            .unwrap();
        repo.output(["config", "commit.gpgsign", "false"]).unwrap();
        (dir, repo)
    }

    pub fn commit_file(repo: &Repository, path: &str, contents: &str, message: &str) -> String {
        let file = repo.root().join(path);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(file, contents).unwrap();
        repo.output(["add", path]).unwrap();
        repo.output(["commit", "-q", "--no-verify", "-m", message])
            .unwrap();
        repo.head().unwrap().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::fs;

    #[test]
    fn oid_helpers_classify_ids() {
        assert!(is_null_oid("0000000000000000000000000000000000000000"));
        assert!(!is_null_oid("0000000000000000000000000000000000000001"));
        assert!(!is_null_oid(""));
        assert!(is_full_oid("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_full_oid("0123456789ABCDEF0123456789abcdef01234567"));
        assert!(!is_full_oid("abc"));
    }

    #[test]
    fn parse_commit_reads_tree_parents_and_message() {
        let raw =
            b"tree aaaa\nparent bbbb\nparent cccc\nauthor A <a@b> 1 +0000\n\nsubject\n\nbody\n";
        let info = parse_commit(raw).unwrap();
        assert_eq!(info.tree, "aaaa");
        assert_eq!(info.parents, vec!["bbbb", "cccc"]);
        assert_eq!(info.message, "subject\n\nbody\n");
        assert!(parse_commit(b"author nobody\n\nmsg").is_err());
    }

    #[test]
    fn staged_tree_and_parents_track_the_index() {
        let (_dir, repo) = init_repo("git-staged");
        assert_eq!(repo.head().unwrap(), None);
        assert!(repo.pending_parents().unwrap().is_empty());
        let first = commit_file(&repo, "a.txt", "one\n", "first");
        assert_eq!(repo.pending_parents().unwrap(), vec![first.clone()]);

        let committed_tree = repo.commit_info(&first).unwrap().tree;
        assert_eq!(repo.staged_tree().unwrap(), committed_tree);

        fs::write(repo.root().join("a.txt"), "two\n").unwrap();
        assert_eq!(
            repo.staged_tree().unwrap(),
            committed_tree,
            "unstaged edits must not change the staged tree"
        );
        repo.output(["add", "a.txt"]).unwrap();
        assert_ne!(repo.staged_tree().unwrap(), committed_tree);
    }

    #[test]
    fn staged_diff_contains_only_staged_additions() {
        let (_dir, repo) = init_repo("git-diff");
        commit_file(&repo, "a.txt", "base\n", "base");
        fs::write(repo.root().join("a.txt"), "base\nstaged line\n").unwrap();
        repo.output(["add", "a.txt"]).unwrap();
        fs::write(
            repo.root().join("a.txt"),
            "base\nstaged line\nunstaged line\n",
        )
        .unwrap();
        let diff = String::from_utf8(repo.staged_diff().unwrap()).unwrap();
        assert!(diff.contains("+staged line"));
        assert!(!diff.contains("unstaged line"));
    }

    #[test]
    fn new_commits_excludes_commits_already_on_refs() {
        let (_dir, repo) = init_repo("git-revlist");
        let first = commit_file(&repo, "a.txt", "1\n", "one");
        repo.output(["checkout", "-q", "-b", "topic"]).unwrap();
        let second = commit_file(&repo, "a.txt", "2\n", "two");
        let third = commit_file(&repo, "a.txt", "3\n", "three");
        repo.output(["checkout", "-q", "main"]).unwrap();
        repo.output(["branch", "-q", "-D", "topic"]).unwrap();
        assert_eq!(repo.new_commits(&third).unwrap(), vec![second, third]);
        assert!(repo.new_commits(&first).unwrap().is_empty());
    }

    #[test]
    fn commit_diff_handles_root_commits() {
        let (_dir, repo) = init_repo("git-rootdiff");
        let root = commit_file(&repo, "a.txt", "hello\n", "root");
        let diff = String::from_utf8(repo.commit_diff(None, &root).unwrap()).unwrap();
        assert!(diff.contains("+hello"));
    }
}
