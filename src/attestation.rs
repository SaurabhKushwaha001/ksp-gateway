//! Signed local attestations that a commit's tree passed the gateway checks.
//!
//! An attestation binds a tree object ID, the parent commits, the digest of the
//! gateway policy that was enforced, and the checks that ran. The gateway signs
//! it with an Ed25519 key kept outside the repository and stores the envelope
//! in a `KSP-Attestation:` commit-message trailer. A server-side verifier can
//! then reject pushed commits whose trailer is missing, invalid, or signed by
//! an untrusted or revoked key.
//!
//! A valid signature proves that a holder of a trusted key signed this payload.
//! It does not prove the checks were meaningful or that the signer's machine
//! was uncompromised; key protection and the trust list are policy decisions.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io,
    path::Path,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Commit-message trailer key carrying the signed envelope.
pub const TRAILER_KEY: &str = "KSP-Attestation";
const PAYLOAD_HEADER: &str = "ksp-attestation v1";
const SIGNATURE_DOMAIN: &[u8] = b"ksp-gateway attestation v1\0";
const SECRET_PREFIX: &str = "ksp-ed25519-secret-v1";
const PUBLIC_PREFIX: &str = "ksp-ed25519-public-v1";

/// Hex-encoded SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Check names are restricted so the canonical encoding stays unambiguous.
pub fn is_valid_check_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// How a check finished when the attestation was signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The check passed with no findings.
    Pass,
    /// The check passed but reported non-blocking findings.
    Warn,
}

impl CheckOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
        }
    }
}

/// One check recorded in an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRecord {
    pub name: String,
    pub outcome: CheckOutcome,
}

/// The signed statement. Field order in the encoding is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub tree: String,
    pub parents: Vec<String>,
    pub policy_digest: String,
    pub timestamp: u64,
    pub key_id: String,
    pub checks: Vec<CheckRecord>,
}

/// Errors from encoding, key handling, or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    InvalidField(&'static str),
    Malformed(String),
    UnknownKey(String),
    RevokedKey(String),
    KeyMismatch,
    BadSignature,
    InsecureKeyFile(String),
    Io(String),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "attestation field is invalid: {field}"),
            Self::Malformed(reason) => write!(f, "malformed attestation: {reason}"),
            Self::UnknownKey(id) => write!(f, "attestation key {id} is not trusted"),
            Self::RevokedKey(id) => write!(f, "attestation key {id} has been revoked"),
            Self::KeyMismatch => write!(f, "attestation names a different key than signed it"),
            Self::BadSignature => write!(f, "attestation signature is invalid"),
            Self::InsecureKeyFile(reason) => write!(f, "insecure signing key file: {reason}"),
            Self::Io(reason) => write!(f, "attestation I/O error: {reason}"),
        }
    }
}

impl std::error::Error for AttestationError {}

impl From<io::Error> for AttestationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl Attestation {
    fn validate(&self) -> Result<(), AttestationError> {
        if !crate::git::is_full_oid(&self.tree) {
            return Err(AttestationError::InvalidField("tree"));
        }
        if !self.parents.iter().all(|p| crate::git::is_full_oid(p)) {
            return Err(AttestationError::InvalidField("parent"));
        }
        if self.policy_digest.len() != 64 || !is_lower_hex(&self.policy_digest) {
            return Err(AttestationError::InvalidField("policy"));
        }
        if self.key_id.len() != 16 || !is_lower_hex(&self.key_id) {
            return Err(AttestationError::InvalidField("key"));
        }
        let mut names = BTreeSet::new();
        for check in &self.checks {
            if !is_valid_check_name(&check.name) || !names.insert(check.name.as_str()) {
                return Err(AttestationError::InvalidField("check"));
            }
        }
        Ok(())
    }

    /// Encode in the canonical line format that is signed.
    pub fn encode(&self) -> Result<String, AttestationError> {
        self.validate()?;
        let mut text = format!("{PAYLOAD_HEADER}\ntree {}\n", self.tree);
        for parent in &self.parents {
            text.push_str(&format!("parent {parent}\n"));
        }
        text.push_str(&format!(
            "policy {}\ntime {}\nkey {}\n",
            self.policy_digest, self.timestamp, self.key_id
        ));
        for check in &self.checks {
            text.push_str(&format!(
                "check {} {}\n",
                check.name,
                check.outcome.as_str()
            ));
        }
        Ok(text)
    }

    /// Parse the canonical format. Any input that does not re-encode to the
    /// same bytes is rejected, so one payload has exactly one encoding.
    pub fn decode(text: &str) -> Result<Self, AttestationError> {
        let malformed = |reason: &str| AttestationError::Malformed(reason.to_string());
        let body = text
            .strip_suffix('\n')
            .ok_or_else(|| malformed("payload must end with a newline"))?;
        let mut lines = body.split('\n').peekable();
        if lines.next() != Some(PAYLOAD_HEADER) {
            return Err(malformed("unsupported payload version"));
        }
        let tree = take_field(&mut lines, "tree")?;
        let mut parents = Vec::new();
        while let Some(parent) = lines.peek().and_then(|line| line.strip_prefix("parent ")) {
            parents.push(parent.to_string());
            lines.next();
        }
        let policy_digest = take_field(&mut lines, "policy")?;
        let timestamp = take_field(&mut lines, "time")?
            .parse::<u64>()
            .map_err(|_| malformed("time must be an integer"))?;
        let key_id = take_field(&mut lines, "key")?;
        let mut checks = Vec::new();
        for line in lines {
            let record = line
                .strip_prefix("check ")
                .ok_or_else(|| malformed("unexpected field"))?;
            let (name, outcome) = record
                .split_once(' ')
                .ok_or_else(|| malformed("check record needs an outcome"))?;
            let outcome = match outcome {
                "pass" => CheckOutcome::Pass,
                "warn" => CheckOutcome::Warn,
                _ => return Err(malformed("unknown check outcome")),
            };
            checks.push(CheckRecord {
                name: name.to_string(),
                outcome,
            });
        }
        let attestation = Self {
            tree,
            parents,
            policy_digest,
            timestamp,
            key_id,
            checks,
        };
        match attestation.encode() {
            Ok(canonical) if canonical == text => Ok(attestation),
            Ok(_) => Err(malformed("payload is not canonically encoded")),
            Err(error) => Err(AttestationError::Malformed(error.to_string())),
        }
    }
}

/// An Ed25519 public key with a stable short identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// First 16 hex characters of SHA-256 over the raw public key.
    pub fn key_id(&self) -> String {
        sha256_hex(self.0.as_bytes())[..16].to_string()
    }

    /// `ksp-ed25519-public-v1 <base64url>` for trust files.
    pub fn to_text(&self) -> String {
        format!(
            "{PUBLIC_PREFIX} {}",
            URL_SAFE_NO_PAD.encode(self.0.as_bytes())
        )
    }

    /// Parse `ksp-ed25519-public-v1 <base64url>`; trailing words are ignored.
    pub fn from_text(text: &str) -> Result<Self, AttestationError> {
        let mut words = text.split_whitespace();
        if words.next() != Some(PUBLIC_PREFIX) {
            return Err(AttestationError::Malformed("not a KSP public key".into()));
        }
        let bytes = words
            .next()
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| AttestationError::Malformed("public key must be 32 bytes".into()))?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| AttestationError::Malformed("public key is not a valid point".into()))
    }
}

/// A private signing key. It is never written into the repository or logs.
pub struct SigningIdentity {
    key: SigningKey,
}

impl fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningIdentity")
            .field("key_id", &self.public_key().key_id())
            .finish_non_exhaustive()
    }
}

impl SigningIdentity {
    /// Generate a key from the operating system's random source.
    pub fn generate() -> Result<Self, AttestationError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|error| AttestationError::Io(format!("random source failed: {error}")))?;
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        Ok(Self { key })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.key.verifying_key())
    }

    /// Write the key with owner-only permissions; refuses to overwrite.
    pub fn save(&self, path: &Path) -> Result<(), AttestationError> {
        use std::io::Write;

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        let encoded = format!(
            "{SECRET_PREFIX} {}\n",
            URL_SAFE_NO_PAD.encode(self.key.to_bytes())
        );
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Load a key, refusing files readable by group or other users.
    pub fn load(path: &Path) -> Result<Self, AttestationError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(AttestationError::InsecureKeyFile(format!(
                    "{} is accessible by other users (mode {:o}); run chmod 600",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let text = fs::read_to_string(path)?;
        let mut words = text.split_whitespace();
        if words.next() != Some(SECRET_PREFIX) {
            return Err(AttestationError::Malformed("not a KSP signing key".into()));
        }
        let mut bytes = words
            .next()
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| AttestationError::Malformed("signing key must be 32 bytes".into()))?;
        let key = SigningKey::from_bytes(&bytes);
        bytes.fill(0);
        Ok(Self { key })
    }

    /// Sign an attestation and return the `key-id.payload.signature` envelope.
    pub fn sign(&self, attestation: &Attestation) -> Result<String, AttestationError> {
        let payload = attestation.encode()?;
        let signature = self.key.sign(&signed_message(payload.as_bytes()));
        Ok(format!(
            "{}.{}.{}",
            self.public_key().key_id(),
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

/// Trusted public keys plus revocations, loaded from a server-side file.
///
/// File format, one entry per line (`#` starts a comment):
/// `ksp-ed25519-public-v1 <base64url> [label...]` trusts a key and
/// `revoke <key-id>` revokes one.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    keys: BTreeMap<String, (PublicKey, String)>,
    revoked: BTreeSet<String>,
}

impl TrustStore {
    pub fn parse(text: &str) -> Result<Self, AttestationError> {
        let mut store = Self::default();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(key_id) = line.strip_prefix("revoke ") {
                let key_id = key_id.trim();
                if key_id.len() != 16 || !is_lower_hex(key_id) {
                    return Err(AttestationError::Malformed(format!(
                        "line {}: revoke needs a 16-character key id",
                        number + 1
                    )));
                }
                store.revoke(key_id);
                continue;
            }
            let key = PublicKey::from_text(line).map_err(|error| {
                AttestationError::Malformed(format!("line {}: {error}", number + 1))
            })?;
            let label = line
                .split_whitespace()
                .skip(2)
                .collect::<Vec<_>>()
                .join(" ");
            store.trust(key, label);
        }
        Ok(store)
    }

    pub fn load(path: &Path) -> Result<Self, AttestationError> {
        Self::parse(&fs::read_to_string(path)?)
    }

    pub fn trust(&mut self, key: PublicKey, label: impl Into<String>) {
        self.keys.insert(key.key_id(), (key, label.into()));
    }

    pub fn revoke(&mut self, key_id: impl Into<String>) {
        self.revoked.insert(key_id.into());
    }

    /// Label recorded for a trusted key.
    pub fn label(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(|(_, label)| label.as_str())
    }

    /// Verify an envelope and return the attestation it signs.
    pub fn verify(&self, envelope: &str) -> Result<Attestation, AttestationError> {
        let malformed = |reason: &str| AttestationError::Malformed(reason.to_string());
        let parts = envelope.split('.').collect::<Vec<_>>();
        let [key_id, payload, signature] = parts[..] else {
            return Err(malformed("envelope must be key.payload.signature"));
        };
        if key_id.len() != 16 || !is_lower_hex(key_id) {
            return Err(malformed("envelope key id is invalid"));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| malformed("payload is not base64url"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(|bytes| Signature::from_bytes(&bytes))
            .ok_or_else(|| malformed("signature must be 64 bytes of base64url"))?;
        if self.revoked.contains(key_id) {
            return Err(AttestationError::RevokedKey(key_id.to_string()));
        }
        let (key, _) = self
            .keys
            .get(key_id)
            .ok_or_else(|| AttestationError::UnknownKey(key_id.to_string()))?;
        key.0
            .verify_strict(&signed_message(&payload), &signature)
            .map_err(|_| AttestationError::BadSignature)?;
        let text = String::from_utf8(payload).map_err(|_| malformed("payload is not UTF-8"))?;
        let attestation = Attestation::decode(&text)?;
        if attestation.key_id != key_id {
            return Err(AttestationError::KeyMismatch);
        }
        Ok(attestation)
    }
}

/// Add or replace the gateway trailer in a commit message.
///
/// The trailer is placed after the message body and before Git's trailing
/// comment block or scissors line, which `git commit` strips afterwards.
pub fn append_trailer(message: &str, envelope: &str) -> String {
    let lines = message.lines().collect::<Vec<_>>();
    let scissors = lines
        .iter()
        .position(|line| line.starts_with('#') && line.contains(">8"))
        .unwrap_or(lines.len());
    let (content, cut) = lines.split_at(scissors);
    let body_end = content
        .iter()
        .rposition(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map_or(0, |index| index + 1);
    let body = content[..body_end]
        .iter()
        .filter(|line| !is_trailer_line(line))
        .copied()
        .collect::<Vec<_>>();
    let mut output = body.join("\n").trim_end().to_string();
    output.push_str(&format!("\n\n{TRAILER_KEY}: {envelope}\n"));
    for line in content[body_end..].iter().chain(cut) {
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn is_trailer_line(line: &str) -> bool {
    line.trim_start()
        .strip_prefix(TRAILER_KEY)
        .is_some_and(|rest| rest.starts_with(':'))
}

/// All gateway trailer values in a commit message.
pub fn extract_trailers(message: &str) -> Vec<String> {
    message
        .lines()
        .filter(|line| is_trailer_line(line))
        .filter_map(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
        .collect()
}

fn take_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &str,
) -> Result<String, AttestationError> {
    lines
        .next()
        .and_then(|line| line.strip_prefix(name))
        .and_then(|rest| rest.strip_prefix(' '))
        .map(str::to_string)
        .ok_or_else(|| AttestationError::Malformed(format!("expected {name} field")))
}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(payload);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::test_support::TempDir;

    fn sample(key_id: &str) -> Attestation {
        Attestation {
            tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
            parents: vec!["0123456789abcdef0123456789abcdef01234567".into()],
            policy_digest: sha256_hex(b"policy"),
            timestamp: 1_790_000_000,
            key_id: key_id.into(),
            checks: vec![
                CheckRecord {
                    name: "semantic-scan".into(),
                    outcome: CheckOutcome::Pass,
                },
                CheckRecord {
                    name: "unit_tests".into(),
                    outcome: CheckOutcome::Warn,
                },
            ],
        }
    }

    fn identity_and_store() -> (SigningIdentity, TrustStore) {
        let identity = SigningIdentity::generate().unwrap();
        let mut store = TrustStore::default();
        store.trust(identity.public_key(), "developer laptop");
        (identity, store)
    }

    #[test]
    fn encoding_round_trips_and_is_canonical() {
        let attestation = sample("00112233aabbccdd");
        let text = attestation.encode().unwrap();
        assert!(text.starts_with("ksp-attestation v1\ntree 4b825dc6"));
        assert_eq!(Attestation::decode(&text).unwrap(), attestation);

        for bad in [
            text.replace("ksp-attestation v1", "ksp-attestation v2"),
            text.replace("tree ", "tree  "),
            format!("{text}extra field\n"),
            text.replace("\n", "\r\n"),
            text.trim_end().to_string(),
            text.replace("check unit_tests warn", "check unit_tests maybe"),
        ] {
            assert!(Attestation::decode(&bad).is_err(), "accepted: {bad:?}");
        }
        let mut reordered = text.lines().collect::<Vec<_>>();
        reordered.swap(1, 2);
        assert!(Attestation::decode(&(reordered.join("\n") + "\n")).is_err());
    }

    #[test]
    fn encoding_rejects_ambiguous_fields() {
        let mut bad_tree = sample("00112233aabbccdd");
        bad_tree.tree = "not hex".into();
        assert!(bad_tree.encode().is_err());

        let mut bad_check = sample("00112233aabbccdd");
        bad_check.checks[0].name = "two words".into();
        assert!(bad_check.encode().is_err());

        let mut duplicate = sample("00112233aabbccdd");
        duplicate.checks[1].name = "semantic-scan".into();
        assert!(duplicate.encode().is_err());
    }

    #[test]
    fn signed_attestations_verify_against_the_trust_store() {
        let (identity, store) = identity_and_store();
        let attestation = sample(&identity.public_key().key_id());
        let envelope = identity.sign(&attestation).unwrap();
        assert!(!envelope.contains(char::is_whitespace));
        assert_eq!(store.verify(&envelope).unwrap(), attestation);
        assert_eq!(
            store.label(&identity.public_key().key_id()),
            Some("developer laptop")
        );
    }

    #[test]
    fn tampered_envelopes_are_rejected() {
        let (identity, store) = identity_and_store();
        let attestation = sample(&identity.public_key().key_id());
        let envelope = identity.sign(&attestation).unwrap();
        let mut parts = envelope.split('.');
        let (key, payload, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );

        let mut forged = attestation.clone();
        forged.tree = "1111111111111111111111111111111111111111".into();
        let forged_payload = URL_SAFE_NO_PAD.encode(forged.encode().unwrap());
        assert_eq!(
            store.verify(&format!("{key}.{forged_payload}.{signature}")),
            Err(AttestationError::BadSignature)
        );

        let mut sig_bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        sig_bytes[0] ^= 1;
        let flipped = format!("{key}.{payload}.{}", URL_SAFE_NO_PAD.encode(sig_bytes));
        assert_eq!(store.verify(&flipped), Err(AttestationError::BadSignature));

        for garbage in ["", "..", "abc", "a.b", "a.b.c.d", "XYZ.!!!.???"] {
            assert!(matches!(
                store.verify(garbage),
                Err(AttestationError::Malformed(_))
            ));
        }
    }

    #[test]
    fn unknown_revoked_and_mismatched_keys_are_rejected() {
        let (identity, mut store) = identity_and_store();
        let key_id = identity.public_key().key_id();
        let envelope = identity.sign(&sample(&key_id)).unwrap();

        let stranger = SigningIdentity::generate().unwrap();
        let stranger_envelope = stranger
            .sign(&sample(&stranger.public_key().key_id()))
            .unwrap();
        assert!(matches!(
            store.verify(&stranger_envelope),
            Err(AttestationError::UnknownKey(_))
        ));

        // A trusted key signing a payload that names another key is refused.
        let claims_other = identity.sign(&sample("ffffffffffffffff")).unwrap();
        assert_eq!(
            store.verify(&claims_other),
            Err(AttestationError::KeyMismatch)
        );

        store.revoke(key_id.clone());
        assert_eq!(
            store.verify(&envelope),
            Err(AttestationError::RevokedKey(key_id))
        );
    }

    #[test]
    fn public_keys_have_stable_text_and_ids() {
        let identity = SigningIdentity::generate().unwrap();
        let public = identity.public_key();
        let text = public.to_text();
        assert!(text.starts_with("ksp-ed25519-public-v1 "));
        let parsed = PublicKey::from_text(&text).unwrap();
        assert_eq!(parsed, public);
        assert_eq!(parsed.key_id().len(), 16);
        assert!(PublicKey::from_text("ksp-ed25519-public-v1 short").is_err());
        assert!(PublicKey::from_text("ssh-ed25519 AAAA").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn signing_keys_are_saved_owner_only_and_insecure_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("keys");
        let path = dir.path().join("nested/signing.key");
        let identity = SigningIdentity::generate().unwrap();
        identity.save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(identity.save(&path).is_err(), "must not overwrite a key");

        let loaded = SigningIdentity::load(&path).unwrap();
        assert_eq!(loaded.public_key(), identity.public_key());
        assert!(!format!("{loaded:?}").contains(SECRET_PREFIX));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            SigningIdentity::load(&path),
            Err(AttestationError::InsecureKeyFile(_))
        ));
    }

    #[test]
    fn trust_store_parses_keys_comments_and_revocations() {
        let first = SigningIdentity::generate().unwrap().public_key();
        let second = SigningIdentity::generate().unwrap().public_key();
        let text = format!(
            "# team keys\n{} alice laptop\n\n{}\nrevoke {}\n",
            first.to_text(),
            second.to_text(),
            second.key_id()
        );
        let store = TrustStore::parse(&text).unwrap();
        assert_eq!(store.label(&first.key_id()), Some("alice laptop"));
        assert!(store.revoked.contains(&second.key_id()));
        assert!(TrustStore::parse("nonsense line\n").is_err());
        assert!(TrustStore::parse("revoke not-hex\n").is_err());
    }

    #[test]
    fn trailers_are_appended_replaced_and_extracted() {
        let message = append_trailer("Fix bug\n\nDetails here.\n", "AAA.BBB");
        assert_eq!(
            message,
            "Fix bug\n\nDetails here.\n\nKSP-Attestation: AAA.BBB\n"
        );
        assert_eq!(extract_trailers(&message), vec!["AAA.BBB"]);

        let replaced = append_trailer(&message, "CCC.DDD");
        assert_eq!(extract_trailers(&replaced), vec!["CCC.DDD"]);
        assert!(!replaced.contains("AAA.BBB"));

        let no_newline = append_trailer("Subject only", "X.Y");
        assert_eq!(no_newline, "Subject only\n\nKSP-Attestation: X.Y\n");

        let with_comments = append_trailer("Subject\n# Please enter the message\n", "X.Y");
        assert_eq!(extract_trailers(&with_comments), vec!["X.Y"]);
        assert!(extract_trailers("no trailer here\n").is_empty());
    }
}
