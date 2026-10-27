# KSP Gateway threat model

## Assets

- The shared repository on the Git server (what other developers and CI pull).
- The developer's credentials and files outside the repository (`~/.ssh`,
  `~/.aws`, other projects).
- The gateway signing key (`~/.config/ksp-gateway/signing.key`).

## Adversaries

1. **Hostile repository content.** Text in a cloned repository or a pulled
   change that tries to steer an AI coding agent ("ignore previous
   instructions…", hidden Unicode, encoded payloads) or scripts that run during
   routine Git or build activity.
2. **A manipulated AI coding agent** running with the developer's privileges,
   which may try to commit malicious changes or skip local hooks.
3. **A developer bypassing checks**, deliberately or by accident, with
   `git commit --no-verify`, amend, or rebase.

## What each layer guarantees

| Layer | Guarantee | Does not guarantee |
|---|---|---|
| Server bouncer (`pre-receive`) | A pushed commit is accepted only if it carries exactly one attestation signed by a trusted, unrevoked key, bound to that commit's tree and parents, listing every required check, and (optionally) produced under an approved policy digest. | Anything on servers where the hook and trust file are not installed. It trusts that the key holder ran the checks honestly. |
| Attestation | Integrity of the signed statement: changing the tree, parents, policy digest, check list, or key ID invalidates it. Payloads have one canonical encoding and a domain-separated signature. | That the signing machine was uncompromised. The commit message, author, and dates are not signed; replaying an envelope onto another commit only works for an identical tree and parents. |
| Kernel sandbox | Command checks run after no-new-privileges, Landlock (full ABI V6 enforcement required), and seccomp; they see only the disposable staged snapshot, the source object store read-only, approved runtime paths, and explicit `read_paths`. Credential paths cannot be granted. Sockets are denied by default. | Containment against kernel exploits. No resource limits or network namespace. Socket-domain filters do not filter destinations. |
| Staged snapshot | Checks see exactly the index being committed (including the temporary index Git uses for `git commit -a`), without unstaged edits or untracked files. | Custom filters, submodules, or special index flags (these fail closed). |
| Semantic firewall | Flags known patterns: instruction overrides, agent-addressed directives, bidi/zero-width/tag characters, Cyrillic/Greek homoglyphs, base64-encoded instructions, pipe-to-shell, Git hook tampering, credential exfiltration, and common secret formats. Oversized diffs fail closed. Excerpts redact secrets. | Detection of novel phrasing, other encodings, or semantic attacks. It is heuristic defense-in-depth with false positives and false negatives. |
| Local policy | Stored in `.git/ksp/policy.toml`, which `git clone` never populates, so a repository cannot weaken its own checks. | Protection from a local process with the developer's privileges editing it; the server's `--allow-policy` digest list is the enforcement point. |

## Key handling

- Keys are generated from the OS random source and written with
  `create_new` and mode `0600`; loading refuses group/other-readable files.
- The private key never enters the repository, logs, or `Debug` output.
- Trust is a server-side file of public keys; `revoke <key-id>` lines revoke.
- **Limit:** an AI agent running unsandboxed as the developer can read the key
  and sign arbitrary attestations. Run agents inside the sandbox (or as another
  user) without access to `~/.config/ksp-gateway`. Hardware-backed or
  agent-held keys are future work.

## Known bypasses and how they are handled

| Action | Local effect | Server effect |
|---|---|---|
| `git commit --no-verify` | Hooks skipped; no trailer | Rejected: missing attestation |
| Amend/rebase/cherry-pick reusing a message | Trailer copied | Rejected: tree or parent mismatch, until `ksp-gateway reattest` re-checks and re-signs |
| Editing the trailer or payload | — | Rejected: bad signature or malformed |
| Key not on the server's list, or revoked | — | Rejected |
| Lowering the local policy | Commit is attested with a different digest | Rejected when the server uses `--allow-policy`; otherwise accepted |
| Removing a required check from the policy | — | Rejected by `--require-check` |

## Motivating context

The project description cites CVE-2026-26268. Verify its details from primary
sources before repeating them in public material; this repository does not
independently validate that claim.
