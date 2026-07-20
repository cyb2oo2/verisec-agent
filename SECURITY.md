# Security policy

VeriSec Agent is a security review tool. Please report product vulnerabilities
responsibly so operators are not put at risk.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

**Do not** open a public GitHub issue for exploitable vulnerabilities in VeriSec
itself (policy bypass, sandbox escape, path traversal on `--repo`, secret
exfiltration via bundles, etc.).

Prefer one of:

1. Private vulnerability report via GitHub Security Advisories on the repository
   (if enabled)
2. Email the maintainers listed in the repository or package metadata with:
   - description and impact
   - reproduction steps
   - affected version / commit
   - any suggested fix

You should receive an acknowledgement within **7 days**. We aim to publish a
fix or advisory timeline within **30 days** for confirmed high-severity issues,
depending on complexity.

## Scope

In scope:

- VeriSec CLI, library code under `src/verisec_agent/`
- Default policy profiles and verification execution boundaries
- Supply-chain issues in release artifacts we publish

Out of scope (file as normal issues/PRs):

- False positives/negatives of security *rules* on third-party code (detector quality)
- Vulnerabilities only in upstream demo/CVE case repositories
- Feature requests for new rule packs

## Threat model

Execution policy, fork-PR posture, and adapter allowlists are documented in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Reports that defeat
`untrusted-fork-pr` assumptions are especially valuable.

## Safe disclosure of detector bugs

Detector misses on public CVEs can be discussed in public issues. Do not attach
private production source code or secrets to bug reports.
