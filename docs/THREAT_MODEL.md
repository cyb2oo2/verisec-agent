# Threat Model

VeriSec treats verification as a deployment boundary, not just a convenience
feature. A review may run on trusted local code, trusted CI code from the main
repository, or untrusted pull request code from a fork.

## Execution Profiles

| Profile | Intended use | Allowed adapters | Network posture | Custom commands |
| --- | --- | --- | --- | --- |
| `trusted-local` | Developer workstation and curated local experiments | Configured policy allowlist | Configured, default `inherit` | Allowed when configured |
| `trusted-ci` | Pushes and same-repository PRs in CI | Configured policy allowlist, with CI caps | Configured, default `inherit` | Allowed when configured |
| `untrusted-fork-pr` | Fork pull requests and other untrusted diffs | Intersection with `ruff` and `semgrep` | Forced `disabled` posture | Blocked |

Profiles are ceilings. When `--policy-profile untrusted-fork-pr` is selected,
repository config cannot re-enable `pytest`, `poc-script`, `custom`, inherited
environment mode, or broader network posture.

## Execution Boundary

Verification commands are rendered to argv and executed with `shell=False`.
The policy checks the rendered executable against an allowlist before execution,
caps timeout and retained stdout/stderr bytes, records the executed argv in the
bundle, and writes blocked decisions into `trace.jsonl`, `report.json`, and tool
stderr artifacts.

The `network_access = "disabled"` setting is a policy posture and environment
constraint (`VERISEC_NETWORK=disabled`, proxy variables cleared). It is not a
kernel firewall or container sandbox. Production deployment should pair the
profile with runner-level network isolation.

## GitHub Actions Boundary

The CI workflow keeps PR comment publication in a separate trusted job. The
untrusted PR job produces a Markdown artifact with read-only permissions; the
comment job only runs for same-repository PRs and only after verifying the
stable VeriSec marker.

Fork PRs never install or execute the fork checkout. The fork-review job checks
out the trusted base commit, installs VeriSec from that base revision, and
retrieves the pull request only as a diff for review under the
`untrusted-fork-pr` profile. Custom verification commands, proof-of-concept
scripts, and unit tests from the fork are not executed.

The nightly scanner-drift workflow is separate from the PR workflow. It runs
only on the default branch through `schedule` or `workflow_dispatch`, uses write
permissions to open a promotion PR, and does not process untrusted fork code.
Promotion happens only after the live nightly portfolio and artifact attestation
pass; the refreshed release portfolio is then rerun and attested before the PR
is created.

## Known Residual Risk

- The local runner is not a container sandbox.
- Static tools can still have parser vulnerabilities.
- The fork-review job still trusts the base branch's declared build backend and
  dependencies. Dependency integrity and runner hardening remain CI-platform
  responsibilities.
- Full network isolation requires the CI runner or container runtime to enforce
  it below the process environment.
