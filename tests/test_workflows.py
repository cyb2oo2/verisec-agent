from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_pr_workflow_keeps_untrusted_path_read_only() -> None:
    text = _workflow("ci.yml")

    assert "pull_request_target" not in text
    assert "pull_request:" in text
    assert "contents: read" in text
    assert "pull-requests: read" in text
    assert "issues: write" in text
    assert "head.repo.full_name == github.repository" in text


def test_ci_fork_review_installs_only_from_trusted_base_revision() -> None:
    text = _workflow("ci.yml")
    fork_job = text[text.index("  fork-review:") : text.index("  comment:")]

    checkout = fork_job.index("Check out trusted base revision")
    install = fork_job.index("Install trusted base tooling")
    review = fork_job.index("Review fork pull request as an untrusted diff")

    assert "ref: ${{ github.event.pull_request.base.sha }}" in fork_job
    assert "persist-credentials: false" in fork_job
    assert "--policy-profile untrusted-fork-pr" in fork_job
    assert checkout < install < review
    assert "python -m pytest" not in fork_job


def test_nightly_workflow_is_trusted_default_branch_promotion() -> None:
    text = _workflow("nightly.yml")

    assert "pull_request_target" not in text
    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert "contents: write" in text
    assert "pull-requests: write" in text
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "cyb/verisec-nightly-promotion-${GITHUB_RUN_ID}" in text
    assert "scripts/promote_nightly_artifacts.py" in text


def test_nightly_workflow_promotes_only_after_attested_nightly_and_release() -> None:
    text = _workflow("nightly.yml")

    nightly = text.index("Run live nightly portfolio")
    nightly_attest = text.index("Attest nightly portfolio")
    first_promote = text.index("Freeze passed nightly scanner baselines")
    release = text.index("Run release portfolio after promotion")
    release_attest = text.index("Attest release portfolio after promotion")
    publish = text.index("Publish promotion benchmark snapshot")
    create_pr = text.index("Create promotion pull request")

    assert nightly < nightly_attest < first_promote < release < release_attest < publish < create_pr
    assert "--manifest verisec_portfolio.nightly.json" in text
    assert "--manifest verisec_portfolio.json" in text
    assert "--release-dir verisec-runs/release-portfolio-after-promotion" in text
    assert "git status --porcelain -- \"${promotion_paths[@]}\"" in text
    assert "gh pr create" in text


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
