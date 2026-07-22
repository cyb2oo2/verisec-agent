# VeriSec Holdout 2

**Status: FROZEN AND RUN (2026-07-22).** The case set, configs, and protocol are
locked as of the freeze date; the single measured run has been performed once and
its result is in Results below. Detectors must not be tuned against these cases
(Invariant 1); the holdout is not re-run.

Second explicitly frozen holdout for VeriSec Agent. It supersedes nothing:
[HOLDOUT_PILOT.md](HOLDOUT_PILOT.md) records the first pilot at its own freeze
commit and remains frozen and historical.

## Protocol

- Split: `holdout-2`, reported as three labelled groups (`same-class-primary`,
  `same-class-removal`, `open-class`)
- Detector freeze commit: `0ca2df57a399bafeafe75aed49d698d07a4c2018`
  (detectors unchanged since `d4bb069`; later commits touch tests, docs, and
  benchmark rendering only)
- Frozen: 2026-07-22
- Case set: [examples/holdout_2_cases.json](../examples/holdout_2_cases.json),
  8 cases, per-case property-check config `examples/holdout2_*.toml`
- Reference partitions: 3 OSS seed cases, 6 promoted CVE cases, 2 pilot holdout cases
- Partition fingerprints: case ID, CVE/GHSA/advisory, repository base/head pair,
  diff URL, upstream commit
- Detector changes after this freeze: none permitted
- Cases are **not** promoted into any measured seed set, before or after the run
- The measured run happens **once**. Its result is published whatever it says.

### Selection provenance

**same-class** was proposed by an assistant with working knowledge of this
repository's detectors, then vetoed by the project owner. Proposal-then-veto
cannot fully exclude selection shaped by detector knowledge; this group carries
residual selection risk and is the weaker of the two methods.

**open-class** was drawn mechanically, rule fixed before the draw:

> Most recent pip advisories in the GitHub Advisory Database, `published-desc`
> order, within a pre-registered window of the top 25 entries. Keep the first
> advisory per distinct package. Then keep only those whose fix commit modifies at
> least one `.py` file.

The `.py` filter is not class-based; it drops advisories whose fix lands entirely
in C extensions, which a Python-only analyser cannot see by construction. A
package failing the filter drops out rather than being replaced by a later
advisory from the same package. Advisory publication is bursty (the window held
12 Pillow and 9 mistune entries); first-per-package prevents that clustering from
producing a sample of three projects.

## Same-class fixes rarely match the detector's assumptions

`py-regex-redos-hardening` assumes a fix hardens a regex *pattern in place*; the
`py-sql-*` family, per [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) D-015, matches only
the literal identifiers of the patches already in the promoted suite and cannot
fire on an unseen SQL fix at all. Surveying same-class candidates against their
upstream patches:

| Case | What the patch does | Matches assumption |
| --- | --- | --- |
| transformers CVE-2025-2099 | rewrites regex, drops nested quantifier | yes — pattern delta |
| pygments CVE-2026-4539 | rewrites GUID regex, drops nested quantifier | yes — pattern delta |
| python-multipart CVE-2024-24762 | regex replaced by `email.message.Message` | no — removed |
| Black CVE-2024-21503 | `FIRST_NON_WHITESPACE_RE` replaced by `lstrip()` | no — removed |
| PyMySQL CVE-2024-36039 | `escape_dict` raises `TypeError`; dict params forbidden | no — removed |

Only two same-class cases are primary-eligible, and both are ReDoS pattern
deltas. This scarcity is itself the finding: the fix shape the detectors assume is
uncommon. The holdout measures that honestly rather than hiding it.

## Cases

### Group A — same-class, primary-eligible (n=2)

| Case | Advisory | Fix commit | Expected primary |
| --- | --- | --- | --- |
| transformers doc-regex ReDoS | CVE-2025-2099 | `8cb522b4190bd556ce51be04942720650b1a3e57` | `py-regex-redos-hardening` @ `src/transformers/testing_utils.py` |
| pygments GUID ReDoS | CVE-2026-4539 | `24b8aa76c6cd6d70f39c6dd605cce319c98e2ccc` | `py-regex-redos-hardening` @ `pygments/lexers/archetype.py` |

"Expected" means the fix shape matches the rule's assumption. Whether the rule
actually fires is what the single run measures; it is not asserted here.

### Group B — same-class, removal-shape: noise / precision only (n=3)

| Case | Advisory | Fix commit | Expected primary |
| --- | --- | --- | --- |
| python-multipart Content-Type ReDoS | CVE-2024-24762 | `20f0ef6b4e4caf7d69a667c54dff57fe467109a4` | none applicable |
| Black leading-tab ReDoS | CVE-2024-21503 | `f00093672628d212b8965a8993cee8bedf5fe9b8` | none applicable |
| PyMySQL `escape_dict` SQLi | CVE-2024-36039 | `521e40050cb386a499f68f483fefd144c493053c` | none applicable |

These measure whether VeriSec stays quiet on a real security patch it cannot
claim. Counting them as recall misses would overstate what was tested.

### Group C — open-class, mechanically drawn (n=3)

| Case | Advisory | Fix commit | Expected primary |
| --- | --- | --- | --- |
| Pillow `ImageCmsTransform.apply()` mode mismatch | CVE-2026-59205 | `a9ffc42bedf4fc0a7ef8d6486e7f9e81e3397721` | none — no rule coverage |
| mistune `safe_url` protocol denylist | CVE-2026-59929 | `c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc` | none — no rule coverage |
| vLLM M-RoPE prompt-embeds crash | CVE-2026-55514 | `470229c37efaf69c86e8bc97482b0b1ff7551c65` | none — no rule coverage |

No-coverage is an **outcome** of the mechanical draw, not a filter. It is itself a
measurement: an unfiltered sample of recent Python advisories landed outside this
rule set. A later draw under the same rule may land inside it.

### Excluded and reserved

Excluded at sourcing: python-sql CVE-2024-9774 (Mercurial host), pg8000
CVE-2025-61385 (Codeberg blocks automated verification), feedparser issue #562
(fix PR unmerged at survey time).

Reserved, verified, **not** in this holdout: Django `_connector` SQLi
CVE-2025-64459 (`72d2c87…`) — an in-place SQL hardening fix, the natural blind
test for a future generic `py-sql-*` rule (D-015 Thread 2 Option B), except its
patch was read during sourcing and so is partially burned for that purpose;
djoser, jaraco.context, Keras, onnx, and vLLM tool-parser ReDoS; LightRAG
(property check needs a running API server).

## Verification configs

Each case has a property check (`examples/holdout2_*.toml`, `custom` adapter)
that asserts the upstream patch content and must pass **before** detector results
are interpreted. Detector output is never evidence that a patch does what its
advisory claims. Group A checks emit `VERISEC_EVIDENCE` for
`py-regex-redos-hardening`; Groups B and C emit `VERISEC_NOTE` with no rule
coverage. Checks were validated against the real patched files at freeze time
(transformers, pygments, and PyMySQL run-verified; all eight parse).

All run under the `custom` adapter, which `policy.py` blocks under
`untrusted-fork-pr`. This holdout is local or trusted-CI only. Pillow's merged fix
is pure-Python, so a wheel install supplies the extension its check needs.

## Partition overlap

`partition-audit --fail-on-overlap` against all three reference manifests, run on
the frozen `examples/holdout_2_cases.json`:

```
VeriSec partition audit passed: 8 case(s), 0 overlap pair(s).
```

No case shares a project with any reference partition; advisory IDs, base/head
pairs, and upstream commits are disjoint. vLLM appears exactly once (Group C), so
the groups are independent.

## Claim boundaries

- These are 8 curated cases across three groups. They are not an estimate of
  recall or precision on arbitrary real-world repositories.
- Primary recall is computed over Group A only (n=2). Groups B and C contribute to
  findings, noise, and precision, never to recall in either direction.
- The three groups answer different questions and must never be pooled into one
  recall figure.
- A low open-class result is the expected, honest outcome of measuring a
  Python-focused rule set against an unfiltered advisory sample. It is not a
  regression.
- Group A was selected by proposal-then-veto and carries residual selection risk;
  Group C was drawn mechanically and does not.
- n=2 for the primary group is small — too small to distinguish a weak detector
  from an unlucky draw with confidence. It is reported as a point observation, not
  an estimate, for the same reason the pilot's n=2 was.
- Blind only for cases whose detector behaviour has never been observed. Any case
  run before this freeze is burned; none were.

## Running the holdout (once)

```powershell
python -m verisec_agent eval --cases examples/holdout_2_cases.json `
  --out verisec-runs/holdout2-run
```

Runs local/trusted-CI only. It clones the eight upstream repositories at the
frozen base/head pairs, so it requires network access. Populate the Results table
below from that run, once, and do not re-tune detectors against these cases
afterward (Invariant 1).

## Results

Run once on 2026-07-22 against detector commit `0ca2df5`
(`verisec-runs/holdout2-run`). Published as measured; not re-run.

| Metric | A: primary-eligible (n=2) | B: removal-shape (n=3) | C: open-class (n=3) |
| --- | ---: | ---: | ---: |
| Cases | 2 | 3 | 3 |
| Findings | 0 | 0 | 0 |
| Primary finding recall | 0.00 | n/a | n/a |
| Primary precision | n/a (no findings) | n/a | n/a |
| Unexpected finding rate | 0.00 | 0.00 | 0.00 |
| Verification commands passed | 1/2 | 3/3 | 3/3 |
| Strict gate | failed (recall 0) | pass | pass |

**Headline: 0 findings across all 8 cases. Primary recall 0/2. Zero false
positives.**

Both primary-eligible cases missed, and for the same structural reason D-015
identified — `py-regex-redos-hardening` keys on `re.<func>(<inline pattern>` and
real fixes do not take that surface form:

- **transformers** (0 findings): the hardened pattern is assigned to a variable
  and used via `re.split(codeblock_pattern, ...)`. The rule's function list is
  `search|match|compile|fullmatch|findall|sub` — `split` is absent — and it
  requires the pattern inline, not through a variable.
- **pygments** (0 hypotheses generated): the rewritten regex is a bare string
  literal in a lexer token tuple, `(r'[0-9a-fA-F]{1,36}...', Literal)`, with no
  `re.` call anywhere. Nothing for the rule to anchor on.

This is the blind confirmation of D-015 on unseen data: the ReDoS hardening rule
does not generalize even within its own target class, because it matches a narrow
syntax that genuine hardening commits rarely use.

The result is not an artifact of a weak sample in the other direction either:
groups B and C produced **zero false positives** on six real security patches,
including removal-shape ReDoS/SQL fixes and out-of-scope classes. VeriSec stayed
silent where it should, and also silent where it should have fired.

**One case errored, and it does not change the detection result.** pygments'
property-check command crashed with `KeyError: '1,36'` because
`verification.py` renders argv via `str.format(**substitutions)` and the config
embeds the literal regex quantifier `{1,36}`, which `str.format` reads as a
replacement field. The crash occurs in the verification step, *after* the
detector generated its 0 hypotheses (recorded in the case trace), so the miss
above is a real detection result, not a crash artifact. The harness bug and the
config that triggered it are tracked separately (see DEVELOPMENT_LOG.md D-018);
they are not fixed by re-tuning any detector, and the holdout is not re-run.
