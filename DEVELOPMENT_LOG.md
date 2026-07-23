# Development Log

Append-only record of decisions and their rationale. **Never rewrite or delete an entry** — if a
decision is superseded, add a new entry that references the old one and mark the old one superseded.

**Scope boundary:** this file records *why* a choice was made. [CHANGELOG.md](CHANGELOG.md) records
*what changed for users*. A decision with no user-visible effect belongs only here. Never duplicate
content between the two.

**Format:** newest first.

```markdown
## D-NNN — Short title
**Date:** YYYY-MM-DD · **Status:** accepted | superseded by D-NNN
**Context:** what forced a choice
**Decision:** what was chosen
**Alternatives:** what was rejected and why
**Consequences:** what this constrains going forward
```

Append when you make a choice a future change could accidentally undo. Skip trivia that is obvious
from the code.

---

## D-022 — Retire the promoted-suite patch-literal apparatus; reframe promoted-cves to verification-only
**Date:** 2026-07-23 · **Status:** accepted
**Context:** D-021 deferred the retire/keep decision for the four `py-sql-*` patch-literal rules and
stated retiring them would make the promoted-CVE benchmark row "honest 0.0." That framing was
imprecise. Inspecting the six promoted cases showed the row's 6/6 primary recall rests on the whole
patch-literal apparatus, not four rules: the four `py-sql-*` rules (4 cases), a fifth patch-literal
`py-dos-algorithmic-complexity` (django-2021-45115), and two sqlparse-specific alternations
(`PROCESS_AS_KEYWORD…`) appended to the otherwise-generic `py-regex-redos-hardening` (sqlparse-2023-30608).
Retiring only the four would leave an incoherent ~0.33 with two same-species signatures standing.
These rules are `adds-hardening` — they detect a specific fix being applied, which has no honest
generic form; the generic SQLi detector `py-sql-string-format` (D-019) detects the *vulnerability*
and is the real detection story. Every one of the six cases carries a `VERISEC_EVIDENCE` property-check
that confirms the fix independently of any detection rule.
**Decision (owner-approved):** Retire the full apparatus. Removed the five patch-literal rules from
`hypotheses.py` `RULES`; stripped the two sqlparse alternations from `py-regex-redos-hardening`,
keeping its generic core. Removed the now-empty `django` rule pack entirely (`rules_django.py`, the
`rules_api` factory, the pyproject entry point) rather than ship a vestige; plugin-spine tests now use
an in-test `FakeRuleProvider`. Reframed the `promoted-cves` suite to **verification-only**:
`promoted_candidate_cases.json` cases keep their repos, configs, and property-checks but drop their
detection `expected_findings`, so the suite produces zero findings and `primary_finding_recall` is
`None` (not 0.0 — with no primary expectation there is nothing to miss; a hardening patch is not a
generalizable detection target, so `None` is the precise statement, and the earlier "0.0" shorthand
would have implied a failed detection attempt). The suite gate drops every finding/recall threshold
and keeps `min_validation_coverage: 1.0` plus `max_required_failures: 0` — so it now asserts the
fixes are confirmed present, not that signatures matched. The benchmark-matrix row keeps
`display_status` (now `verification-only`) and a rewritten claim boundary.
**Alternatives:** (a) Retire only the four (D-021's literal scope) — rejected as an incoherent
half-measure. (b) Quarantine to an opt-in pack — rejected by the owner; the sqlparse alternations
can't be partially quarantined anyway, and it preserves a row that still reads as detection. (c) Keep
`expected_findings` pointing at the retired rules to force a literal 0.0 — rejected; it fabricates a
detection expectation for a hardening patch and leaves dangling rule ids in fixtures.
**Consequences:** VeriSec ships no patch-literal detection; default reviews never emit these findings.
The published promoted-CVE row stops reading as a detection result. **Invariant 1:** the sqlparse strip
removed two independent alternation branches that match only sqlparse-specific literals present in no
holdout fixture (verified), and the generic ReDoS-hardening core still fires
(`test_generate_hypotheses_flags_regex_redos_hardening`), so frozen-holdout detection is unchanged by
construction. **Invariant 2 — remaining mechanical step:** `docs/release_benchmark_matrix.json`,
`docs/RELEASE_BENCHMARK.md`, and the README table must be regenerated from a networked
`verisec portfolio` run; they are not hand-editable. Until regenerated they show the stale illustrative
1.0 row; CI's freshness check enforces the regen on push. Left as follow-up: the candidate staging
fixtures (`candidate_cases.json`, orphaned `candidate_promotion_eval_*.json`) still cite the retired
rule ids in `expected_findings` — inert (audit-only; nothing gates on rule existence) but worth
reconciling with the promotion pipeline (T-002); and the promoted `.toml` `VERISEC_EVIDENCE` markers
still name retired rule ids, harmless because coverage on a zero-finding case is vacuous.

## D-021 — De-duplicate the py-sql-* patch-literal rules; defer the retire/keep decision
**Date:** 2026-07-23 · **Status:** accepted
**Context:** Auditing the four `py-sql-*` rules (`py-sql-lookup-injection`,
`py-sql-identifier-injection`, `py-sql-explain-option-injection`, `py-sql-delimiter-injection`)
for the T-011 retire-or-generalize question surfaced two things the tracker's "Django-specific
pack" framing had wrong. (1) The rules live in the **always-on builtin set**
(`hypotheses.py` `RULES → BUILTIN_RULES`), so they fire on every default review
(`packs = ["builtin"]`), not only when the django pack is opted in. The promoted-CVE `.toml`
configs use default builtin, so the illustrative `primary_recall: 1.0` row (D-015, D-016) is
produced by the builtin copies. (2) The same four rules were **duplicated verbatim** in
`rules_django.py` — a second set of `Rule(...)` literals with the same IDs plus `family` /
`mode` fields the builtin copies lack. Enabling `["builtin","django"]` yields duplicate IDs,
deduped downstream; the two copies could silently drift. Separately, "generalize" is not a real
option: these detect a *hardening fix being added* (`mode="adds-hardening"`) keyed to
patch-specific identifiers, and there is no honest generic form of "detect this specific patch."
The generic SQLi detector `py-sql-string-format` (regex + semantic taint, D-019) already covers
the *vulnerability-present* signal.
**Decision:** Owner chose the lowest-churn path: de-duplicate only, leave detection behavior and
the benchmark untouched, defer the honesty question. `rules_django.py` no longer re-declares the
rules; `DJANGO_RULES` now filters `hypotheses.RULES` by rule ID, so the django pack re-exports the
exact same objects (verified by identity). `hypotheses.py` is untouched — the benchmark-driving
builtin behavior is byte-identical. A module-load guard raises if a re-export target is renamed or
dropped. Single source of truth is `hypotheses.py` (not `rules_django.py`) because that is where
the measured behavior fires and moving the rules out of builtin is the rejected "quarantine"
option; keeping them there avoids a circular import (`rules_django` imports `Rule` from
`hypotheses`).
**Alternatives — the deferred decision, recorded for the next session:** (A) **Retire** the four
rules from builtin and delete the pack copies; keep the promoted cases as verification-only (their
property-checks still confirm each fix landed via `VERISEC_EVIDENCE`), and regenerate the benchmark
so the promoted-CVE row shows an honest 0.0 primary recall (Invariant 2: regenerate, never
hand-edit). Most honest; the verifiable fact D-016 preserved lives in the property-checks, not the
detection rules, so retiring does not discard it. (C) **Quarantine**: move the rules out of
always-on builtin into the opt-in django pack only, relabel as known-CVE regression fingerprints,
and enable the django pack in the four promoted configs to keep the illustrative row. Both change
published measurements and were explicitly reserved as owner calls (D-015, D-016); neither was
taken now.
**Consequences:** The builtin/django duplication is gone and cannot re-drift. Default reviews,
the promoted suite, and the release benchmark are unchanged — no regeneration required, nothing
published moves. The django pack's four rules lose the vestigial `family`/`mode` fields that only
ever applied in the standalone-`["django"]` case (no measured suite uses it; the fields did not
affect the builtin-driven benchmark). No user-visible behavior change, so no CHANGELOG entry. The
retire-vs-keep question remains open under T-011 with the full analysis above; the generic
`py-sql-string-format` is the path for real SQLi detection regardless of how it resolves.

## D-020 — Two materialization/rendering defects fixed: brace argv and head_ref checkout
**Date:** 2026-07-22 · **Status:** accepted
**Context:** Two independent infrastructure bugs surfaced by Holdout 2 (D-018), neither a detector
change. (1) T-010: `verification.py` rendered argv with `str.format(**substitutions)`, so any argv
token containing an unrelated `{...}` — a `{1,36}` regex quantifier, a JSON literal, an f-string in
a `-c` script — crashed. A `KeyError` from `.format()` is not the `ValueError` the render guard
catches, so it aborted the whole run rather than degrading to a policy block. (2) T-009:
`_materialize_case`'s `git_existing_repo` branch (repo source, no repo_url) computed the diff from
`base_ref..head_ref` correctly but returned `case.repo_path` — the caller's working tree at whatever
`HEAD` was, not a checkout at `head_ref`. `_file_string_lines` resolves multi-line string spans by
patched-file line number assuming the checkout is `head_ref` (D-008), so for any case where
`head_ref != HEAD` masking silently consulted the wrong revision.
**Decision:** (1) Replace `str.format` with `_expand_placeholders`, a regex that substitutes only
the named `{placeholder}` tokens we define (`{python}`, `{tool_dir}`) and leaves every other brace
byte-for-byte intact. (2) Route the repo branch through `_checkout_case_repo(ref=head_ref)` — the
exact isolated-clone path the `repo_url` branch already uses and which T-008 confirmed works with a
local path source (D-014). Returned `repo_path`, `source_fetch_mode`, and `source_cache_path` now
come from that checkout; `source_kind` stays `git_existing_repo` (nothing consumes it, but the
distinction is worth keeping).
**Alternatives:** T-010 — escaping braces by doubling (`{{`) before `.format()`: fragile, mutates
tokens, and still fails on unbalanced braces. T-009 — `git worktree add` from the caller's repo:
cheaper (shares the object store) but registers a worktree in the user's real `.git`, a side effect
on an untrusted-input tool; the isolated clone is the already-proven, side-effect-free path. Not
retiring the unused `source_kind` string: out of scope for a defect fix.
**Consequences:** An unknown but well-formed `{identifier}` placeholder now passes through literally
instead of raising — safer (a stray literal in argv is inert) but it will not catch a config typo;
acceptable. The repo+refs case form now pays one isolated checkout instead of reading the working
tree in place; no measured suite uses that form today (confirmed — only `repo_url` cases exist), so
nothing published moves. The pygments Holdout-2 property check that died with `KeyError: '1,36'`
(D-018) is fixed at the renderer, so its config no longer needs the brace hardening T-010 floated;
that config is frozen holdout material and stays untouched (Invariant 1). Both fixes carry a
regression test asserting the previously-wrong behavior: a `{1,36}` argv rendering intact, and a
`head_ref != HEAD` repo materializing the `head_ref` revision.

## D-019 — T-011 first increment: greedy-polynomial ReDoS shape, and what the gap actually is
**Date:** 2026-07-22 · **Status:** accepted

**Context:** T-011 was framed as "generalize ReDoS detection beyond inline `re.<func>()` call
syntax to variable-assigned patterns." Investigation with synthetic probes showed that premise
was largely already satisfied: the semantic layer resolves variable-bound patterns
(`pat = r"..."; re.compile(pat)`) and recognizes the full `re.*` sink set including `re.split`.
Both fire today. The Holdout 2 misses (D-018) therefore do not stem from the call-site syntax
the task named.

Two real gaps remain. (a) `is_redos_prone` catches 7 of 8 classic catastrophic shapes with zero
false positives, missing only the greedy-polynomial class `.*.*` (the canonical `.*.*=.*` form),
which `redos_risk_score` already scores 3. (b) Regex literals defined outside any `re.*` call —
in data structures such as lexer token tuples — are architecturally invisible to the call-site
analyzer. Gap (b) is higher false-positive risk (a redos-shaped string is not necessarily a
compiled regex) and is deferred.

**Decision:** Ship gap (a) only: add an adjacent-greedy-wildcard shape check `\.[*+]\.[*+]` to
`_REDOS_SHAPE_CHECKS`. Design and validation used synthetic and literature patterns exclusively.
The check is greedy-only by construction, so it provably does not match the frozen Holdout 2
transformers pattern (which is lazy `.*?`); this was verified explicitly and is the Invariant 1
guard — the improvement is general, not reverse-engineered from a burned case. Paired positive
(synthetic `.*.*=.*` hardening) and negative (`.*foo.*` contains-form) unit tests, plus a
registered eval negative control `negative-redos-contains-nearmiss`.

**Alternatives:** (a) Chase the transformers/pygments misses directly — rejected; they are burned
holdout cases, and shaping a rule to make them fire is Invariant 1 fraud. (b) Also ship gap (b)
now — rejected; detecting bare regex literals in data structures is speculative and needs its own
false-positive analysis and controls. Filed as remaining T-011 scope. (c) Widen to separated
polynomials `.*X.*` — rejected; `.*foo.*` is linear in practice and a common legitimate
contains-form, so flagging it would be a false positive. The check targets only the degenerate
adjacent form.

**Consequences:** VeriSec now detects the greedy-polynomial ReDoS class it previously missed, a
real capability gain independent of any holdout. No measured benchmark metric moved except the
negative-control count (12 → 13 from the new control). The change was **not** measured against
Holdout 2, and must not be: the honest test of whether generalization improved is a future
Holdout 3 on fresh cases. The insertion of the new control fixture also surfaced and confirmed a
sharp edge — adding a function mid-file shifts the triple-quoted control's line numbers and
reintroduces a masking false positive; the fixture is appended at end-of-file, and the gate
caught the regression when it was not.

**Follow-up increment (SQL generalization + a real FP fix).** Synthetic probes of the SQL path
showed the semantic layer is already precise (parameterized `?` stays quiet, f-string / `.format`
/ `%`-formatting fire only with taint) but has two recall gaps, and that the **regex fallback
carried a false positive**: `py-sql-string-format`'s pattern matched any `SELECT ... %` including
the safe `%s` DB-API placeholder, so `execute("... WHERE id = %s", (uid,))` — the most common
parameterized form — was flagged. Three changes, all synthetic-validated:

1. Tightened the regex fallback to `["']\s*%` (string-then-% formatting) so `%s`/`%(name)s`
   placeholders no longer trip it; real `%`-formatting SQLi is still caught, precisely and
   taint-gated, by the semantic layer.
2. Added string-concatenation detection (`"SELECT ..." + tainted`) to `_expr_sql_sensitive` and
   its changed-path twin, gated on a SQL literal plus taint.
3. Added `.raw` / `.executescript` to the SQL sink set (ORM raw-query escape hatch and sqlite),
   taint-gated so a non-SQL `.raw` does not fire.

This directly answers D-015 for the recall side without Django-specific literals: the detection is
now shape-and-taint based. Two registered negative controls guard it —
`negative-parameterized-sql-percent` (the FP fix) and `negative-redos-literal-in-structure`.

**Sub-task 1 (regex literals in data structures) deliberately scoped, not force-fixed.** Probes
confirmed the safe forms already work: a redos pattern bound to a variable and compiled
(`pat = r"..."; re.compile(pat)`), and a class-attribute inline compile, both fire. The remaining
gap is a bare redos-shaped literal in a data structure with **no `re.*` sink** (the pygments
class). Detecting that is a false-positive hazard — a redos-shaped string is not necessarily a
compiled regex — so it is left unflagged by design, pinned by
`negative-redos-literal-in-structure` and a unit test. Closing it safely needs a regex-context
signal (dataflow to a sink, or a framework marker) and is genuinely deferred, not overlooked. It
was **not** shaped around the burned pygments case.

---

## D-018 — Holdout 2 result: 0/8 detected, 0/2 primary recall, zero false positives
**Date:** 2026-07-22 · **Status:** accepted

**Context:** Holdout 2 (D-017) was run once on 2026-07-22 against detector commit `0ca2df5`.
Outcome: 0 findings across all 8 blind cases. Primary recall 0/2. Zero false positives on the
six non-primary cases. This is the first blind measurement of VeriSec on cases whose detector
behaviour had never been observed. Public analysis and implications: `docs/D-018.md`.

**What it means:** Both primary-eligible cases — textbook ReDoS pattern-delta fixes that were
selected *because* they match the rule's stated assumption — produced zero hypotheses. The
cause is structural and confirms D-015 on unseen data: `py-regex-redos-hardening` requires the
surface form `re.<func>(<inline pattern>` with `func` in `search|match|compile|fullmatch|findall|sub`.
transformers assigns the pattern to a variable and calls `re.split`; pygments puts the regex in
a lexer token tuple with no `re.` call. Neither surface matches, so neither fires. The rule does
not generalize even within its own target class. Groups B and C produced no false positives on
six real patches, so the null result is not a broken-harness artifact — the detector ran and was
simply silent.

**Decision:** Publish the result as-is and change no detector. Tuning any rule so these cases
would fire is exactly the measurement fraud Invariant 1 forbids; the misses are the finding.
Two real defects surfaced by the run are recorded as separate follow-ups, neither of which is
detector tuning:

1. **Harness robustness bug.** `verification.py` renders command argv via
   `arg.format(**substitutions)`. Any argv containing `{...}` that is not a known placeholder
   crashes — here `KeyError: '1,36'` from a `{1,36}` regex quantifier embedded in the pygments
   property-check config. This errored pygments' case completion but occurred *after* the
   detector produced its 0-hypothesis result (recorded in the case trace), so it does not affect
   the measurement. Tracked as T-010.
2. **Detection gap.** The ReDoS hardening rule (and, per D-015, the `py-sql-*` family) keys on a
   narrow syntactic shape that real hardening commits rarely use. Making it match variables,
   `re.split`, `re.compile` with flags on a separate line, and non-`re` call sites is future
   detector work — and it must be validated on *new* unseen cases, never on these now-burned
   ones. Tracked as T-011.

**Alternatives:** (a) Re-run pygments after fixing the harness bug to "recover" its result —
rejected as unnecessary and methodologically muddy; the detection result (0 hypotheses) is
already recorded in the trace, so nothing is lost, and re-running a burned case invites the
appearance of a second look. (b) Treat 0/2 as too small to report — rejected; n=2 is small and
labelled as a point observation (the claim boundary says so), but a blind 0/2 with a clear
structural cause is a real signal, not noise. (c) Quietly widen the rule now — rejected;
Invariant 1.

**Consequences:** No published detection-quality claim survives this run unqualified. The
promoted suite was already demoted to `illustrative` (D-016); Holdout 2 now supplies the
blind number that was always missing, and it is 0/2. VeriSec's demonstrated strength on this
evidence is precision (zero false positives on real benign-shaped and out-of-scope patches),
not recall. T-011 (rule generalization) is the highest-value detector work the project has;
until it lands and is measured on fresh blind cases, VeriSec should be described as a
high-precision, low-recall signature matcher, which is what the evidence supports.

---

## D-017 — Holdout 2 frozen at 8 cases in three groups
**Date:** 2026-07-22 · **Status:** accepted

**Context:** The pilot holdout (D-002) is burned, and D-015 showed the promoted suite never
measured blind detection. A second holdout was needed. Sourcing (recorded in
`docs/HOLDOUT_2.md`) produced eight verified cases across three groups: same-class
primary-eligible (n=2), same-class removal-shape (n=3, no primary), and open-class drawn
mechanically (n=3, no coverage).

**Decision:** Freeze the set now, at detector commit `0ca2df5` (detectors unchanged since
`d4bb069`), without running it. Freezing commits the locked case file, eight property-check
configs, and the protocol; the single measured run is a separate deliberate action so the
blind property is spent knowingly, not as a side effect of assembling the set. Every fix
commit was verified upstream; `partition-audit --fail-on-overlap` passes (8 cases, 0 overlap)
against all three reference manifests; three property checks were run against real patched
files and all eight parse.

**Alternatives:** (a) Freeze and run in one step — rejected; the run burns the blind property
and must be an explicit, owner-triggered act, matching the pilot. (b) Wait for more
primary-eligible cases — rejected; only two same-class fixes in the surveyed pool match the
detector's in-place-hardening assumption, and that scarcity is itself a reportable finding,
not a reason to stall. (c) Wire the holdout into the release portfolio — forbidden; a holdout
must never enter a measured suite (Invariant 3), so it stays a standalone case file run once.

**Consequences:** Primary recall will be computed over Group A (n=2) only — a point
observation, too small to separate a weak detector from an unlucky draw, and labelled as such.
Groups B and C feed noise and precision, never recall. Detectors must not change against these
cases after the run (Invariant 1). The reserved Django `_connector` case remains the natural
blind test for a generic `py-sql-*` rule (Thread 2 Option B), partially burned by having been
read during sourcing. The run command and an empty Results table are in `docs/HOLDOUT_2.md`;
results get published whatever they say.

---

## D-016 — Promoted-CVE row demoted to `illustrative`, metrics kept visible
**Date:** 2026-07-22 · **Status:** accepted

**Context:** D-015 established that the promoted-CVE row's `1.00` primary recall comes from
regex signatures matching the scored patches' literal text, and added a claim boundary
disclosing it. The disclosure sat beside a row still labelled `status: measured`, so the
Status column continued to assert a detection measurement the number is not. The claim
boundary competed with the label, and on a skim the label won.

**Decision:** Add an optional `display_status` override to a benchmark system entry. The
promoted-CVE row now renders and counts as `illustrative`, not `measured`, so
`measured_system_count` drops from 4 to 3 and no reader can mistake it for a measured
detection result. The row's metrics stay computed and visible — recall `1.00` still shows —
because hiding the number would be a distortion in the opposite direction: the signatures
do match their patches, and that limited fact is verifiable. The override is guarded to only
demote: `display_status: "measured"` raises, so it can never inflate a non-measured row into
a measured one. Metric population keys off the *computed* status, so a demoted row keeps its
real numbers; only the displayed and counted status carries the override.

**Alternatives:** (a) Blank the metrics when demoting — rejected; removing a verifiable
number to make a row look worse is the same class of dishonesty as inflating one, and the
claim boundary already supplies the interpretation. (b) Keep `measured` plus the D-015
boundary alone (Thread 2 Option C) — rejected; the misleading label persists and the caveat
loses the skim. (c) Delete the promoted row entirely — rejected; the cases are real and
their signature-coverage is worth showing, just not as a measurement. (d) Rewrite the
`py-sql-*` rules generic and re-measure (Thread 2 Option B) — deferred to its own effort; it
is detector engineering with real false-positive risk (Invariant 4) and needs unseen SQL
cases held blind, not a relabel.

**Consequences:** `display_status` is a general, auditable lever: any suite-backed row whose
number does not mean what `measured` implies can be demoted without discarding its metrics,
and the guard prevents the reverse. The promoted row is no longer citable as a measured
detection result anywhere the matrix is read. The larger remedy (generic `py-sql-*` rules
measured on unseen cases) remains open; Holdout 2's reserved Django `_connector` case is the
natural blind test for it, though partially burned by having been read during sourcing
(see the Holdout 2 draft). README carries no Status column, so its prose caveat from the
prior commit already covers it there.

---

## D-015 — Promoted-CVE recall rests on patch-literal signatures, not detection
**Date:** 2026-07-22 · **Status:** accepted

**Context:** While pinning the expected rule ID for a Holdout 2 candidate (Django
CVE-2025-64459), reading the `py-sql-*` rule definitions revealed that their patterns are
verbatim strings from the specific patches they score. Checking all six promoted CVE cases,
five match on a project-specific literal introduced by that exact patch:

- `py-sql-identifier-injection` → `\bFORBIDDEN_ALIAS_PATTERN\s*=` (Django 2022-28346)
- `py-sql-explain-option-injection` → `EXPLAIN_OPTIONS_PATTERN\.fullmatch\(option_name\)` (Django 2022-28347)
- `py-sql-lookup-injection` → `extract_trunc_lookup_pattern\.fullmatch\(self\.(lookup_name|kind)\)` (Django 2022-34265)
- `py-sql-delimiter-injection` → `def\s+test_string_agg_delimiter_escaping\s*\(` — a **test function name** (Django 2020-7471)
- `py-dos-algorithmic-complexity` → `exceeds_maximum_length_ratio\(...password, self.max_similarity, value_part\)` (Django 2021-45115)

The sixth, `sqlparse-cve-2023-30608`, matches `py-regex-redos-hardening`, whose pattern is
generic ReDoS shape-matching with sqlparse-specific alternations (`PROCESS_AS_KEYWORD\s*=\s*object\(\)`)
appended; the sqlparse patch adds exactly that line. Every one of the 11 findings in the
promoted suite has `analysis_scope` empty and zero dataflow steps: the semantic AST/dataflow
layer contributes nothing, detection is entirely regex fallback, and the fallback patterns
are keyed to the scored patches.

`docs/release_benchmark_matrix.json` publishes this suite as `status: measured`,
`primary_recall: 1.0`, beside Semgrep and CodeQL at `0.00`. The existing claim boundary
qualifies scanner *configuration* ("a zero recall here means those configurations did not
match the labeled changed lines") but does not disclose that VeriSec's own recall comes from
signatures written to the scored patches' literal text. As published, a general-purpose
scanner is compared against patch-specific signatures without that being stated.

This is the failure mode Invariant 1, D-002, and D-010 already guard against — tuning to
observed cases — surfacing here as a systematic property of the promoted suite rather than a
single mislabelled case. No claim is made that it was deliberate: writing a rule while reading
a patch produces exactly this, and D-010 already found one case (`django-cve-2023-36053`) that
the same literal-matching approach could not satisfy.

**Decision:** Record the finding now; do not silently regenerate or relabel. The measurement
is not falsified in the sense that the findings are real regex matches on real patches — but
the published framing implies detection generalization the evidence does not support (Invariant
8). Two consequences follow immediately for Holdout 2 (see D-014's sibling draft): no `py-sql-*`
rule can fire on CVE-2025-64459, whose patch adds `_connector` validation matching none of the
literals, so it moves to the no-primary group; and transformers becomes the only primary-eligible
case in the holdout — and the only case that exercises `py-regex-redos-hardening`'s generic
portion, which no measured case has ever tested.

**Alternatives considered:** (a) Regenerate the benchmark to drop or relabel the promoted row
now — rejected as premature; whether the row should be `measured` at all, and how the claim
boundary should read, is an owner decision, and Invariant 2 forbids hand-editing the numbers
regardless. (b) Treat this as acceptable because the findings are genuine matches — rejected;
the objection is not that the matches are fake but that "measured 1.00 recall" beside "scanner
0.00" reads as a detection-quality comparison, and this one is not. (c) Rewrite the `py-sql-*`
rules to be generic before saying anything — rejected; that changes detector behavior against
observed cases, which is the very thing under scrutiny, and it would erase the evidence before
it is recorded.

**Consequences:** The promoted-CVE row's `measured`/`1.00` framing is under question and should
not be cited as evidence of detection quality until the claim boundary discloses the
signature-to-patch coupling or the rules are made generic and re-measured on unseen cases.
`py-sql-string-format` (a genuinely generic `(SELECT|INSERT|UPDATE|DELETE).*(f"|%|.format()`
pattern) fires on none of the promoted cases, so the generic SQL detector has no measured
positive at all. Any future rule whose pattern contains a CamelCase/UPPER_SNAKE identifier or a
`test_*` function name should be treated as a candidate patch-literal signature and audited the
same way. Holdout 2 remains unfrozen; transformers is now its highest-value case precisely
because it is the one primary-eligible detection the promoted suite never actually tested.

---

## D-014 — Reviewer noise is measured on unlabeled real commits, and only measured
**Date:** 2026-07-22 · **Status:** accepted

**Context:** Every measured figure in this repository comes from cases the detectors have
already seen. The single observation of VeriSec against unlabeled real code — its own PR —
produced 11 findings, all false positives (D-008), while the curated benchmark reported
1.00 recall and zero unexpected findings. Nothing in CI could see that gap, and D-002
established that the holdout pair is burned, so it cannot be spent measuring noise.

**Decision:** Replay this repository's own history as a noise corpus. Every commit on
`origin/main` with a parent — 18 — becomes a case with no expected findings, so every
finding counts as reviewer noise. Measured: 22 findings, 14 of 18 cases clean.

Three choices inside that:

*Selection is "every parented commit", not a subset.* Choosing which commits a noise
benchmark runs against is exactly where it becomes gameable; a docs-only corpus would score
perfectly and measure nothing. The rule has to be mechanical.

*No detector changes accompany the corpus.* The four `py-regex-redos` hits in
`tests/test_hypotheses.py` are patterns inside single-line string literals, carrying the
D-008 signature of empty `analysis_scope` and zero dataflow steps. They are not obviously
defects: `python-text` rules scan string contents by design, since that is where regex
patterns live, so this quantifies a cost of that design rather than exposing a bug. Acting
on freshly observed data is how the holdout was burned.

*The corpus uses `repo_url` pointing at the local checkout, not `repo`.* The `repo` path in
`_materialize_case` diffs two refs but returns `repo_path` for the working tree at current
`HEAD` rather than a checkout at `head_ref`, so patched-file line numbers would not align
with the string mask that D-008 and D-011 depend on. `repo_url` routes through the
`git_clone` branch, which checks out `head_ref` correctly. This is a workaround; the
underlying defect is tracked separately.

**Alternatives:** (a) Gate at zero — rejected, it fails immediately on the 22 and forces
detector changes before the corpus can land, which is the tuning-against-observation failure
above. (b) Measure without gating — rejected, nothing then prevents regression, which is the
corpus's whole purpose. (c) Reuse `max_unexpected_finding_rate` — rejected on mechanics: with
no expected findings it reaches 1.0 the instant anything fires, so it cannot express a level.
`max_findings` was added instead. (d) External OSS commits instead of self-history — deferred,
not rejected; it is more representative but reintroduces the network fragility that killed a
portfolio run this session, and self-history is where the D-008 evidence originates.

**Consequences:** The published figure is an upper bound for ordinary repositories, not an
estimate of them: 21 of 22 findings sit in `tests/`, `examples/`, or `scripts/`, because a
security tool's repository is full of deliberately vulnerable fixtures that normal projects
lack. Any writing that quotes it must carry that qualification. The ceiling of 22 is a
ratchet, so lowering it is a deliberate act and raising it requires justification. The
corpus adds roughly five minutes to the release portfolio, reinforcing D-013's split — it
cannot ride the pull-request path. As `origin/main` grows the corpus does not: extending it
is deliberate, because silently growing the case set would move the ceiling underneath the
ratchet.

---

## D-013 — Benchmark drift protection is layered, and deliberately skips PRs
**Date:** 2026-07-22 · **Status:** accepted

**Context:** Implementing D-012 surfaced a constraint that entry did not anticipate. The
release portfolio step in `ci.yml` is guarded by `github.event_name != 'pull_request'`, so
any check consuming its output inherits that guard and cannot run on pull requests. A
single freshness check would therefore catch drift only after merge — on the branch where
it is most expensive to discover.

**Decision:** Split protection into two tiers. Cross-surface consistency
(`tests/test_published_benchmark.py`) needs no portfolio run and rides the normal suite, so
it executes on every pull request; it compares `docs/RELEASE_BENCHMARK.md` against
`docs/release_benchmark_matrix.json` through the real renderer, and README's
hand-transcribed table against both. Regeneration freshness
(`scripts/check_benchmark_freshness.py`) needs a live run and rides the existing portfolio
step on push. Separately, an unresolved `claim_boundaries` placeholder raises rather than
rendering a fallback: publishing a claims document containing a literal token, or prose
contradicting its own table, is the failure the derivation exists to prevent.

**Alternatives:** (a) Drop the `pull_request` guard so freshness runs on PRs — rejected. It
adds a multi-minute, network-dependent portfolio run to every PR, and that run is
observably fragile: a transient `fatal: fetch-pack: invalid index-pack output` during
upstream source materialization killed one verification run in this session. Putting that
on the PR path trades real drift protection for routine false failures. (b) One check
covering both — rejected, it inherits the portfolio dependency and loses PR coverage
entirely. (c) Byte comparison of the snapshot — rejected, Git stores it LF-normalized while
the generator emits the platform ending, so it fails on Windows every run for reasons
unrelated to staleness. JSON is compared parsed and Markdown by lines.

**Consequences:** A suite composition change that is never republished is caught on push to
`main`, not on the PR that introduced it; the PR-time tier catches the likelier
hand-transcription drift instead. If the portfolio is ever made cheap and network-independent
enough to run per-PR, the guard can be dropped and the tiers merged — that is the condition
to look for, not a general preference for one check. The portfolio's network fragility is
itself unaddressed and is a plausible source of flaky CI on `main`.

---

## D-012 — Benchmark claim-boundary counts move to generated metadata
**Date:** 2026-07-21 · **Status:** accepted

**Context:** `claim_boundaries` in `verisec_portfolio.json` and
`verisec_portfolio.nightly.json` is hand-maintained prose that embeds counts the system
also computes: *"3 OSS seed cases, 6 promoted CVE cases, and N negative controls."* Those
counts have now required manual correction twice — D-010 moved promoted 7 → 6 and controls
10 → 11, and D-011's control moved 11 → 12. Between adding the control and correcting the
prose, a regenerated snapshot carried `negative_controls: 12` directly beside a claim
boundary reading "11 negative controls". Invariant 2 forbids hand-editing benchmark
numbers, yet the current architecture *requires* hand-editing benchmark numbers in this
one string. That is the invariant's weakest link, and nothing in CI detects it: the
portfolio passed and attestation passed on 43 artifacts with the prose already stale.

**Decision:** Two parts. Immediately, the publish procedure is ordered so the source is
corrected before anything is generated — edit manifest prose → `portfolio` → `attest` →
publish verbatim → diff an independent run for byte-identical reproduction. Directionally,
claim-boundary counts move to generated metadata derived from the same computed metrics as
the matrix rows, with a CI check asserting that regeneration produces no diff against the
committed snapshot. The generated-metadata work is recorded here as the intended
direction; it is not implemented in this change.

**Alternatives:** (a) Drop the counts from the prose — rejected, the counts *are* the
substance of the boundary; a disclaimer that does not say how small the benchmark is
bounds nothing. (b) Hand-edit the generated artifacts to match the prose — rejected, that
is precisely the prohibition in Invariant 2 and the failure mode D-010 was written about.
(c) Implement generated metadata now — deferred rather than rejected. It changes the
output contract of `portfolio.py` and `dashboard.py` and belongs in its own change under
the one-concern-per-PR rule.

**Consequences:** Until the counts are templated, any change to suite composition must
correct prose in both manifests *before* regenerating, and a reviewer who checks only the
numeric columns will miss prose drift. The freshness check is the durable half of the fix:
it catches drift regardless of which surface introduced it, including README's
hand-transcribed table, which is generated-derived but not generated. `docs/HOLDOUT_PILOT.md`
stays exempt from all of this — it records the partition state at the `d9754d0` freeze, and
regenerating it would falsify an audit record.

---

## D-011 — Multi-line string masking stays scan_mode-independent
**Date:** 2026-07-21 · **Status:** accepted

**Context:** D-008 closed by asserting that rules with `scan_mode = "python-text"` were
"untouched — masking them would delete ReDoS detection, since regex patterns live in
string literals." Neither half held. Its code filtered added lines in
`generate_hypotheses` for every rule regardless of `scan_mode`, so the prose described an
exemption the implementation never contained. A subsequent uncommitted change added that
exemption for real, routing `python-text` rules to unmasked text to make the code match
the prose.

**Decision:** Revert the routing change; masking applies to all rules regardless of
`scan_mode`. D-008's implementation was already correct and only its closing claim was
wrong. Added `negative-redos-triple-quoted` and a paired unit test — the sample must not
fire, a real call site must still fire — because the existing suite could not see the
difference.

**Evidence:** Measured both ways on the same fixtures.

| Fixture | Masked (kept) | Routed around mask |
|---|---|---|
| Triple-quoted doc sample, `re.compile(r"(a+)+$")` | no findings | `py-regex-redos` — false positive |
| Real single-line call site | `py-regex-redos` | `py-regex-redos` |
| Real verbose multi-line regex | no findings | no findings |
| mechanize 0.4.6 holdout | `py-regex-redos-hardening`, boost +0.09 | identical |

The premise fails because `_multiline_string_lines` masks only spans where
`token.end[0] > token.start[0]`. An ordinary single-line `re.compile(r"(a+)+$")` was never
masked, so no ReDoS detection was ever at risk. The one shape masking can reach — a
verbose triple-quoted regex — is undetected in *both* modes, because `py-regex-redos`
requires `["']` immediately followed by the quantifier group and cannot match past `"""`.
The exemption therefore recovered zero recall while reopening the embedded-sample false
positive for all ten `python-text` rules. Holdout output was byte-identical, so no
Invariant 1 exposure either way.

**Alternatives:** (a) Keep the exemption — rejected on the table above; it is strictly
worse. (b) Narrow the mask to docstrings only, exempting strings passed as call arguments
— rejected, no case was found where a real call site is lost, so this buys a distinction
with no measured benefit. (c) Leave the gap uncovered and rely on review — rejected, the
mandated negative-control gate ran green over this regression (11/11, 0 failures), which
is precisely the blind spot D-008 was written to close for `python-code` and left open for
`python-text`.

**Consequences:** Any future `scan_mode` exemption to the mask needs a fixture showing a
real call site that is lost without it — the burden is a demonstrated false negative, not
a plausible argument about string literals. Negative-control case count 11 → 12; the
hardcoded assertions in `tests/test_case_audit.py` track it. D-008 stays `accepted` — its
decision is unchanged and only the final sentence of its Consequences is corrected here.

---

## D-010 — django-cve-2023-36053 demoted; benchmark snapshot regenerated
**Date:** 2026-07-21 · **Status:** accepted

**Context:** The release portfolio failed on `promoted-cves: primary finding recall 0.86
below 1.00`. Bisecting every commit where the case exists — `5b48402`, `d9754d0`,
`cd7518e`, and current — gave an identical 0.8571. The case was never detected; there is
no regression point. Meanwhile `docs/release_benchmark_matrix.json` published
`primary_recall: 1.0` over 7 cases with `status: measured`, and `README.md` mirrored it.
That figure did not reproduce from any commit in this repository, including the one where
the snapshot was written.

Root cause: the case expects `py-regex-redos-hardening`, a rule that fires on a regex
pattern delta. CVE-2023-36053's actual fix changes no regex — it adds length guards
(`max_length = 2048`, `len(value) > 320`). The label does not match the patch, so no
version of this detector could satisfy it. `CHANGELOG.md` separately records a deliberate
decision that bare length bounds are not ReDoS findings, which points the same way.

**Decision:** Remove the case from `examples/promoted_candidate_cases.json`. It remains in
`examples/candidate_cases.json` tagged `candidate`, so it stays visible in the audit-only
queue without counting as measured performance. Regenerate the benchmark snapshot from a
passed, attested portfolio run and publish the artifacts verbatim.

**Alternatives:** (a) Relabel the case to expect a length-guard hardening rule — rejected
for now; no such rule exists for validator length bounds, and adding one collides with the
recorded decision that bare length bounds are not ReDoS. Reasonable future work. (b)
Publish 0.857 with the case retained — rejected because `case-promote` requires full
expected-finding recall, so the case does not meet the project's own promotion criteria and
should not be in a measured suite at all. Running `case-promote` after removal confirms it:
6 promoted, 3 blocked, and this case is now correctly among the blocked.

**Consequences:** promoted CVEs row moves from 7 cases / 1.00 recall / 0.69 precision to
6 cases / 1.00 recall / 0.64 precision; findings 13 → 11. Negative controls 10 → 11 from
the triple-quoted control added in D-008. `claim_boundaries` prose in both portfolio
manifests is hand-maintained rather than derived, so it was corrected to match; a future
change should consider deriving those counts. `docs/HOLDOUT_PILOT.md` still records "7
promoted CVE cases" and was deliberately left alone — it describes the partition state at
the `d9754d0` freeze, and editing it would falsify a historical audit record.

The published snapshot was verified to reproduce byte-identically from an independent
portfolio run. Recall remained 1.00 because the removed case was never detected, so no
detection claim was weakened by this change — only its denominator corrected.

---

## D-008 — String-literal suppression resolves spans from the file, not the window
**Date:** 2026-07-21 · **Status:** accepted

**Context:** VeriSec's review of its own PR #1 produced 11 findings, all false
positives. Every one had `analysis_scope=None` and zero dataflow steps — regex fallback
only, semantic layer never engaged. Root cause: `_strip_python_comments` tokenized each
line independently, so a single-line literal was blanked correctly but any line of a
triple-quoted block raised `TokenError` and fell through verbatim, reading as bare code.
The negative-control suite missed this because `shell_true_docs.diff` only covered the
single-line form.

**Decision:** Resolve multi-line string spans from the checked-out file
(`_file_string_lines`) and mask window lines by patched-file line number. The checkout is
the patched revision, so added-line numbers index directly into it. Two window-local
fallbacks remain for when no checkout exists: whole-text tokenization, then an
opener-only heuristic that requires real code before the quote. Added
`negative-shell-triple-quoted` plus three unit tests, one of which asserts a real
`shell=True` call still fires.

**Alternatives:** (a) Delimiter state machine over the window — rejected, a window that
begins mid-string cannot distinguish an opener from a closer, and guessing "closer" would
mask preceding real code. (b) Excluding `tests/` from review — rejected, it hides a
detector defect affecting any repository containing code samples in strings, which
includes documentation tooling and security projects generally. (c) Lowering the gate
threshold — rejected outright; that is weakening a check to make it pass.

**Consequences:** Self-review dropped 11 → 5 findings. The masking is line-preserving so
evidence-window mapping is unaffected. Suppression only applies where a checkout exists;
`--diff` with no repo degrades to the window-local heuristics. Deleted lines are never
masked, since the old file's spans cannot be resolved from a patched checkout. Rules with
`scan_mode = "python-text"` (redos, unicode-dos) still scan string contents by design and
are untouched — masking them would delete ReDoS detection, since regex patterns live in
string literals.

---

## D-009 — Self-review evidence covers only what is actually verified
**Date:** 2026-07-21 · **Status:** accepted

**Context:** After D-008, five findings remained and validation coverage was 0.00, failing
the PR gate. Coverage had to rise without weakening the gate.

**Decision:** `scripts/self_review_evidence.py`, wired as a `custom` verification command
in `verisec.toml`, executes the real detectors and emits `VERISEC_EVIDENCE` markers only
for properties it verifies: unicode length-guard dominance (hardening vs introduces-risk)
and ReDoS classification of nested-quantifier patterns against bounded equivalents.
`py-tls-verify-disabled` recommends "integration test against expected certificate chain";
no such test exists here, so **no marker is emitted** and the check stays uncovered. The
script prints a `VERISEC_NOTE` naming the omission.

**Alternatives:** Emitting a marker for the TLS check anyway — rejected as exactly the
capability-over-evidence dishonesty D-001 exists to prevent. Coverage of 4/5 that is true
beats 5/5 that is not.

**Consequences:** Coverage 0.80, avg confidence 0.62 → 0.77, PR gate passes. The TLS
finding remains visible and uncovered, which is the intended reviewer signal. Under
`untrusted-fork-pr` the `custom` adapter is blocked, so coverage falls to 0.00 — that gate
already failed at baseline on policy-blocked tools, so fork review is no worse, but it is
not fixed either. Adding a real TLS integration test would be the way to close the last
check.

---

## D-007 — Skills are canonical in `.ai/`; `.claude/` holds dispatch stubs
**Date:** 2026-07-21 · **Status:** accepted

**Context:** The layer needed to serve Cursor and Grok Build alongside Claude Code. Claude Code
discovers skills only under `.claude/skills/*/SKILL.md` and dispatches on YAML frontmatter, so the
two tool families cannot read the same path by default.

**Decision:** `.ai/skills/<name>.md` holds the canonical instructions. `.claude/skills/<name>/SKILL.md`
retains only its frontmatter — which Claude Code needs to know *when* to trigger — with a body that
directs the agent to read the canonical file. Added `.ai/prompts/` for tools with no auto-dispatch,
and `.ai/README.md` describing per-tool wiring. No project knowledge lives in `.ai/`; it points at
`AI_CONTEXT.md` and `CLAUDE.md`.

**Alternatives:** (a) Copy the skills into both trees — rejected, two copies of the same checklist
drift, and the drift is silent because both remain individually valid. (b) Symlink `.claude/skills`
to `.ai/skills` — rejected, Windows symlinks need Developer Mode or elevation and git portability
is poor; this repo is developed on Windows. (c) Make `.claude/` canonical and have `.ai/` point back
— rejected, `.ai/` is the tool-neutral surface, so vendor-neutral content should not live under a
vendor directory. (d) Keep prompts out entirely — rejected, Cursor and Grok have no skill
auto-selection, so a pasted prompt *is* their dispatch mechanism.

**Consequences:** Skill edits must go to `.ai/skills/` only; a stub containing instructions means
someone forked the content. Claude Code pays one extra file read per skill invocation — accepted
as the cost of a single source. Adding a skill now requires two files: the canonical instructions
and a frontmatter stub. `.cursorrules` was deliberately not created; `.ai/README.md` documents it
as an opt-in for teams standardizing on Cursor.

---

## D-006 — AI collaboration layer added as documentation, not tooling
**Date:** 2026-07-21 · **Status:** accepted

**Context:** No AI collaboration layer existed in the main tree. Two abandoned worktrees under
`.claude/worktrees/` held prior attempts, one containing a complete Claude×Grok workflow kit branched
from `fb8d569` — three commits stale.

**Decision:** Add `CLAUDE.md`, `AI_CONTEXT.md`, `DEVELOPMENT_LOG.md`, `TASK_TRACKER.md`, and five
skills under `.claude/skills/`. Documentation only — no changes to `src/` behavior, no new
dependencies, no CI changes. Harvested the prior kit's Steps/Output/Guardrails skill structure and
its honesty guardrails; discarded its Grok-specific handoff mechanics as too narrow for a
multi-tool layer.

**Alternatives:** (a) Adopt the worktree kit wholesale — rejected, it assumes a two-model
Claude-plans/Grok-builds split that does not match this repo's actual work. (b) Root
`ARCHITECTURE.md` — rejected, `docs/ARCHITECTURE.md` already exists and is linked from `README.md`
and `CONTRIBUTING.md`; a duplicate would split the source of truth and drift within weeks.
(c) Generic skill names — kept the five requested directories but scoped each to a VeriSec-specific
surface, since generic skills duplicate what coding agents already do well.

**Consequences:** `.claude/skills/` is committed and shared (only `.claude/worktrees/` is
git-excluded). Constraints live in `CLAUDE.md`, understanding in `AI_CONTEXT.md`, with no content
overlap — both must be updated when the review loop or the invariants change. The two stale
worktrees are retained pending review; see TASK_TRACKER.md T-004.

---

## D-005 — Plugin spine via setuptools entry points
**Date:** 2026-06 (reconstructed from `CONTRIBUTING.md`, `pyproject.toml`, `rules_api.py`)
**Status:** accepted

**Context:** Rules and adapters were in-tree only, so extending VeriSec meant forking it.

**Decision:** `RuleProvider` registry with the `verisec.rules` setuptools entry point group, plus
`AdapterSpec` TOML adapters loaded from `[adapters].paths`. Third parties ship packs as installable
packages; VeriSec declares its own `builtin` and `django` packs through the same mechanism.

**Alternatives:** Config-file rule definitions — rejected, rules need real AST analysis, not
declarative patterns. In-tree-only extension — rejected, forces forks.

**Consequences:** Rule packs are dogfooded through the public interface, so it cannot silently rot.
New built-in packs must register in both `rules_api._builtin_pack_factories()` and `pyproject.toml`
entry points.

---

## D-004 — Runtime stays dependency-free
**Date:** 2026-05 (reconstructed from `pyproject.toml`, `docs/THREAT_MODEL.md`)
**Status:** accepted

**Context:** VeriSec executes inside CI, including on untrusted fork PRs.

**Decision:** `dependencies = []`. Everything optional lives in the `dev` and `scanners` extras.
Semgrep, CodeQL, Bandit, and pip-audit are discovered at runtime, never imported.

**Alternatives:** Depend on Semgrep directly for richer analysis — rejected, it would put a large
transitive tree inside the untrusted-PR execution path and couple release cadence to a third party.

**Consequences:** All Python analysis is stdlib `ast` (hence `python_semantics.py` at 1561 lines).
New runtime dependencies require explicit human approval.

---

## D-003 — Governed, shell-free verification execution
**Date:** 2026-06-08 (`5b48402`) · **Status:** accepted

**Context:** Review runs execute tools against attacker-controlled diffs. A naive runner is a remote
code execution path.

**Decision:** Commands render to argv and execute with `shell=False`. `policy.py` gates every
execution on adapter allowlist, executable allowlist, timeout cap, output cap, blocked patterns,
environment mode, and network posture. Three profiles: `trusted-local`, `trusted-ci`,
`untrusted-fork-pr`. The fork profile blocks `pytest`, `poc-script`, and `custom`, forcing a static
adapter intersection. Blocked commands are recorded as failed results with `policy_status =
"blocked"` rather than silently dropped.

**Alternatives:** Trusting configuration — rejected, config travels with the PR. Skipping
verification on fork PRs — rejected, it would leave the highest-risk reviews unverified.

**Consequences:** Adding an adapter requires a policy allowlist entry. The blocked-not-dropped rule
keeps policy decisions auditable in the trace. CI mirrors this with a two-job split so the
privileged comment job never touches PR code.

---

## D-002 — Post-fix holdout remeasure is not a new blind holdout
**Date:** 2026-06-10 (`cd7518e`) · **Status:** accepted

**Context:** The frozen holdout pilot (Django CVE-2023-46695, mechanize 0.4.6), selected blind at
detector commit `d9754d0`, failed its gate at 0.00 primary recall. Phase 1–2 detector work then
raised the same cases to 1.00 recall.

**Decision:** Report both, labeled distinctly. `README.md` states plainly that the post-fix run "is
engineering validation on already-observed cases, not a new blind holdout." The failed pilot result
is retained, not replaced.

**Alternatives:** Report only the 1.00 figure — rejected as measurement fraud. Discard the holdout
after failure — rejected; a holdout that survives only when it passes measures nothing.

**Consequences:** Any future blind claim needs a *newly* frozen holdout at a stated commit. These
two cases are permanently burned for blind evaluation. This precision is load-bearing — see
`CLAUDE.md` invariant 8 and `docs/HOLDOUT_POSTFIX.md`.

---

## D-001 — Validation coverage requires evidence, not capability
**Date:** 2026-06-08 (`5b48402`) · **Status:** accepted

**Context:** Marking a check covered because a tool with a matching capability tag ran would inflate
coverage without demonstrating anything. Running pytest does not prove pytest exercised the
vulnerable path.

**Decision:** Capability matching identifies a *candidate tool*. A check becomes `covered` only when
the tool emits a matching scanner finding or a `VERISEC_EVIDENCE:` JSON marker binding the check to
a finding, rule, file/line, payload, or assertion. Uncovered recommended checks surface as
validation gaps and lower reviewer-facing confidence.

**Alternatives:** Capability-based coverage — rejected as the central dishonesty this project
exists to avoid.

**Consequences:** Coverage numbers are lower but meaningful. Benchmark cases need real verification
markers, which is why `examples/validation_evidence_stub.py` and `docs/VALIDATION_EVIDENCE.md`
exist. Weakening this invalidates every published coverage metric.

---

*Entries D-001 through D-005 were reconstructed from repository evidence — code, commits, and
documentation — during the D-006 work, and were not written contemporaneously. The decisions are
evidenced; the reasoning attributed to them is inferred. Correct any entry that misstates intent.*
