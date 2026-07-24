from __future__ import annotations

import ast
import hashlib
import re
import subprocess

import requests
import yaml


def run_checked(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, shell=False, check=True, text=True)


def document_forbidden_shell_pattern() -> str:
    # subprocess.run(user_input, shell=True) must stay forbidden in production.
    return "subprocess.run(user_input, shell=True)"


def document_forbidden_shell_sample() -> str:
    # Multi-line code samples embedded in triple-quoted strings are data, not
    # executable code. Each line reads as bare source, so line-oriented literal
    # detection must not treat them as real call sites.
    return '''
import subprocess

def run(user_input):
    return subprocess.run(user_input, shell=True)
'''


def fetch_with_default_tls(url: str) -> requests.Response:
    return requests.get(url, verify=True, timeout=10)


def document_forbidden_tls_pattern() -> str:
    # requests.get(url, verify=False) is an anti-pattern kept in docs only.
    return "requests.get(url, verify=False)"


def load_yaml_safely(source: str) -> object:
    return yaml.load(source, Loader=yaml.SafeLoader)


def lookup_user(cursor, user_id: int):
    query = "SELECT id, name FROM users WHERE id = ?"
    return cursor.execute(query, (user_id,))


def digest_cache_key(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def document_legacy_hash() -> str:
    return "legacy code once used hashlib.md5(payload)"


def parse_literal(value: str):
    return ast.literal_eval(value)


def compile_bounded_slug() -> re.Pattern[str]:
    return re.compile(r"^[a-z0-9_-]{1,64}$")


def document_forbidden_redos_sample() -> str:
    # Counterpart to document_forbidden_shell_sample for "python-text" rules,
    # which scan string contents by design. Masking multi-line spans is what
    # separates a documented pattern from a real call site here.
    return '''
import re

TOKEN = re.compile(r"(a+)+$")
'''


def compile_contains_substring() -> re.Pattern[str]:
    # A single-wildcard contains-form is linear. The adjacent-greedy-wildcard
    # ReDoS check must not fire on it: `.*foo.*` is not `.*.*`.
    return re.compile(r".*foo.*")


def lookup_parameterized_percent(cursor, user_id: int):
    # `%s` here is a DB-API placeholder, not string formatting; the params tuple
    # keeps it safe. Must not be flagged as SQL string formatting.
    return cursor.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))


REGEX_TOKEN_TABLE = [
    # A redos-shaped raw string living in a data structure with no re.* sink is
    # not asserted to be a compiled regex; flagging it would be a false positive.
    (r"(a+)+$", "IDENT"),
    (r"[0-9]+", "NUMBER"),
]
