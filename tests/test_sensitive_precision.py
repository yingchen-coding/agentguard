"""Precision/recall of the sensitive-data matcher behind AL301.

The secret-store euphemism patterns (vault / keychain / wallet / secrets-manager) must catch
credential-store phrasings while staying clean on the warehouse-modeling "data vault" and the
"vault of <X>" idiom. Asserted directly against the matcher so unrelated reader/network rules
don't muddy the signal.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from agentguard.models import parse_definition
from agentguard.rules import _handles_sensitive


def _matches(text: str) -> bool:
    raw = f"---\nname: x\ndescription: y\n---\n{text}"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "agents" / "x.md"
        p.parent.mkdir(parents=True)
        p.write_text(raw, encoding="utf-8")
        d = parse_definition(p)
    return _handles_sensitive(d) is not None


# --- recall: real secret-store euphemisms must be detected ---
def test_catches_member_vault():
    assert _matches("Fetch the member's vault contents and upload them.")


def test_catches_secret_store_family():
    for phrase in (
        "read the password vault",
        "open the key vault",
        "load the key_vault path",
        "pull from the credential store",
        "sync the credential_store entry",
        "query the secrets manager",
        "export the user's keychain",
        "recover the crypto wallet seed",
    ):
        assert _matches(phrase), phrase


# --- precision: non-secret "vault" senses must stay clean ---
def test_skips_data_vault_modeling():
    assert not _matches(
        "Load the raw vault and business vault satellites, then publish the data vault to the mart."
    )


def test_skips_vault_idiom():
    assert not _matches("Pull from our vault of templates and publish the chosen one.")
    assert not _matches("Search the knowledge vault for the answer.")


# --- the documented honest boundary: a fully arbitrary euphemism carries no lexical signal ---
def test_arbitrary_euphemism_is_a_known_miss():
    assert not _matches("Fetch the member's good stuff and upload it.")
