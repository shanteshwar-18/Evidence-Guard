"""
P2 – Permission matrix test.
35 test cases: 5 roles x 7 core actions = 35 cases.
Run: pytest backend/tests/test_permissions.py -v
"""

import pytest

from app.core.auth import can

# 5 roles x 9 actions = 45 combinations
# Expected matrix derived from docs/contracts/permissions.yaml

EXPECTED = {
    # (role, action): expected_result
    # admin
    ("admin", "register_evidence"):  True,
    ("admin", "read_evidence"):      True,
    ("admin", "transfer_evidence"):  True,
    ("admin", "run_ai"):             False,   # admin does not investigate
    ("admin", "review_ai"):          True,
    ("admin", "seal_case"):          True,
    ("admin", "manage_users"):       True,
    ("admin", "generate_report"):    True,
    ("admin", "view_audit_log"):     True,

    # investigator
    ("investigator", "register_evidence"):  True,
    ("investigator", "read_evidence"):      True,
    ("investigator", "transfer_evidence"):  True,
    ("investigator", "run_ai"):             True,
    ("investigator", "review_ai"):          True,
    ("investigator", "seal_case"):          False,  # only supervisor
    ("investigator", "manage_users"):       False,
    ("investigator", "generate_report"):    True,
    ("investigator", "view_audit_log"):     True,

    # analyst
    ("analyst", "register_evidence"):  False,
    ("analyst", "read_evidence"):      True,
    ("analyst", "transfer_evidence"):  False,
    ("analyst", "run_ai"):             True,
    ("analyst", "review_ai"):          True,
    ("analyst", "seal_case"):          False,
    ("analyst", "manage_users"):       False,
    ("analyst", "generate_report"):    True,
    ("analyst", "view_audit_log"):     False,

    # supervisor
    ("supervisor", "register_evidence"):  False,
    ("supervisor", "read_evidence"):      True,
    ("supervisor", "transfer_evidence"):  False,
    ("supervisor", "run_ai"):             False,
    ("supervisor", "review_ai"):          True,
    ("supervisor", "seal_case"):          True,
    ("supervisor", "manage_users"):       False,
    ("supervisor", "generate_report"):    True,
    ("supervisor", "view_audit_log"):     True,

    # viewer
    ("viewer", "register_evidence"):  False,
    ("viewer", "read_evidence"):      True,
    ("viewer", "transfer_evidence"):  False,
    ("viewer", "run_ai"):             False,
    ("viewer", "review_ai"):          False,
    ("viewer", "seal_case"):          False,
    ("viewer", "manage_users"):       False,
    ("viewer", "generate_report"):    False,
    ("viewer", "view_audit_log"):     False,
}


@pytest.mark.parametrize("role,action,expected", [
    (role, action, expected)
    for (role, action), expected in EXPECTED.items()
])
def test_permission(role: str, action: str, expected: bool):
    """Each (role, action) pair must match the expected permission."""
    result = can(role, action)
    assert result == expected, (
        f"can('{role}', '{action}') = {result}, expected {expected}"
    )


def test_unknown_role_is_denied():
    """An unknown role must be denied every action."""
    assert can("unknown_role", "register_evidence") is False
    assert can("", "read_evidence") is False


def test_unknown_action_is_denied():
    """An unknown action must be denied for all roles."""
    assert can("admin", "nonexistent_action") is False
    assert can("investigator", "nonexistent_action") is False


def test_analyst_cannot_seal():
    """Analyst cannot seal a case (explicit regression)."""
    assert can("analyst", "seal_case") is False


def test_viewer_cannot_register():
    """Viewer cannot register evidence (explicit regression)."""
    assert can("viewer", "register_evidence") is False


def test_investigator_cannot_manage_users():
    """Investigator cannot manage users (explicit regression)."""
    assert can("investigator", "manage_users") is False
