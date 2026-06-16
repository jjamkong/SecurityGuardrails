from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sg.models import ScopeAuthorization
from sg.scope import AuthorizationError, build_scope, enforce_authorization, is_in_scope


def test_build_scope_defaults_to_target_host() -> None:
    scope = build_scope("https://app.test/x", "me", "a1")
    assert scope.allowed_hosts == ["app.test"]


def test_enforce_requires_authorizer() -> None:
    scope = build_scope("https://app.test/", "", "a1")
    with pytest.raises(AuthorizationError):
        enforce_authorization(scope)


def test_enforce_blocks_out_of_scope_target() -> None:
    scope = ScopeAuthorization(
        target="https://evil.test/",
        allowed_hosts=["app.test"],
        authorized_by="me",
        authorization_id="a1",
    )
    with pytest.raises(AuthorizationError):
        enforce_authorization(scope)


def test_enforce_blocks_expired() -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    scope = build_scope("https://app.test/", "me", "a1", expires_at=past)
    with pytest.raises(AuthorizationError):
        enforce_authorization(scope)


def test_enforce_passes_for_valid_scope() -> None:
    enforce_authorization(build_scope("https://app.test/", "me", "a1"))


def test_is_in_scope() -> None:
    scope = build_scope("https://app.test/", "me", "a1")
    assert is_in_scope("https://app.test/other", scope)
    assert not is_in_scope("https://evil.test/", scope)
