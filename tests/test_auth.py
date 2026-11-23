"""The service credential: provider behaviour, register(), the scoped token route through the
real Hermes token seam, and the secret staying out of agent subprocess environments."""
from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from conftest import V1, api, entry, make_app
from fastapi.testclient import TestClient

from hermes_cli.dashboard_auth import (
    TokenPrincipal,
    assert_protocol_compliance,
    clear_providers,
    get_provider,
    register_provider,
)
from hermes_cli.dashboard_auth import token_auth
from hermes_cli.dashboard_auth.registry import unregister_global_provider

ENV = "KANBAN_REST_API_SECRET"


@pytest.fixture(autouse=True)
def _clean_providers_and_routes():
    clear_providers()
    token_auth.clear_token_routes()
    yield
    clear_providers()
    token_auth.clear_token_routes()


def _strong() -> str:
    return secrets.token_urlsafe(32)


class _Ctx:
    """PluginContext stand-in: settings from a dict, providers into the real registry."""

    def __init__(self, **settings) -> None:
        self.settings = settings
        self.registered: list = []

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_dashboard_auth_provider(self, provider):
        register_provider(provider)
        self.registered.append(provider)
        return object()  # the real context hands back a registration, None when it refuses


class TestProvider:
    def test_protocol_and_flags(self) -> None:
        assert_protocol_compliance(entry.KanbanApiSecretProvider)
        p = entry.KanbanApiSecretProvider(secret=_strong())
        assert p.supports_token is True and p.supports_session is False

    def test_verify_token(self) -> None:
        s = _strong()
        p = entry.KanbanApiSecretProvider(secret=s)
        principal = p.verify_token(token=s)
        assert isinstance(principal, TokenPrincipal)
        assert (principal.principal, principal.provider, principal.scopes) == (
            "kanban-api", "kanban-rest-secret", ("kanban",))
        assert p.verify_token(token=_strong()) is None
        assert p.verify_token(token="") is None
        assert entry.KanbanApiSecretProvider(secret=s, scope="boards").verify_token(token=s).scopes == ("boards",)

    @pytest.mark.parametrize("weak", ["weak", "a" * 64, "abcdefghijklmnopq" * 4])
    def test_construction_rejects_degenerate_secrets(self, weak: str) -> None:
        with pytest.raises(ValueError):
            entry.KanbanApiSecretProvider(secret=weak)

    def test_non_interactive(self) -> None:
        p = entry.KanbanApiSecretProvider(secret=_strong())
        assert p.verify_session(access_token="anything") is None
        for call in (lambda: p.start_login(redirect_uri="r"),
                     lambda: p.complete_login(code="c", state="s", code_verifier="v", redirect_uri="r"),
                     lambda: p.refresh_session(refresh_token="r")):
            with pytest.raises(NotImplementedError):
                call()


class TestRegister:
    def test_off_until_secret_env_is_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, _strong())
        ctx = _Ctx()
        entry.register(ctx)
        assert ctx.registered == []
        assert "secret_env" in entry.LAST_SKIP_REASON
        assert not token_auth.is_token_route(f"{V1}/tasks")

    def test_off_when_the_named_variable_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV, raising=False)
        ctx = _Ctx(secret_env=ENV)
        entry.register(ctx)
        assert ctx.registered == [] and ENV in entry.LAST_SKIP_REASON

    def test_weak_secret_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, "tooweak")
        ctx = _Ctx(secret_env=ENV)
        entry.register(ctx)
        assert ctx.registered == [] and "rejected" in entry.LAST_SKIP_REASON
        assert not token_auth.is_token_route(f"{V1}/tasks")

    def test_min_secret_chars_setting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, _strong())
        entry.register(_Ctx(secret_env=ENV, min_secret_chars=999))
        assert "rejected" in entry.LAST_SKIP_REASON
        short = _strong()[:36]
        monkeypatch.setenv(ENV, short)
        ctx = _Ctx(secret_env=ENV, min_secret_chars=32)
        entry.register(ctx)
        assert ctx.registered[0].verify_token(token=short) is not None

    def test_route_is_token_authable_only_while_the_provider_is_registered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV, _strong())
        entry.register(_Ctx(secret_env=ENV))
        assert entry.LAST_SKIP_REASON == ""
        assert token_auth.is_token_route(f"{V1}/tasks")
        assert token_auth.is_token_route(f"{V1}/tasks/t_abc/complete")
        # Neither the bundled operator Kanban routes nor anything outside /v1 joins the seam.
        assert not token_auth.is_token_route("/api/plugins/kanban/board")
        assert not token_auth.is_token_route("/api/plugins/kanban-rest/other")

        name = entry.KanbanApiSecretProvider.name
        assert unregister_global_provider(name, get_provider(name))
        assert not token_auth.is_token_route(f"{V1}/tasks")

    def test_refused_provider_does_not_rescope_the_route(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, _strong())
        entry.register(_Ctx(secret_env=ENV))
        assert token_auth._match_token_route(f"{V1}/tasks") == "kanban"

        refused = _Ctx(secret_env=ENV, scope="drain")
        refused.register_dashboard_auth_provider = lambda provider: None
        entry.register(refused)
        assert token_auth._match_token_route(f"{V1}/tasks") == "kanban"


@pytest.fixture()
def gated(monkeypatch: pytest.MonkeyPatch):
    """The router behind the real token seam, with a second service credential of another scope."""
    secret, other = _strong(), _strong()
    monkeypatch.setenv(ENV, secret)
    entry.register(_Ctx(secret_env=ENV))

    class OtherService(entry.KanbanApiSecretProvider):
        name = "other-service-secret"

    register_provider(OtherService(secret=other, scope="drain"))
    app = make_app(api.router)
    app.middleware("http")(token_auth.token_auth_middleware)
    with TestClient(app) as client:
        yield client, secret, other


class TestGatedEndToEnd:
    def test_bearer_secret_drives_the_surface_and_is_the_recorded_actor(self, gated) -> None:
        client, secret, _ = gated
        auth = {"Authorization": f"Bearer {secret}"}
        assert client.get(f"{V1}/health", headers=auth).status_code == 200
        created = client.post(f"{V1}/tasks", headers={**auth, "Idempotency-Key": "e2e-1"}, json={"title": "e2e"})
        assert created.status_code == 201, created.text
        assert created.json()["task"]["created_by"] == "api:kanban-api"
        replay = client.post(f"{V1}/tasks", headers={**auth, "Idempotency-Key": "e2e-1"}, json={"title": "e2e"})
        assert replay.status_code == 200 and replay.json()["created"] is False

    def test_missing_or_wrong_token_is_401(self, gated) -> None:
        client, _, _ = gated
        assert client.get(f"{V1}/tasks").status_code == 401
        assert client.get(f"{V1}/tasks", headers={"Authorization": f"Bearer {_strong()}"}).status_code == 401

    def test_foreign_scoped_credential_is_403(self, gated) -> None:
        client, _, other = gated
        assert client.get(f"{V1}/tasks", headers={"Authorization": f"Bearer {other}"}).status_code == 403


def _write_config(home: Path, text: str) -> None:
    (home / "config.yaml").write_text(text, encoding="utf-8")


def test_naming_the_secret_withholds_it_from_agent_subprocesses(hermes_home: Path) -> None:
    from tools.environments.local import hermes_subprocess_env

    env = {ENV: _strong(), "PATH": "/usr/bin"}
    assert ENV in hermes_subprocess_env(base_env=env)  # an arbitrary name is not a known secret
    _write_config(hermes_home, f"plugins:\n  entries:\n    kanban-rest:\n      settings:\n        secret_env: {ENV}\n")
    assert ENV not in hermes_subprocess_env(base_env=env)


def test_real_discovery_registers_the_credential(hermes_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from conftest import PLUGIN_DIR

    from hermes_cli import plugins

    (hermes_home / "plugins").mkdir()
    (hermes_home / "plugins" / "kanban-rest").symlink_to(PLUGIN_DIR, target_is_directory=True)
    _write_config(hermes_home, "plugins:\n  enabled: [kanban-rest]\n  entries:\n    kanban-rest:\n"
                               f"      settings:\n        secret_env: {ENV}\n")
    secret = _strong()
    monkeypatch.setenv(ENV, secret)
    plugins.discover_plugins(force=True)
    provider = get_provider(entry.KanbanApiSecretProvider.name)
    assert provider is not None and provider.verify_token(token=secret) is not None
    assert token_auth._match_token_route(f"{V1}/tasks") == "kanban"
