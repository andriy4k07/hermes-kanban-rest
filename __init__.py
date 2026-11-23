"""Kanban REST plugin entry point.

The routes live in ``dashboard/plugin_api.py``, which the dashboard imports on its own and mounts
at ``/api/plugins/kanban-rest/``. ``register`` adds what that module cannot: the service
credential. When the operator names the secret's ``.env`` variable (setting ``secret_env``), an
inbound bearer is compared constant-time and vouched for as the ``kanban-api`` principal carrying
the ``kanban`` scope, and the ``/v1`` prefix is registered as token-authable demanding that scope,
so another service credential (the drain secret, say) cannot open this surface, and this one
cannot open theirs. The operator dashboard routes stay on the cookie/session gate.

Naming the variable in ``config.yaml`` is also what keeps the secret out of agent subprocesses:
Hermes withholds every env name a ``*_secret_env`` setting points at from terminal and tool
children (``tools.environments.local_env_policy``).
"""
from __future__ import annotations

import hmac
import logging
from typing import Optional

from agent.secret_scope import get_secret
from hermes_cli.dashboard_auth import DashboardAuthProvider, Session, TokenPrincipal
from hermes_cli.dashboard_auth.token_auth import register_token_route_prefix

logger = logging.getLogger(__name__)

PLUGIN_ID = "kanban-rest"
API_PREFIX = f"/api/plugins/{PLUGIN_ID}/v1/"
DEFAULT_SCOPE = "kanban"
# token_urlsafe(32) produces exactly 43 chars, so a correctly provisioned secret clears the bar.
DEFAULT_MIN_SECRET_CHARS = 43
_MIN_DISTINCT_CHARS = 16
_NOT_INTERACTIVE = "the Kanban REST credential is a non-interactive service credential; there is no login flow"

LAST_SKIP_REASON: str = ""


def assess_secret_strength(secret: str, *, min_chars: int = DEFAULT_MIN_SECRET_CHARS) -> Optional[str]:
    """Why ``secret`` is refused, else ``None``. Catches only degenerate values (short, few
    distinct characters, a repeated block): entropy is a property of how a secret was generated,
    so provisioning must still use a CSPRNG."""
    if len(secret) < min_chars:
        return (f"secret too short: {len(secret)} chars (need >= {min_chars}; generate it with "
                "`python -c \"import secrets; print(secrets.token_urlsafe(32))\"`)")
    distinct = len(set(secret))
    if distinct < _MIN_DISTINCT_CHARS:
        return f"secret has only {distinct} distinct characters (need >= {_MIN_DISTINCT_CHARS}); looks structured"
    if secret in (secret + secret)[1:-1]:
        return "secret is a repeated block; looks structured"
    return None


class KanbanApiSecretProvider(DashboardAuthProvider):
    """Shared-bearer-secret service credential for the Kanban REST API (token only)."""

    name = "kanban-rest-secret"
    display_name = "Kanban REST API (service credential)"
    supports_token = True
    supports_session = False

    def __init__(self, *, secret: str, scope: str = DEFAULT_SCOPE,
                 min_secret_chars: int = DEFAULT_MIN_SECRET_CHARS) -> None:
        # Checked here too, so a caller bypassing register() cannot build one around a weak secret.
        reason = assess_secret_strength(secret, min_chars=min_secret_chars)
        if reason is not None:
            raise ValueError(f"{self.name} secret rejected: {reason}")
        self._secret = secret.encode("utf-8")
        self._scope = scope

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        if token and hmac.compare_digest(token.encode("utf-8"), self._secret):
            return TokenPrincipal(principal="kanban-api", provider=self.name, scopes=(self._scope,))
        return None

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        # Never mints a session, so it stacks harmlessly in the cookie-verify loop.
        return None

    def start_login(self, *, redirect_uri: str):
        raise NotImplementedError(_NOT_INTERACTIVE)

    def complete_login(self, *, code: str, state: str, code_verifier: str, redirect_uri: str) -> Session:
        raise NotImplementedError(_NOT_INTERACTIVE)

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError(_NOT_INTERACTIVE)

    def revoke_session(self, *, refresh_token: str) -> None:
        return None


def _settings(ctx) -> tuple[Optional[dict], str]:
    """``(provider kwargs, "")``, or ``(None, why the credential stays off)``."""
    env = str(ctx.get_config("secret_env", "") or "").strip()
    if not env:
        return None, ("secret_env is not set: the Kanban REST API stays on dashboard-session auth. Store a "
                      "CSPRNG secret in .env and name its variable in plugins.entries.kanban-rest.settings.secret_env.")
    secret = (get_secret(env) or "").strip()
    if not secret:
        return None, f"{env} (named by secret_env) is empty or unset; the Kanban REST credential stays off."
    scope = str(ctx.get_config("scope", DEFAULT_SCOPE) or "").strip() or DEFAULT_SCOPE
    try:
        min_chars = int(ctx.get_config("min_secret_chars", DEFAULT_MIN_SECRET_CHARS))
    except (TypeError, ValueError):
        min_chars = DEFAULT_MIN_SECRET_CHARS
    reason = assess_secret_strength(secret, min_chars=min_chars)
    if reason is not None:
        return None, f"{env} rejected: {reason}. The Kanban REST credential stays off (fail-closed)."
    return {"secret": secret, "scope": scope, "min_secret_chars": min_chars}, ""


def register(ctx) -> None:
    """Register the service credential and its token route when a usable secret is configured;
    otherwise record why not in ``LAST_SKIP_REASON``."""
    global LAST_SKIP_REASON
    kwargs, LAST_SKIP_REASON = _settings(ctx)
    if kwargs is None:
        logger.info("kanban-rest: %s", LAST_SKIP_REASON)
        return
    # The context refuses a provider from a profile other than the launch one (None); that
    # profile's settings must not re-scope the process-global route either.
    if ctx.register_dashboard_auth_provider(KanbanApiSecretProvider(**kwargs)) is None:
        return
    # ``provider=``: the prefix lapses when the provider is unregistered (plugin disabled), so the
    # surface falls back to session auth instead of answering 401 to everything until restart.
    register_token_route_prefix(API_PREFIX, scope=kwargs["scope"], provider=KanbanApiSecretProvider.name)
    logger.info("kanban-rest: service credential registered (scope=%s, prefix=%s)", kwargs["scope"], API_PREFIX)
