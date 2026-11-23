"""Shared fixtures. The tests run against a real Hermes checkout on ``sys.path`` (see README) and
load the plugin from its files, the way Hermes loads it. Every test gets its own HOME and
HERMES_HOME, so nothing is written to the operator's real ``~/.hermes``."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

# Before any Hermes import: import-time code may resolve the home.
os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="kanban-rest-test-home-")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PLUGIN_DIR = Path(__file__).resolve().parents[1]
PREFIX = "/api/plugins/kanban-rest"
V1 = f"{PREFIX}/v1"


def _load(alias: str, path: Path, *, package: bool = False):
    spec = importlib.util.spec_from_file_location(
        alias, path, submodule_search_locations=[str(path.parent)] if package else None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


entry = _load("kanban_rest_plugin", PLUGIN_DIR / "__init__.py", package=True)
api = _load("kanban_rest_plugin_api", PLUGIN_DIR / "dashboard" / "plugin_api.py")


@pytest.fixture(autouse=True)
def hermes_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from hermes_constants import reset_hermes_home_key_cache

    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    for name in ("HERMES_KANBAN_DB", "HERMES_KANBAN_BOARD", "HERMES_KANBAN_TASK", "HERMES_KANBAN_RUN_ID"):
        monkeypatch.delenv(name, raising=False)
    reset_hermes_home_key_cache()
    return home


def make_app(router) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix=PREFIX)
    return app


@pytest.fixture()
def client() -> TestClient:
    with TestClient(make_app(api.router)) as test_client:
        yield test_client


def create(client: TestClient, **overrides) -> dict:
    payload = {
        "title": "External operation",
        "body": "private execution instructions",
        "tenant": "ops",
        "priority": 5,
        "idempotency_key": "operation-001",
    }
    payload.update(overrides)
    response = client.post(f"{V1}/tasks", json=payload)
    assert response.status_code == 201, response.text
    return response.json()
