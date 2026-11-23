"""Opt-in run transcripts: the worker-side session link and the sanitized transcript endpoint."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest
from conftest import V1, create, entry
from fastapi.testclient import TestClient

from hermes_cli import kanban_db
from hermes_cli import kanban_db_connect as kbc
from hermes_cli.plugins_state import PluginState
from hermes_constants import reset_hermes_home_override, set_hermes_home_override

_EXPOSE = "plugins:\n  entries:\n    kanban-rest:\n      settings:\n        expose_transcripts: true\n"


class _WorkerCtx:
    """The worker profile's plugin context: its settings and its own plugin state."""

    def __init__(self, expose: bool = True) -> None:
        self.expose = expose
        self.state = PluginState(entry.PLUGIN_ID)

    def get_config(self, key, default=None):
        return self.expose if key == "expose_transcripts" else default


@pytest.fixture()
def transcripts_on(hermes_home: Path) -> None:
    (hermes_home / "config.yaml").write_text(_EXPOSE)


@pytest.fixture()
def worker_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Home of the profile that runs the workers; every profile name resolves to it."""
    from hermes_cli import profiles as profiles_mod

    home = tmp_path / "worker-home"
    home.mkdir()
    (home / "config.yaml").write_text(_EXPOSE)
    monkeypatch.setattr(profiles_mod, "resolve_profile_env", lambda name: str(home))
    return home


def _start_worker(monkeypatch: pytest.MonkeyPatch, home: Path, task_id: str, session_id: str, *,
                  expose: bool = True) -> int:
    """Claim the task the way the dispatcher does and run the worker's session-start hook in its home."""
    with kbc.connect_closing() as conn:
        kanban_db.claim_task(conn, task_id)
        run_id = kanban_db.latest_run(conn, task_id).id
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(run_id))
    _session_start(home, session_id, expose=expose)
    return run_id


def _session_start(home: Path, session_id: str, *, expose: bool = True) -> None:
    token = set_hermes_home_override(home)
    try:
        entry._link_run_session(_WorkerCtx(expose), session_id)
    finally:
        reset_hermes_home_override(token)


@contextmanager
def _store(home: Path):
    """A writable handle on the worker profile's own session store."""
    from persistence_assembly import open_persistence, profile_scope

    with open_persistence(profile_scope(home=home)) as store:
        yield store


def _session(home: Path, session_id: str, *messages: dict, **create_kwargs) -> None:
    from persistence.conversation.messages import NewMessage
    from persistence.conversation.sessions import NewSession

    with _store(home) as store:
        store.sessions.create(NewSession(session_id, "kanban", **create_kwargs))
        store.messages.append_batch(session_id, [NewMessage(m.pop("role"), m.pop("content", None), **m)
                                                 for m in messages])


def test_transcript_is_off_by_default(client: TestClient) -> None:
    task_id = create(client, idempotency_key="transcript-off")["task"]["id"]
    assert client.get(f"{V1}/tasks/{task_id}/transcript").status_code == 404
    assert "transcript" not in client.get(f"{V1}/capabilities").json()["observability"]


def test_transcript_streams_the_worker_session_while_running(
    client: TestClient, transcripts_on: None, worker_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "transcript" in client.get(f"{V1}/capabilities").json()["observability"]
    task_id = create(client, title="hello", idempotency_key="transcript-1")["task"]["id"]
    url = f"{V1}/tasks/{task_id}/transcript"
    empty = client.get(url).json()
    assert empty["run_id"] is None and empty["messages"] == []

    with kbc.connect_closing() as conn:
        kanban_db.claim_task(conn, task_id)
    pending = client.get(url).json()  # run known, worker has not linked a session yet
    assert pending["run_status"] == "running" and pending["messages"] == []

    _session(worker_home, "sess-1",
             {"role": "system", "content": "secret system prompt"},
             {"role": "user", "content": "work kanban task"},
             {"role": "assistant", "content": None, "reasoning": "The user says hello",
              "tool_calls": [{"id": "c1", "type": "function", "function": {
                  "name": "kanban_show", "arguments": '{"key": "sk-abcdefghijklmnopqrstuvwxyz123456"}'}}]},
             {"role": "tool", "content": "x" * 5000, "tool_name": "kanban_show", "tool_call_id": "c1"},
             {"role": "assistant", "content": "Hello! <script>"})
    with kbc.connect_closing() as conn:
        run_id = kanban_db.latest_run(conn, task_id).id
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(run_id))
    _session_start(worker_home, "sess-1")
    _session_start(worker_home, "sess-2")  # a later agent in the same worker: first writer wins

    body = client.get(url, params={"limit": 3}).json()
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]  # system dropped
    assert body["has_more"] is True
    call = body["messages"][1]
    assert call["reasoning"] == "The user says hello"
    assert call["tool_calls"][0]["name"] == "kanban_show"
    assert "sk-abcdefghijklmnop" not in call["tool_calls"][0]["arguments"]
    assert "sess-1" not in str(body)

    rest = client.get(url, params={"after_id": body["next_after_id"]}).json()
    assert [m["role"] for m in rest["messages"]] == ["tool", "assistant"]
    assert rest["messages"][0]["truncated"] is True
    assert len(rest["messages"][0]["content"]) == 4000
    assert rest["messages"][1]["content"] == "Hello! <script>"
    assert rest["has_more"] is False
    tail = client.get(url, params={"after_id": rest["next_after_id"]}).json()
    assert tail["messages"] == [] and tail["next_after_id"] == rest["next_after_id"]

    assert client.get(url, params={"run_id": 999}).status_code == 404
    assert client.get(f"{V1}/tasks/missing/transcript").status_code == 404


def test_hook_links_only_a_live_run_of_its_own_task_and_only_when_opted_in(
    client: TestClient, worker_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def link(task_id: str, run_id: int):
        token = set_hermes_home_override(worker_home)
        try:
            return PluginState(entry.PLUGIN_ID).get(entry.run_link_key("default", run_id))
        finally:
            reset_hermes_home_override(token)

    _session_start(worker_home, "outside-any-worker")  # no kanban env: no-op
    off = create(client, idempotency_key="link-off")["task"]["id"]
    off_run = _start_worker(monkeypatch, worker_home, off, "sess-off", expose=False)
    assert link(off, off_run) is None

    task_id = create(client, idempotency_key="link-own")["task"]["id"]
    other = create(client, idempotency_key="link-other")["task"]["id"]
    run_id = _start_worker(monkeypatch, worker_home, task_id, "sess-main")
    assert link(task_id, run_id) == {"task": task_id, "session": "sess-main"}

    # An environment naming another task's run labels nothing.
    with kbc.connect_closing() as conn:
        kanban_db.claim_task(conn, other)
        other_run = kanban_db.latest_run(conn, other).id
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(other_run))
    _session_start(worker_home, "sess-forged")
    assert link(other, other_run) is None


def test_transcript_latest_follows_compression_continuations(
    client: TestClient, transcripts_on: None, worker_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_id = create(client, idempotency_key="transcript-latest")["task"]["id"]
    _start_worker(monkeypatch, worker_home, task_id, "s-root")
    _session(worker_home, "s-root", *({"role": "assistant", "content": f"root {i}"} for i in range(3)))
    with _store(worker_home) as store:
        store.sessions.end("s-root", "compression")
    _session(worker_home, "s-cont", {"role": "assistant", "content": "cont 0"}, parent_session_id="s-root")

    url = f"{V1}/tasks/{task_id}/transcript"
    body = client.get(url, params={"latest": "true", "limit": 2}).json()
    assert [m["content"] for m in body["messages"]] == ["root 2", "cont 0"]
    assert body["has_more"] is True
    assert [m["content"] for m in client.get(url).json()["messages"]] == ["root 0", "root 1", "root 2", "cont 0"]


def test_transcript_ignores_caller_supplied_metadata_session(
    client: TestClient, transcripts_on: None, worker_home: Path
) -> None:
    _session(worker_home, "private-chat", {"role": "user", "content": "not a kanban run"})
    task_id = create(client, idempotency_key="transcript-metadata")["task"]["id"]
    with kbc.connect_closing() as conn:
        kanban_db.claim_task(conn, task_id)
        kanban_db.complete_task(conn, task_id, summary="done", metadata={"worker_session_id": "private-chat"})
    body = client.get(f"{V1}/tasks/{task_id}/transcript").json()
    assert body["messages"] == [] and "session_id" not in body


def test_transcript_needs_the_worker_profiles_own_opt_in(
    client: TestClient, transcripts_on: None, worker_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The opt-in is read from the profile that ran the worker, never from the profile the request
    selected: ``?profile=`` must not unlock another profile's worker."""
    task_id = create(client, idempotency_key="transcript-owner")["task"]["id"]
    _start_worker(monkeypatch, worker_home, task_id, "s1")
    _session(worker_home, "s1", {"role": "assistant", "content": "worker output"})
    url = f"{V1}/tasks/{task_id}/transcript"
    assert [m["content"] for m in client.get(url).json()["messages"]] == ["worker output"]
    (worker_home / "config.yaml").write_text("")
    assert client.get(url).status_code == 404


def test_transcript_of_a_finished_run_stops_where_the_run_did(
    client: TestClient, transcripts_on: None, worker_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resumed session appends a later conversation that is not this run's."""
    task_id = create(client, idempotency_key="transcript-ended")["task"]["id"]
    _start_worker(monkeypatch, worker_home, task_id, "s1")
    with kbc.connect_closing() as conn:
        assert kanban_db.complete_task(conn, task_id, summary="done")
        ended_at = kanban_db.latest_run(conn, task_id).ended_at
    _session(worker_home, "s1",
             *({"role": "assistant", "content": f"run step {i}", "timestamp": ended_at - 10 + i} for i in range(3)),
             *({"role": "user", "content": f"resumed later {i}", "timestamp": ended_at + 3600 + i} for i in range(3)))

    url = f"{V1}/tasks/{task_id}/transcript"
    for params in ({}, {"latest": "true", "limit": 2}):
        contents = [m["content"] for m in client.get(url, params=params).json()["messages"]]
        assert contents and all(c.startswith("run step") for c in contents), params


def test_steps_keep_their_uid_when_compaction_renumbers_them(
    client: TestClient, transcripts_on: None, worker_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In-place compaction soft-archives the summarized steps (they stay in the transcript) and
    re-inserts the steps it carries forward under fresh ids; ``uid`` lets a poller spot the repeat."""
    from persistence.conversation.messages import ConversationRequest, NewMessage

    task_id = create(client, idempotency_key="transcript-uid")["task"]["id"]
    _start_worker(monkeypatch, worker_home, task_id, "s1")
    _session(worker_home, "s1", {"role": "assistant", "content": "step 1"}, {"role": "assistant", "content": "step 2"})
    url = f"{V1}/tasks/{task_id}/transcript"
    first = client.get(url).json()
    seen = {m["uid"]: m["content"] for m in first["messages"]}
    assert len(seen) == 2 and all(seen)

    with _store(worker_home) as store:
        history = [m.as_openai_message() for m in store.messages.read_conversation(
            "s1", ConversationRequest(include_row_ids=True))]
        store.messages.compact("s1", [NewMessage("user", "[summary]"),
                                      *(NewMessage.from_live(m) for m in history if m.get("content") == "step 2")])

    again = client.get(url, params={"after_id": first["next_after_id"]}).json()["messages"]
    repeat = [m for m in again if m["content"] == "step 2"]
    assert repeat and seen[repeat[0]["uid"]] == "step 2"
    for params in ({"limit": 500}, {"latest": "true", "limit": 500}):
        contents = [m["content"] for m in client.get(url, params=params).json()["messages"]]
        assert {"step 1", "step 2", "[summary]"} <= set(contents), params
