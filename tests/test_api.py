"""The v1 contract: sanitized DTOs, idempotent creation, actions and bounded observation."""
from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest
from conftest import V1, api, create
from fastapi.testclient import TestClient

from hermes_cli import kanban_db
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_edit


def test_health_capabilities_and_safe_board_dtos(client: TestClient) -> None:
    health = client.get(f"{V1}/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "hermes-kanban", "api_version": "1",
                             "current_board": "default"}

    body = client.get(f"{V1}/capabilities").json()
    assert body["idempotent_task_creation"] is True
    assert body["profile_execution"] is False
    assert "ready" in body["task_statuses"]

    boards = client.get(f"{V1}/boards").json()
    assert boards["current"] == "default"
    assert boards["boards"][0]["id"] == "default"
    assert "db_path" not in boards["boards"][0]
    assert "default_workdir" not in boards["boards"][0]

    detail = client.get(f"{V1}/boards/Default")
    assert detail.status_code == 200
    assert detail.json()["board"]["id"] == "default"


def test_create_list_get_patch_are_idempotent_and_sanitized(client: TestClient) -> None:
    first = create(client)
    task_id = first["task"]["id"]
    assert first["created"] is True
    assert first["task"]["links"] == {"parents": [], "children": []}

    repeated = client.post(f"{V1}/tasks", headers={"Idempotency-Key": "operation-001"},
                           json={"title": "ignored on replay"})
    assert repeated.status_code == 200
    assert repeated.json()["created"] is False
    assert repeated.json()["task"]["id"] == task_id

    listed = client.get(f"{V1}/tasks", params={"tenant": "ops"})
    assert listed.status_code == 200
    assert listed.json()["count"] == 1

    detail = client.get(f"{V1}/tasks/{task_id}")
    task = detail.json()["task"]
    assert task["title"] == "External operation"
    forbidden = {"body", "result", "workspace_path", "branch_name", "claim_lock", "worker_pid",
                 "session_id", "idempotency_key", "last_failure_error"}
    assert forbidden.isdisjoint(task)
    assert "private execution instructions" not in detail.text

    patched = client.patch(f"{V1}/tasks/{task_id}",
                           json={"title": "Renamed operation", "priority": 9, "assignee": "Worker-One"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["task"]["title"] == "Renamed operation"
    assert patched.json()["task"]["priority"] == 9
    assert patched.json()["task"]["assignee"] == "worker-one"


@pytest.mark.parametrize("where", ["header", "body"])
def test_blank_idempotency_key_is_refused(client: TestClient, where: str) -> None:
    kwargs = {"headers": {"Idempotency-Key": "  "}, "json": {"title": "x"}} if where == "header" else {
        "json": {"title": "x", "idempotency_key": " "}}
    assert client.post(f"{V1}/tasks", **kwargs).status_code == 422


def test_conflicting_idempotency_keys_are_refused(client: TestClient) -> None:
    refused = client.post(f"{V1}/tasks", headers={"Idempotency-Key": "a"},
                          json={"title": "x", "idempotency_key": "b"})
    assert refused.status_code == 409


def test_links_actions_and_observability_are_sanitized(client: TestClient) -> None:
    parent_id = create(client, title="Parent", idempotency_key="parent-001")["task"]["id"]
    child_id = create(client, title="Child", idempotency_key="child-001")["task"]["id"]

    assert client.post(f"{V1}/tasks/{parent_id}/links/{child_id}").status_code == 200
    child = client.get(f"{V1}/tasks/{child_id}").json()["task"]
    assert child["links"]["parents"] == [parent_id]
    assert child["status"] == "todo"

    comment = client.post(f"{V1}/tasks/{parent_id}/comment", json={"body": "private operator note"})
    assert comment.status_code == 201
    assert "private operator note" not in comment.text

    completed = client.post(f"{V1}/tasks/{parent_id}/complete", json={"summary": "private completion handoff"})
    assert completed.status_code == 200, completed.text
    assert completed.json()["task"]["status"] == "done"
    assert "private completion handoff" not in completed.text

    events = client.get(f"{V1}/tasks/{parent_id}/events")
    assert events.json()["events"]
    assert all("payload" not in event for event in events.json()["events"])
    assert "private" not in events.text

    with kbc.connect_closing(board="default") as conn, kanban_db.write_txn(conn):
        conn.execute(
            "INSERT INTO task_runs (task_id, profile, status, started_at, ended_at, outcome, summary, metadata, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (parent_id, "private-profile", "done", 1_700_000_000, 1_700_000_001, "completed",
             "raw private summary", json.dumps({"workspace": "/srv/private/work"}), "secret error"),
        )
    runs = client.get(f"{V1}/tasks/{parent_id}/runs")
    run = [r for r in runs.json()["runs"] if r["profile"] == "private-profile"]
    assert len(run) == 1, runs.text
    assert set(run[0]) == {"id", "profile", "status", "outcome", "started_at", "ended_at"}
    for leaked in ("raw private summary", "secret error", "/srv/private/work"):
        assert leaked not in runs.text

    log_path = kanban_db.worker_log_path(parent_id, board="default")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "working in /srv/private/worktree\nAuthorization: Bearer secret-value-1234567890\n"
        "retrying with Bearer bare-opaque-token-42\n"
        "GET https://example.test?access_token=query-token-42\n"
        "cat /secret.txt from /workspace\n"
        "copy \\\\fileserver\\private\\report.txt C:\\Users\\John Doe\\private\\ledger.txt\n"
        "  hermes --resume 20261004_101112_abc123\n"
        'request headers {"Authorization": "Basic dXNlcjpodW50ZXIy"}\n'
        'open "/Users/operator/Private Client/ledger.json" then /srv/next\n',
        encoding="utf-8",
    )
    log_body = client.get(f"{V1}/tasks/{parent_id}/log").json()
    assert "path" not in log_body
    for leaked in ("/srv/private", "secret-value-1234567890", "bare-opaque-token-42", "query-token-42",
                   "/secret.txt", "/workspace", "fileserver", "report.txt", "Doe", "ledger.txt",
                   "20261004_101112_abc123", "dXNlcjpodW50ZXIy", "Client", "ledger.json"):
        assert leaked not in log_body["excerpt"], leaked

    unlinked = client.delete(f"{V1}/tasks/{parent_id}/links/{child_id}")
    assert unlinked.json()["removed"] is True

    blocked = client.post(f"{V1}/tasks/{child_id}/block", json={"reason": "private blocker", "kind": "needs_input"})
    assert blocked.status_code == 200
    assert blocked.json()["task"]["status"] == "blocked"
    assert "private blocker" not in blocked.text
    assert client.post(f"{V1}/tasks/{child_id}/unblock").status_code == 200
    assert client.post(f"{V1}/tasks/{child_id}/archive").status_code == 200


def test_archiving_frees_the_idempotency_key(client: TestClient) -> None:
    task_id = create(client, idempotency_key="race-key")["task"]["id"]
    with kbc.connect_closing(board="default") as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        with pytest.raises(sqlite3.IntegrityError), kanban_db.write_txn(conn):
            conn.execute(
                "INSERT INTO tasks (id, title, status, created_at, workspace_kind, idempotency_key) "
                "VALUES (?, ?, ?, ?, 'scratch', ?)",
                ("t_duplicate", "dup", row["status"], row["created_at"], "race-key"),
            )

    assert client.post(f"{V1}/tasks/{task_id}/archive").status_code == 200
    reused = client.post(f"{V1}/tasks", json={"title": "after archive", "idempotency_key": "race-key"})
    assert reused.status_code == 201, reused.text
    assert reused.json()["created"] is True
    assert reused.json()["task"]["id"] != task_id


def test_create_lost_to_a_concurrent_create_answers_200(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    original_id = create(client, idempotency_key="winner-key")["task"]["id"]
    monkeypatch.setattr(kanban_db, "create_task_idempotent", lambda conn, **kwargs: (original_id, False))
    raced = client.post(f"{V1}/tasks", json={"title": "raced", "idempotency_key": "winner-key"})
    assert raced.status_code == 200, raced.text
    assert raced.json()["created"] is False
    assert raced.json()["task"]["id"] == original_id


def test_link_missing_task_is_404_not_400(client: TestClient) -> None:
    real_id = create(client, idempotency_key="link-real")["task"]["id"]
    assert client.post(f"{V1}/tasks/t_nope/links/{real_id}").status_code == 404
    assert client.post(f"{V1}/tasks/{real_id}/links/t_nope").status_code == 404
    assert client.delete(f"{V1}/tasks/{real_id}/links/t_nope").status_code == 404


def test_complete_without_evidence_is_a_client_error(client: TestClient) -> None:
    task_id = create(client, idempotency_key="empty-complete")["task"]["id"]
    rejected = client.post(f"{V1}/tasks/{task_id}/complete")
    assert rejected.status_code == 400, rejected.text
    assert "no result or summary evidence" in rejected.json()["detail"]
    assert client.get(f"{V1}/tasks/{task_id}").json()["task"]["status"] != "done"


def test_patch_rejects_text_edits_to_finished_tasks(client: TestClient) -> None:
    done_id = create(client, idempotency_key="done-edit")["task"]["id"]
    assert client.post(f"{V1}/tasks/{done_id}/complete", json={"summary": "shipped"}).status_code == 200
    assert client.patch(f"{V1}/tasks/{done_id}", json={"title": "too late"}).status_code == 409
    assert client.get(f"{V1}/tasks/{done_id}").json()["task"]["title"] == "External operation"

    assert client.post(f"{V1}/tasks/{done_id}/archive").status_code == 200
    assert client.patch(f"{V1}/tasks/{done_id}", json={"body": "amend history"}).status_code == 409


def test_patch_refuses_null_for_fields_that_cannot_be_cleared(client: TestClient) -> None:
    url = f"{V1}/tasks/{create(client, idempotency_key='patch-null')['task']['id']}"
    assert client.patch(url, json={"title": None}).status_code == 422
    assert client.patch(url, json={"priority": None}).status_code == 422
    assert client.patch(url, json={"body": None, "assignee": None}).status_code == 200
    assert client.patch(url, json={}).status_code == 400


def test_patch_never_echoes_an_unrecognised_storage_error(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    task_id = create(client, idempotency_key="patch-leak")["task"]["id"]

    def boom(*args, **kwargs):
        raise RuntimeError("database disk image is malformed at /srv/hermes/kanban.db")

    monkeypatch.setattr(kanban_db_edit, "update_task_fields", boom)
    rejected = client.patch(f"{V1}/tasks/{task_id}", json={"priority": 1})
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "task could not be updated"


def test_patch_edits_notify_observers_once(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    task_id = create(client, idempotency_key="notify-edit")["task"]["id"]
    notified = []
    monkeypatch.setattr(kanban_db, "notify_task_updated",
                        lambda conn, tid, fields, board=None: notified.append((tid, sorted(fields), board)))
    patched = client.patch(f"{V1}/tasks/{task_id}", json={"assignee": "worker-two", "title": "renamed", "priority": 7})
    assert patched.status_code == 200, patched.text
    assert notified == [(task_id, ["assignee", "priority", "title"], "default")]
    kinds = {e["kind"] for e in client.get(f"{V1}/tasks/{task_id}/events").json()["events"]}
    assert {"assigned", "reprioritized", "edited"} <= kinds


def test_events_and_runs_limit_returns_most_recent_in_order(client: TestClient) -> None:
    task_id = create(client, idempotency_key="limit-key")["task"]["id"]
    with kbc.connect_closing(board="default") as conn, kanban_db.write_txn(conn):
        for i in range(5):
            conn.execute("INSERT INTO task_events (task_id, run_id, kind, payload, created_at) "
                         "VALUES (?, NULL, ?, NULL, ?)", (task_id, f"evt{i}", 2_000_000_000 + i))
        for i in range(4):
            conn.execute("INSERT INTO task_runs (task_id, status, started_at, ended_at, outcome) "
                         "VALUES (?, 'done', ?, ?, 'completed')", (task_id, 2_000_000_000 + i, 2_000_000_001 + i))

    events = client.get(f"{V1}/tasks/{task_id}/events", params={"limit": 3}).json()
    assert [e["kind"] for e in events["events"]] == ["evt2", "evt3", "evt4"]
    runs = client.get(f"{V1}/tasks/{task_id}/runs", params={"limit": 2}).json()
    assert [r["started_at"] for r in runs["runs"]] == [2_000_000_002, 2_000_000_003]


def test_error_detail_is_sanitized(client: TestClient) -> None:
    bad_board = client.get(f"{V1}/tasks", params={"board": "Bad Slug!!"})
    assert bad_board.status_code == 400, bad_board.text
    assert bad_board.json()["detail"] == "invalid board id"
    assert "1-64 chars" not in bad_board.text
    assert client.get(f"{V1}/tasks", params={"board": "missing"}).status_code == 404

    unknown_parent = client.post(f"{V1}/tasks", json={"title": "orphan", "parents": ["t_missing"]})
    assert unknown_parent.status_code == 400, unknown_parent.text
    assert "unknown parent task" in unknown_parent.json()["detail"]


def test_api_actor_can_never_be_a_profile_name(client: TestClient) -> None:
    """A worker skips comments authored under its own profile name, so the API's provenance must
    not be a name a profile could carry."""
    from hermes_cli.profiles import validate_profile_name

    created_by = create(client, idempotency_key="actor-key")["task"]["created_by"]
    assert created_by == "api:external"
    with pytest.raises(ValueError):
        validate_profile_name(created_by)
    task_id = create(client, idempotency_key="actor-comment")["task"]["id"]
    assert client.post(f"{V1}/tasks/{task_id}/comment", json={"body": "x", "author": "worker"}).status_code == 422


def test_profiles_roster_is_sanitized_and_sorted(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from hermes_cli import profiles as profiles_mod

    fake = [SimpleNamespace(name="zeta", description="  Runs deploys.  ", model="secret-model", path="/private/dir"),
            SimpleNamespace(name="alpha", description="", model=None, path="/x")]
    monkeypatch.setattr(profiles_mod, "list_profiles", lambda: fake)
    resp = client.get(f"{V1}/profiles")
    assert resp.json() == {"profiles": [{"name": "alpha", "description": "", "has_description": False},
                                        {"name": "zeta", "description": "Runs deploys.", "has_description": True}],
                           "count": 2}

    def boom():
        raise RuntimeError("disk exploded at /private/some/path")

    monkeypatch.setattr(profiles_mod, "list_profiles", boom)
    resp = client.get(f"{V1}/profiles")
    assert resp.status_code == 503
    assert "disk exploded" not in resp.text


def test_log_tail_is_cut_after_redaction(client: TestClient) -> None:
    """A tail window opening inside a secret hands the redactor a credential without the context
    it keys on: the ``Bearer`` prefix, or a PEM block's ``BEGIN`` line."""
    task_id = create(client, idempotency_key="log-tail")["task"]["id"]
    log_path = kanban_db.worker_log_path(task_id, board="default")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("Authorization: Bearer opaque-credential-0123456789", encoding="utf-8")
    for tail_bytes in (10, 30, 40):
        body = client.get(f"{V1}/tasks/{task_id}/log", params={"tail_bytes": tail_bytes}).json()
        assert "0123456789" not in body["excerpt"], tail_bytes

    key_body = "".join(f"KEYBODY{line:02d}{'A' * 55}\n" for line in range(20))
    log_path.write_text("starting\n-----BEGIN PRIVATE KEY-----\n" + key_body + "-----END PRIVATE KEY-----\ndone\n",
                        encoding="utf-8")
    for tail_bytes in (40, 200, 700, 1300):
        body = client.get(f"{V1}/tasks/{task_id}/log", params={"tail_bytes": tail_bytes}).json()
        assert "KEYBODY" not in body["excerpt"], tail_bytes
        assert len(body["excerpt"].encode()) <= tail_bytes


def test_actions_fire_lifecycle_hooks_for_the_requested_board(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    kanban_db.create_board("ops")
    fired: list[tuple[str, object]] = []
    monkeypatch.setattr(kanban_db, "_fire_kanban_lifecycle_hook",
                        lambda event, task_id, **fields: fired.append((event, fields.get("board"))))
    done = client.post(f"{V1}/tasks?board=ops", json={"title": "to complete"}).json()["task"]["id"]
    stuck = client.post(f"{V1}/tasks?board=ops", json={"title": "to block"}).json()["task"]["id"]
    assert client.post(f"{V1}/tasks/{done}/complete?board=ops", json={"summary": "ok"}).status_code == 200
    assert client.post(f"{V1}/tasks/{stuck}/block?board=ops", json={"reason": "wait"}).status_code == 200
    assert fired and {board for _event, board in fired} == {"ops"}


def test_task_list_reports_links_and_a_cut_page(client: TestClient) -> None:
    parent = create(client, idempotency_key="list-parent")["task"]["id"]
    child = create(client, idempotency_key="list-child", parents=[parent])["task"]["id"]
    full = client.get(f"{V1}/tasks").json()
    assert full["has_more"] is False
    for task in full["tasks"]:
        assert task["links"] == client.get(f"{V1}/tasks/{task['id']}").json()["task"]["links"]
    assert {t["id"]: t["links"] for t in full["tasks"]}[parent]["children"] == [child]
    cut = client.get(f"{V1}/tasks", params={"limit": 1}).json()
    assert cut["count"] == 1 and cut["has_more"] is True


def test_sanitizer_hides_cookies_and_unterminated_private_keys() -> None:
    cookies = api._sanitize_log(
        "curl -H 'Cookie: session=abc123def456; csrf=Zx9Yw8Vu7T' -b 'sid=q1w2e3r4t5y6' https://x.test\n"
        "< Set-Cookie: hermes_session=plainvalue123456; HttpOnly\n"
        '{"Cookie": "session=jsonvalue7890"}\n'
        'Cookie: sid="quoted-value-1234"; theme=dark\n'
        'curl -H "Cookie: sid=\\"escaped-value-5678\\"; csrf=after-escape-9012" https://x.test\n'
        "git checkout -b fix/thing\n"
    )
    for secret in ("abc123def456", "Zx9Yw8Vu7T", "q1w2e3r4t5y6", "plainvalue123456", "jsonvalue7890",
                   "quoted-value-1234", "escaped-value-5678", "after-escape-9012"):
        assert secret not in cookies
    assert "git checkout -b fix/thing" in cookies

    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
    key = api._sanitize_log(f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body[::-1]}\nworker: still running\n")
    assert body not in key and body[::-1] not in key
    assert "worker: still running" in key
    dumped = api._sanitize_log('{"key": "-----BEGIN PRIVATE KEY-----\\n' + body + '\\n' + body[::-1] + '"}')
    assert body not in dumped and body[::-1] not in dumped


def test_blocking_a_running_task_reclaims_its_worker_first(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    task_id = create(client, idempotency_key="block-running")["task"]["id"]
    with kbc.connect_closing() as conn:
        kanban_db.claim_task(conn, task_id)
    reclaimed: list[str] = []
    real_reclaim = kanban_db.reclaim_task

    def reclaim(conn, tid, **kwargs):
        reclaimed.append(tid)
        return real_reclaim(conn, tid, **kwargs)

    monkeypatch.setattr(kanban_db, "reclaim_task", reclaim)
    url = f"{V1}/tasks/{task_id}"
    # A request refused anyway must not cost the worker its life.
    assert client.post(f"{url}/block", json={"kind": "typo"}).status_code == 400
    assert reclaimed == []

    blocked = client.post(f"{url}/block", json={"reason": "hold"})
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["task"]["status"] == "blocked"
    assert reclaimed == [task_id]
    with kbc.connect_closing() as conn:
        assert kanban_db.get_task(conn, task_id).claim_lock is None

    reclaimed.clear()
    assert client.post(f"{url}/unblock").status_code == 200
    assert client.post(f"{url}/block", json={"reason": "hold"}).status_code == 200
    assert reclaimed == []  # a task nobody is running has no worker to stop
