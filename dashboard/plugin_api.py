"""Sanitized v1 REST adapter for the shared Hermes Kanban store.

The dashboard mounts this router at ``/api/plugins/kanban-rest/``; every route lives under
``/v1``. It reads and writes through the same ``hermes_cli.kanban_db`` functions as the CLI,
dashboard, tools and dispatcher, and exposes workflow/task concepts rather than SQLite rows:
private task bodies, results, comments, workspace paths, claims, process data, profile internals
and raw event payloads are never serialized.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from fastapi import APIRouter, HTTPException, Query

from agent.redact import redact_sensitive_text
from hermes_cli import kanban_db
from hermes_cli import kanban_db_connect as kbc

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1")

_API_VERSION = "1"
_DEFAULT_LOG_TAIL = 8_192
_MAX_LOG_TAIL = 32_768
# Read this much before the requested tail so redaction sees where a secret starts (a PEM
# block's BEGIN line, an auth header's name); the excerpt is cut after redacting.
_LOG_REDACTION_CONTEXT = 32_768
# A directory name may hold spaces, so a name runs on past a space while a separator still
# follows and no character that ends prose (or that Windows forbids in a name) intervenes.
# Windows arm: drive or UNC root; separators may be doubled (JSON-escaped).
_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![\w:])(?:"
    r"(?:[A-Za-z]:[\\/]+|\\{2,})(?:[^\\/\r\n<>:\"|?*]+[\\/]+)*[^\s\\/]*"
    r"|/(?=[^/\s])(?:[^/\s]+(?: [^/\s<>:\"|?*,;()\[\]{}'=]+)*/+)*[^/\s]*)"
)
# The id shape Hermes mints for sessions; a worker prints its own on exit.
_SESSION_ID_RE = re.compile(r"\b\d{8}_\d{6}_[0-9a-f]{6,}\b")
# An ``Authorization: Bearer/Basic <token>`` header anywhere in a line (a dumped curl command,
# a shell trace), or a bare ``Bearer <token>``. Quotes (possibly escaped) around the name and
# value cover a header dumped as a JSON or dict entry.
_AUTH_HEADER_RE = re.compile(
    r"""(?i)(authorization\\?["']?\s*[:=]\s*\\?["']?(?:bearer|basic)\s+|\bbearer\s+)[^\s"'\\]+"""
)
# A cookie is a credential the shared redactor has no rule for. Cookie values may themselves
# be quoted (``sid="..."``), so a match never ends at the first quote: it runs to the end of
# the line, or to the unescaped quote that encloses the header / the JSON value / curl's argument.
_COOKIE_RE = re.compile(
    r"""(?ix)
      ( (?P<q>["'])? \b(?:set-)?cookie \s*[:=]\s* )           # Cookie: a="b"; c=d  /  'Cookie: a=b'
        (?(q) (?:\\.|(?!(?P=q))[^\\\r\n])+ | [^\r\n]+ )
    | ( \b(?:set-)?cookie \\?["'] \s*[:=]\s* \\?(?P<v>["']) )  # "Cookie": "a=b"
        (?:\\.|(?!(?P=v))[^\\\r\n])+
    | ( (?<![\w-])(?:-b|--cookie)[ =] \\?(?P<c>["'])? )        # curl -b 'a=b', not -b jar.txt
        (?(c) (?=(?:\\.|(?!(?P=c))[^\\\r\n])*=)(?:\\.|(?!(?P=c))[^\\\r\n])+ | (?=\S*=)\S+ )
    """
)
# The shared redactor needs the END line. A live log, or output cut mid-key, has only BEGIN
# and part of the body: hide BEGIN and the base64 / PEM-header lines that follow it.
_OPEN_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----"
    r"(?:(?:\s|\\[nr])*(?:[A-Za-z0-9+/=]{24,}|(?:[A-Za-z0-9+/=]+|(?:Proc-Type|DEK-Info):[^\r\n\\]*)(?=[\r\n\\\"']|$)))*"
)

# Known-safe validation messages from ``kanban_db`` that may be echoed to an external caller
# verbatim: they carry no filesystem paths, SQL, or other internal detail. Anything else
# collapses to a stable generic fallback while the raw error is logged server-side.
_SAFE_ERROR_MARKERS = (
    "title is required",
    "unknown parent task",
    "unknown task",
    "a task cannot depend on itself",
    "would create a cycle",
    "is a toolset name",
    "are toolset names",
    "skill name cannot contain comma",
    "must be one of",
    "has no result or summary evidence",
    "cannot reassign",
    "cannot edit the title/body",
)


def _client_error(exc: Exception, *, fallback: str, status_code: int = 400) -> HTTPException:
    """An HTTPException whose ``detail`` is a known-safe validation message or ``fallback``;
    the raw text is logged, never sent."""
    message = str(exc)
    detail = message if any(m in message for m in _SAFE_ERROR_MARKERS) else fallback
    log.warning("kanban-rest request rejected (detail=%r): %s", detail, message)
    return HTTPException(status_code=status_code, detail=detail)


@contextmanager
def _connection(board: Optional[str]) -> Iterator[sqlite3.Connection]:
    # ``connect`` runs the schema/migration pass on a path's first open and caches it; calling
    # ``init_db`` per request would evict that and re-run the integrity probe on every poll.
    slug = _resolve_board_slug(board)
    # Lifecycle hooks name their board from the scoped current board, not from the connection.
    with kanban_db.scoped_current_board(slug), kbc.connect_closing(board=slug) as conn:
        yield conn


def _resolve_board_slug(board: Optional[str]) -> str:
    if board is None or not str(board).strip():
        return kanban_db.get_current_board()
    slug = str(board).strip().lower()
    try:
        exists = kanban_db.board_exists(slug)  # validates the slug: ValueError on a bad one
    except ValueError as exc:
        raise _client_error(exc, fallback="invalid board id") from exc
    if not exists:
        raise HTTPException(status_code=404, detail="board not found")
    return slug


def _resolve_board_id_or_name(value: str) -> str:
    candidate = value.strip()
    try:
        if kanban_db.board_exists(candidate.lower()):
            return candidate.lower()
    except ValueError:
        pass  # not a slug: try it as a display name
    matches = [
        item["slug"]
        for item in kanban_db.list_boards(include_archived=False)
        if str(item.get("name") or "").casefold() == candidate.casefold()
    ]
    if not matches:
        raise HTTPException(status_code=404, detail="board not found")
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="board name is ambiguous; use its id")
    return matches[0]


def _board_counts(slug: str) -> dict[str, int]:
    # Boards are separate SQLite files, so per-board counts need one connection each.
    with kbc.connect_closing(board=slug) as conn:
        rows = conn.execute("SELECT status, COUNT(*) AS count FROM tasks GROUP BY status").fetchall()
        return {row["status"]: int(row["count"]) for row in rows}


def _board_dto(meta: dict[str, Any], *, current: str) -> dict[str, Any]:
    slug = str(meta["slug"])
    counts = _board_counts(slug)
    return {
        "id": slug,
        "name": str(meta.get("name") or slug),
        "description": str(meta.get("description") or ""),
        "icon": str(meta.get("icon") or ""),
        "color": str(meta.get("color") or ""),
        "created_at": meta.get("created_at"),
        "is_current": slug == current,
        "counts": counts,
        "total": sum(counts.values()),
    }


def _task_dto(conn: sqlite3.Connection, task: Any, graph: Optional[dict[str, dict]] = None) -> dict[str, Any]:
    """``graph``: ``task_graph_contexts`` for a whole page, so a list costs two link queries
    instead of two per task."""
    links = (graph or kanban_db.task_graph_contexts(conn, [task.id]))[task.id]
    return {
        "id": task.id,
        "title": task.title,
        "assignee": task.assignee,
        # Which profile (or surface, e.g. "api:kanban-api" / "dashboard") created the card, so a
        # control plane can show orchestrator fan-out, not just who the work was routed to.
        "created_by": task.created_by,
        "status": task.status,
        "priority": task.priority,
        "tenant": task.tenant,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "completed_at": task.completed_at,
        "workflow_template_id": task.workflow_template_id,
        "current_step_key": task.current_step_key,
        "block_kind": task.block_kind,
        "links": {
            "parents": [link["id"] for link in links["parents"]],
            "children": [link["id"] for link in links["children"]],
        },
    }


def _require_task(conn: sqlite3.Connection, task_id: str) -> Any:
    task = kanban_db.get_task(conn, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return task


def _task_response(conn: sqlite3.Connection, task_id: str) -> dict[str, Any]:
    return {"task": _task_dto(conn, _require_task(conn, task_id))}


def _newest_rows(conn: sqlite3.Connection, sql: str, order: str, task_id: str, limit: int) -> list[sqlite3.Row]:
    """The newest ``limit`` rows of ``sql`` (one task's rows), still oldest-first; the LIMIT
    runs in SQL so long histories never materialise every row."""
    newest_first = order.replace("ASC", "DESC")
    return conn.execute(
        f"SELECT * FROM ({sql} ORDER BY {newest_first} LIMIT ?) ORDER BY {order}", (task_id, limit),
    ).fetchall()


def _read_log_tail(task_id: str, *, board: str, tail_bytes: int) -> Optional[str]:
    """The worker log's last ``tail_bytes``, never starting mid-line (a cut line can lose the
    context, ``Bearer ``, a secret is recognised by); None when there is no log."""
    path = kanban_db.worker_log_path(task_id, board=board)
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            if size > tail_bytes:
                f.seek(size - tail_bytes)
                f.readline()
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return None


def _sanitize_log(content: str) -> str:
    redacted = redact_sensitive_text(content, force=True, redact_url_credentials=True)
    redacted = _OPEN_PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", redacted)
    redacted = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _COOKIE_RE.sub(lambda m: (m[1] or m[3] or m[5]) + "[REDACTED]", redacted)
    redacted = _SESSION_ID_RE.sub("[SESSION]", redacted)
    return _ABSOLUTE_PATH_RE.sub("[PATH]", redacted)


@router.get("/health")
def health() -> dict[str, Any]:
    current = kanban_db.get_current_board()
    try:
        with _connection(current) as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="kanban store unavailable") from exc
    return {"status": "ok", "service": "hermes-kanban", "api_version": _API_VERSION, "current_board": current}


@router.get("/capabilities")
def capabilities() -> dict[str, Any]:
    return {
        "api_version": _API_VERSION,
        "boards": {"read": True, "write": False},
        "tasks": {"read": True, "create": True, "update": True},
        "actions": ["comment", "complete", "block", "unblock", "archive"],
        "links": {"create": True, "delete": True},
        "observability": ["events", "runs", "sanitized_log_excerpt"],
        "task_statuses": sorted(kanban_db.VALID_STATUSES),
        "block_kinds": sorted(kanban_db.VALID_BLOCK_KINDS),
        "idempotent_task_creation": True,
        "profile_execution": False,
        # Read-only roster (GET /profiles): name + description only, for assignee pickers.
        "profiles_api": True,
    }


@router.get("/profiles")
def list_profiles() -> dict[str, Any]:
    """Sanitized assignee roster: the profile name and its operator-facing description only.
    Models, providers, paths, env/config state and skill inventories are not exposed."""
    from hermes_cli import profiles as profiles_mod  # lazy: heavy CLI import

    try:
        infos = profiles_mod.list_profiles()
    except Exception as exc:
        log.warning("kanban-rest profiles listing failed: %s", exc)
        raise HTTPException(status_code=503, detail="profiles unavailable") from exc
    roster = sorted(
        ({"name": info.name, "description": (info.description or "").strip(),
          "has_description": bool((info.description or "").strip())} for info in infos),
        key=lambda item: item["name"],
    )
    return {"profiles": roster, "count": len(roster)}


@router.get("/boards")
def list_boards() -> dict[str, Any]:
    current = kanban_db.get_current_board()
    boards = [_board_dto(meta, current=current) for meta in kanban_db.list_boards(include_archived=False)]
    return {"boards": boards, "current": current, "count": len(boards)}


@router.get("/boards/{board_id_or_name}")
def get_board(board_id_or_name: str) -> dict[str, Any]:
    slug = _resolve_board_id_or_name(board_id_or_name)
    return {"board": _board_dto(kanban_db.read_board_metadata(slug), current=kanban_db.get_current_board())}


@router.get("/tasks")
def list_tasks(
    board: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    assignee: Optional[str] = Query(default=None),
    tenant: Optional[str] = Query(default=None),
    include_archived: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=200),
) -> dict[str, Any]:
    try:
        with _connection(board) as conn:
            tasks = kanban_db.list_tasks(
                conn, status=status, assignee=assignee, tenant=tenant,
                include_archived=include_archived, limit=limit + 1,
            )
            has_more = len(tasks) > limit
            tasks = tasks[:limit]
            graph = kanban_db.task_graph_contexts(conn, [task.id for task in tasks])
            items = [_task_dto(conn, task, graph) for task in tasks]
    except ValueError as exc:
        raise _client_error(exc, fallback="invalid task filter") from exc
    return {"tasks": items, "count": len(items), "limit": limit, "has_more": has_more}


@router.get("/tasks/{task_id}")
def get_task(task_id: str, board: Optional[str] = Query(default=None)) -> dict[str, Any]:
    with _connection(board) as conn:
        return _task_response(conn, task_id)


@router.get("/tasks/{task_id}/events")
def task_events(
    task_id: str,
    board: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    with _connection(board) as conn:
        _require_task(conn, task_id)
        rows = _newest_rows(conn, "SELECT * FROM task_events WHERE task_id = ?",
                            "created_at ASC, id ASC", task_id, limit)
        items = [{"id": row["id"], "task_id": row["task_id"], "kind": row["kind"],
                  "created_at": row["created_at"], "run_id": row["run_id"]} for row in rows]
        return {"events": items, "count": len(items)}


@router.get("/tasks/{task_id}/runs")
def task_runs(
    task_id: str,
    board: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    with _connection(board) as conn:
        _require_task(conn, task_id)
        rows = _newest_rows(conn, "SELECT * FROM task_runs WHERE task_id = ?",
                            "started_at ASC, id ASC", task_id, limit)
        items = [
            {
                "id": row["id"],
                # The profile that executed this attempt: reassignment between retries makes the
                # per-run value the only accurate execution record.
                "profile": row["profile"],
                "status": row["status"],
                "outcome": row["outcome"],
                "started_at": row["started_at"],
                "ended_at": row["ended_at"],
            }
            for row in rows
        ]
        return {"runs": items, "count": len(items)}


@router.get("/tasks/{task_id}/log")
def task_log(
    task_id: str,
    board: Optional[str] = Query(default=None),
    tail_bytes: int = Query(default=_DEFAULT_LOG_TAIL, ge=1, le=_MAX_LOG_TAIL),
) -> dict[str, Any]:
    slug = _resolve_board_slug(board)
    with _connection(slug) as conn:
        _require_task(conn, task_id)
    content = _read_log_tail(task_id, board=slug, tail_bytes=tail_bytes + _LOG_REDACTION_CONTEXT)
    try:
        size = kanban_db.worker_log_path(task_id, board=slug).stat().st_size
    except OSError:
        size = 0
    return {
        "task_id": task_id,
        "exists": content is not None,
        "size_bytes": size,
        "tail_bytes": tail_bytes,
        "truncated": size > tail_bytes,
        "excerpt": _sanitize_log(content or "").encode()[-tail_bytes:].decode(errors="ignore"),
    }
