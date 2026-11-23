# hermes-kanban-rest

A small, authenticated REST API over the [Hermes Agent](https://github.com/NousResearch/hermes-agent)
Kanban store, for external control planes. It is a Hermes plugin: the dashboard mounts it at
`/api/plugins/kanban-rest/v1`, and it reads and writes through the same `hermes_cli.kanban_db`
functions as the CLI, the dashboard, the tools and the dispatcher. It adds no queue and no schema.

The API is workflow-oriented and safe by default. Task bodies, results, comment text, workspace
paths, claim locks, worker PIDs, session IDs, raw event payloads, run metadata/errors/summaries and
unredacted logs are never returned. The log endpoint returns only a bounded excerpt after Hermes
secret redaction and absolute-path removal. The one exception is the
[run transcript](#run-transcripts-opt-in), which is off unless the operator enables it.

## Requirements

- A Hermes Agent build that includes all three of these changes (none is in a release yet). Each
  is a hard requirement:
  - [#159312](https://github.com/NousResearch/hermes-agent/pull/159312) scoped token routes
    (`register_token_route_prefix(..., scope=..., provider=...)`). Without it the plugin fails to
    load, and `hermes plugins list` shows the import error.
  - [#159311](https://github.com/NousResearch/hermes-agent/pull/159311) atomic task edits
    (`kanban_db_edit.update_task_fields`). Without it the API module fails to import and no `/v1`
    route is mounted.
  - [#159310](https://github.com/NousResearch/hermes-agent/pull/159310) race-safe idempotent
    creates (`kanban_db.create_task_idempotent`). Without it `POST /tasks` fails with 500.
- The plugin reads the Kanban store through `hermes_cli.kanban_db*` and a few read-only SQL queries
  of its own. These are not a published plugin API, so a Hermes release can change them; pin the
  plugin to a Hermes version you have tested.
- The default in-process plugin isolation (`plugins.isolation: in_process`). The token route is
  registered in the process that serves the dashboard, which a hosted plugin process is not.

## Install

```bash
hermes plugins install https://github.com/andriy4k07/hermes-kanban-rest
hermes plugins enable kanban-rest
```

Restart the dashboard (`hermes dashboard`) so it mounts the routes.

## Configure the service credential

Generate a secret with a CSPRNG, store it in the profile's `.env`, and name that variable in the
plugin's `secret_env` setting:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # 256 bits, 43 characters
echo 'KANBAN_REST_API_SECRET=<the value>' >> ~/.hermes/.env
hermes plugins config kanban-rest                              # set secret_env: KANBAN_REST_API_SECRET
```

or directly in `config.yaml`:

```yaml
plugins:
  enabled: [kanban-rest]
  entries:
    kanban-rest:
      settings:
        secret_env: KANBAN_REST_API_SECRET
        # min_secret_chars: 43   # shortest secret accepted
```

The secret is read through Hermes' credential route (`agent.secret_scope.get_secret`). Naming it in
`secret_env` also keeps it out of agent subprocesses: Hermes withholds every variable a
`*_secret_env` setting points at from terminal and tool children and from the persisted terminal
snapshot. Credentialed CLI children that inherit provider credentials (for example a delegated
Claude Code or Codex process) are the one exception, as for any other configured API key.

A short or obviously structured secret (under `min_secret_chars`, fewer than 16 distinct
characters, or one block repeated) is refused at startup and the credential stays off. That check
only catches degenerate values; it cannot tell how a secret was generated.

## Authentication and scopes

Callers send `Authorization: Bearer <secret>`. The plugin registers a token-only dashboard-auth
provider whose principal (`kanban-api`) carries the `kanban` scope, and registers the `/v1` prefix
as a token route demanding that scope:

- a missing or wrong token gets **401**; another service credential (for example the gateway drain
  secret) authenticates but lacks the scope and gets **403**, and this credential cannot open
  their routes either;
- once the credential is active, `/v1` accepts only it, on every bind, loopback included;
- with `secret_env` unset (or the plugin disabled), `/v1` falls back to dashboard-session auth,
  which no headless controller can use;
- the interactive dashboard, including the bundled Kanban board's routes under
  `/api/plugins/kanban/`, stays on the cookie/session gate.

Within this API the credential is not narrowed further: one secret reads and writes every board,
and with transcripts enabled it reads the runs of every profile that opted in. Hand it only to a control plane you would trust with the whole Kanban store.

```bash
export HERMES_URL="http://127.0.0.1:9119"
export API="$HERMES_URL/api/plugins/kanban-rest/v1"
export AUTH="Authorization: Bearer $KANBAN_REST_API_SECRET"
```

## Endpoints

Paths are relative to `/api/plugins/kanban-rest/v1`.

| Area | Endpoints |
|---|---|
| Status | `GET /health`, `GET /capabilities` |
| Boards | `GET /boards`, `GET /boards/{id-or-name}` |
| Profiles | `GET /profiles` |
| Tasks | `GET /tasks`, `POST /tasks`, `GET /tasks/{id}`, `PATCH /tasks/{id}` |
| Actions | `POST /tasks/{id}/comment`, `/complete`, `/block`, `/unblock`, `/archive` |
| Dependencies | `POST /tasks/{parent}/links/{child}`, `DELETE /tasks/{parent}/links/{child}` |
| Observation | `GET /tasks/{id}/events`, `/runs`, `/log`, `/transcript` (opt-in) |

All task endpoints accept `?board=<board-id>`; omit it for the current board. An invalid board id is
400, an unknown one 404.

- `GET /tasks` filters on `status`, `assignee`, `tenant`, `include_archived` and `limit` (at most
  200). There is no cursor: `has_more: true` means more tasks match, so narrow the filters. For
  totals use the per-status `counts` of `GET /boards`.
- `GET /profiles` is the assignee roster: `name`, `description` (from `profile.yaml`) and
  `has_description` only. There is no endpoint that manages or starts a profile: an assigned task
  becomes eligible through the normal Kanban rules and the gateway's dispatcher launches it.
- Task payloads carry `created_by` (the profile or surface that created the card) beside
  `assignee`; each run in `GET /tasks/{id}/runs` names the `profile` that executed it.
- Cards and comments created through the API are attributed to the verified principal with an
  `api:` prefix (`api:kanban-api`, or `api:external` with no service token). The caller cannot
  choose it: a comment with an `author` field is refused with 422. The prefix can never match a
  profile name, so a worker never mistakes an operator's comment for its own.
- `PATCH /tasks/{id}` applies all fields in one transaction. `title`/`body` edits on a `done` or
  `archived` task are refused with 409; `priority` and `assignee` may still change (`assignee` not
  while running). `null` clears `body` and unassigns `assignee`; `null` for `title` or `priority`
  is 422.
- `POST /tasks/{id}/complete` needs evidence: a non-empty `summary` unless the task already has a
  result, otherwise 400 and the task stays open.
- `POST /tasks/{id}/block` on a running task first reclaims it (the worker is stopped with SIGTERM,
  then SIGKILL) so no worker keeps running behind a blocked card.
- Linking two tasks returns 404 when either does not exist, 400 only for a self-dependency or a
  cycle.
- `events` (default 100, at most 500) and `runs` (default 50, at most 200) return the newest
  entries, oldest first. `log` returns a redacted excerpt of at most `tail_bytes` (default 8192,
  at most 32768). The log is read from a line boundary and cut to `tail_bytes` after redaction, so
  the excerpt's first line can be partial.
- Error details are echoed only when they are known-safe validation messages; anything else is a
  stable generic message, with the raw error logged server-side.

### Idempotency

`POST /tasks` accepts an `Idempotency-Key` header or an `idempotency_key` field (both set and
different: 409). Repeating a request with the same key returns the existing live task with
**200** and `created: false`; a new task is **201** with `created: true`. The key is unique among
live (non-archived) tasks on the board through a partial `UNIQUE` index, so two concurrent `POST`s
with one key still resolve to one task. Archiving a task frees its key. A repeat is matched by key
alone: its body is not compared, so a reused key with a different title returns the original task.
A blank key is refused with 422.

## Example: a parent operation and dependent work

A link means **the parent is a prerequisite for the child**. Declare it in the create request: a
child created with an assignee and no parents is `ready` at once, so the dispatcher may claim it
before a later link request arrives, and a running child cannot be linked.

```bash
PARENT=$(curl -fsS -X POST "$API/tasks?board=default" -H "$AUTH" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: maintenance-2026-07-10-parent' \
  -d '{"title": "Approve and fan out maintenance", "tenant": "maintenance", "priority": 20}' | jq -r '.task.id')

CHILD=$(curl -fsS -X POST "$API/tasks?board=default" -H "$AUTH" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: maintenance-2026-07-10-child-a' \
  -d '{"title": "Process workstream A", "assignee": "worker-a", "tenant": "maintenance",
       "parents": ["'"$PARENT"'"]}' | jq -r '.task.id')

# Release the child once the parent's work is done.
curl -fsS -X POST "$API/tasks/$PARENT/complete?board=default" -H "$AUTH" \
  -H 'Content-Type: application/json' -d '{"summary": "Scope approved."}'

# Poll state and the sanitized timeline.
curl -fsS "$API/tasks?board=default&tenant=maintenance" -H "$AUTH" \
  | jq '.tasks[] | {id, title, status, assignee, created_by, links}'
curl -fsS "$API/tasks/$CHILD/events?board=default" -H "$AUTH" | jq
curl -fsS "$API/tasks/$CHILD/log?board=default&tail_bytes=8192" -H "$AUTH" | jq
```

## Run transcripts (opt-in)

`GET /tasks/{id}/transcript` returns a worker's step-by-step session for one run: reasoning, tool
calls and results, and replies. That includes the task body (the worker's first prompt) and its
output, so it is **off by default**: the endpoint returns 404 and `GET /capabilities` leaves
`transcript` out of `observability`. Turn it on per profile:

```yaml
plugins:
  entries:
    kanban-rest:
      settings:
        expose_transcripts: true
```

A transcript is served only when the profile that **ran the worker** has it on, as well as the
profile serving the API; a `?profile=` on the request does not change whose opt-in counts. With
workers in named profiles, enable the plugin and the setting in each of them: the worker side of
the plugin is what records which session a run opened.

When a dispatcher-spawned worker starts its session, the plugin's `on_session_start` hook stores
the link (task, run, session) in that worker profile's own plugin state. Only a live run of the
task named by the worker's environment is linked, and the first agent to start wins, so a
background review or a delegated child in the same worker cannot relabel the run. Runs started
before the setting was on, or whose worker has not started yet, return an empty `messages` list.

Every text field goes through the same redaction and path removal as the log excerpt. Tool results
are capped at 4,000 characters and other fields at 20,000 (`truncated: true` marks a cut). System
messages are never returned, and neither is the worker's session id.

| Query | Default | Meaning |
|---|---|---|
| `run_id` | latest run | A run of this task (`GET /tasks/{id}/runs`); a run of another task is 404. |
| `after_id` | `0` | Return steps after this cursor. Pass the previous `next_after_id` to poll. |
| `limit` | `200` | Page size, 1-500. |
| `latest` | `false` | The newest `limit` steps instead (`after_id` is ignored; `has_more` then means older steps exist). |

The transcript is readable while the run is going, and continuations after context compression
are followed. A finished run's transcript ends with the run: the session can be resumed later
(`hermes --resume`), and steps written more than two minutes after the run ended are not returned.

```bash
curl -fsS "$API/tasks/$CHILD/transcript?board=default&after_id=0" -H "$AUTH" \
  | jq '{run_status, next_after_id, has_more, steps: [.messages[] | {id, role, tool_calls: [.tool_calls[].name], truncated}]}'
```

Each message carries `id`, `uid`, `role` (`user`, `assistant` or `tool`), `content`, `reasoning`,
`tool_calls` (`id`, `name`, `arguments`), `tool_name`, `tool_call_id`, `timestamp` and `truncated`,
wrapped with `task_id`, `run_id`, `run_status`, `next_after_id` and `has_more`. `id` is only the
paging cursor: when a worker compacts its context mid-run, the steps it carries forward are stored
again under new ids, so a poller can receive a step it already has. `uid` stays the same, so
deduplicate on it.

## Development

The tests run against a real Hermes checkout (with the PRs above) using its environment, each test
in its own temporary `HOME` and `HERMES_HOME`:

```bash
HERMES=/path/to/hermes-agent
PYTHONPATH="$HERMES" "$HERMES/.venv/bin/python" -m pytest
ruff check .
```

## License

MIT
