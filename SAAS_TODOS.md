# Claven — SaaS Migration Todos

## Architecture

### Execution model: stateless + serverless

The service is fully stateless — no filesystem state between invocations. All state lives in Neon (free plan Postgres). This enables a true scale-to-zero serverless model on Cloud Run where containers only run when there is actual work to do.

The polling loop in `main.py` (`while running: shutdown_event.wait(...)`) is replaced by event-driven execution. Three notification modes are supported for reliability and flexibility:

| Mode | Trigger | Requires public endpoint? | Latency | Use case |
|---|---|---|---|---|
| **Push** | Pub/Sub push → Cloud Run webhook | Yes | Near-realtime | Production |
| **Pull** | Cloud Scheduler → Cloud Run pulls Pub/Sub | No | Scheduled interval | Fallback, local dev |
| **Poll** | Cloud Scheduler → Cloud Run polls Gmail history API | No | Scheduled interval | No Pub/Sub, local dev |

All three modes run the same processing logic — the trigger mechanism is fully swappable because the service is stateless and all state (including `historyId`) lives in Neon.

### Push mode (primary)

1. On user signup, call `gmail.users.watch()` to register a Pub/Sub topic for their inbox
2. Gmail publishes a notification to the Pub/Sub topic when new mail arrives
3. Pub/Sub **push subscription** POSTs to the Cloud Run webhook endpoint
4. Cloud Run spins up, fetches Gmail history since stored `historyId`, processes messages, updates Neon, terminates
5. Pub/Sub retries automatically on non-2xx with exponential backoff for up to 7 days

### Pull mode (fallback)

Same Pub/Sub topic, second **pull subscription**. Cloud Scheduler triggers Cloud Run on a configurable interval; the instance pulls all pending messages from the subscription, processes them, and exits. Works without a public endpoint — useful when the push endpoint is unavailable or for local dev against a real inbox.

### Poll mode (direct fallback)

No Pub/Sub involved. Cloud Scheduler triggers Cloud Run on a configurable interval; the instance calls `gmail.users.list_history()` directly since the stored `historyId`, processes new messages, updates Neon, exits. Fully self-contained — useful for local development without any GCP infrastructure.

### Execution primitives

| Primitive | What it handles |
|---|---|
| **Cloud Run service** | Push webhook handler, OAuth endpoints, user dashboard, watch renewal, pull/poll trigger endpoints |
| **Cloud Run Job** | One-off initial inbox scan + sent recipients scan on signup — uses `list_messages`, not `list_history`; runs to completion with no timeout constraint |
| **Cloud Scheduler** | Watch renewal every 6 days; pull/poll fallback on configurable interval |

The initial scan (Cloud Run Job) and the notification modes (push/pull/poll) are distinct code paths. The scan walks the full inbox once and establishes the `historyId`. The notification modes only process incremental history since that `historyId` and are never used for bootstrapping.

### Code structure: core library + thin entry points

All business logic lives in a `claven/core/` package. The CLI, web server, and Cloud Run Job are thin entry points that call into the core — they handle how work is triggered, not what the work is. No logic lives in entry points; no logic is duplicated across them.

```
claven/
  core/
    scan.py      # initial_scan, sent_recipients (list_messages-based, one-time)
    process.py   # process_message, run_poll, run_pull (list_history-based, incremental)
    watch.py     # gmail.users.watch / stop / renew
    db.py        # all Neon reads and writes
    gmail.py     # Gmail API calls (from gmail_service.py)
    rules.py     # label matching (from labeler.py)
    auth.py      # token storage, refresh, OAuth flow helpers

  cli.py         # click entry point — thin HTTP client to server.py
  server.py      # FastAPI/Flask entry point — parse HTTP, call core, return JSON
  job.py         # Cloud Run Job entry point — call core, exit
```

The CLI is a **thin HTTP client to the server** — it does not import or run `claven/core/` directly. This means:
- No business logic in the CLI layer
- No version drift between CLI and server (core only runs server-side)
- Concurrency is handled in one place (the server)
- Local dev: point `CLAVEN_SERVER_URL` at a local `server.py` instance
- Production: point `CLAVEN_SERVER_URL` at the Cloud Run service URL

`claven poll --once` POSTs to `$CLAVEN_SERVER_URL/internal/poll`. `POST /internal/poll` calls `core.process.run_poll()`. Same execution path regardless of caller.

### Serverless platform: Cloud Run

**Current decision: Cloud Run.** Alternatives considered: Fly.io.

Rationale for Cloud Run:
- Native integration with Pub/Sub, Cloud Scheduler, Secret Manager, Artifact Registry — all already in the stack
- Generous free tier (2M requests/month, 360K GB-seconds, 180K vCPU-seconds) — sufficient for early stage
- Pay-as-you-go beyond free tier; no hard billing cap built in (see billing risk below)

Fly.io is a viable alternative if billing risk or GCP ecosystem lock-in becomes a concern — it has always-on free instances and configurable spending limits. Revisit if Cloud Run costs become an issue.

**Billing risk:** GCP budget alerts notify but do not stop services. A retry storm or DDoS could generate unexpected charges. Mitigations: set a GCP budget alert at a low threshold ($5-10), consider a Cloud Function to disable billing if the threshold is breached. Verify current GCP billing safety options before going to production.

### Latency model

The CLI talks to the server over HTTP. End-to-end latency depends on the state of two independent components: the Cloud Run container and the Neon database.

| Config | Container | Neon | Typical latency | Notes |
|---|---|---|---|---|
| **cold-cold** | Cold | Suspended | 4–7s | Both need to wake up; worst case |
| **cold-warm** | Cold | Active | 3–6s | Container dominates; Neon was recently used |
| **warm-cold** | Warm | Suspended | ~500–600ms | Neon free tier suspends after 5 min idle |
| **warm-warm** | Warm | Active | 25–70ms | Fully warm path; excellent interactive latency |

**Container warm window:** Cloud Run keeps a container warm for approximately 15 minutes after the last request (not guaranteed; platform-managed). Within a session, only the first command pays the cold start cost.

**Neon suspension:** Neon free tier suspends the database after 5 minutes of inactivity. Wake time is ~500ms. Paid Neon plans allow disabling suspension.

**min-instances configuration:**
- `min-instances=0` (default): scale to zero, free tier, cold-cold or cold-warm on first request per session
- `min-instances=1`: one container always warm, eliminates container cold start, ~$10–15/month — defer until interactive UX is a priority for paying users

For Pub/Sub webhooks and Cloud Scheduler triggers, cold start latency is acceptable — they are not interactive. The cold start cost only matters for CLI use.

### Secrets and config

All secrets (Neon connection string, OAuth client secret, token encryption key) are stored in Google Secret Manager and mounted as environment variables. Nothing sensitive is baked into the container image.

---

## Code restructure (do this first)

Everything else depends on this shape. Current `main.py`, `gmail_service.py`, and `labeler.py` are flat scripts — restructure into a `claven/` package before adding any new functionality.

- [ ] Create `claven/` package with `core/` subpackage
- [ ] Move `labeler.py` → `claven/core/rules.py` (no logic changes)
- [ ] Move Gmail API calls from `gmail_service.py` → `claven/core/gmail.py` (no logic changes)
- [ ] Extract `initial_scan` and sent recipients logic from `main.py` → `claven/core/scan.py`
- [ ] Extract `process_message`, `poll_new_messages` from `main.py` → `claven/core/process.py`
- [ ] Create `claven/core/db.py` as a stub (file-based for now, swapped for Neon later)
- [ ] Create `claven/core/auth.py` as a stub (wraps current `get_service` for now)
- [ ] Create `claven/cli.py` as the new entry point — thin `click` wrapper over core functions, replacing `main.py`
- [ ] Create `claven/server.py` and `claven/job.py` as empty stubs so the shape is established
- [ ] Verify the restructured code runs identically to the current `main.py` before proceeding

## Auth & OAuth

- [ ] Create a new **Web application** OAuth client in GCloud (separate from the Desktop app one); add your server's callback URL as an authorized redirect URI
- [ ] Replace `InstalledAppFlow.run_local_server()` with a proper web OAuth flow: `/oauth/start` redirects to Google, `/oauth/callback` exchanges the code for tokens
- [ ] Add `state` parameter to the OAuth redirect and verify it on callback (CSRF protection)
- [ ] Decide on user identity: "Sign in with Google" is simplest (email from the token's `id_token` or `userinfo` endpoint becomes the user ID), or support email/password separately
- [ ] Store and refresh tokens server-side (see Database section); the current `token.json` approach doesn't work when the server holds tokens on behalf of users

## Database

- [ ] Replace all file-based state with a database — every `accounts/<name>/*.json` file maps to a DB table:
  - `users` — id, email, created_at
  - `gmail_tokens` — user_id, access_token (encrypted), refresh_token (encrypted), expiry
  - `sent_recipients` — user_id, email_address (replaces `sent_recipients_cache.json`)
  - `scan_state` — user_id, history_id, resume_index, processed_message_ids, known_senders_count (replaces `scan_checkpoint.json`)
- [ ] Encrypt tokens at rest — never store raw access/refresh tokens in the DB
- [ ] Replace the file-based `load_scan_checkpoint` / `save_scan_checkpoint` and `_load_recipients_cache` / `_save_recipients_cache` functions with DB-backed equivalents

## Per-User Configuration

- [ ] Move `config.yaml` label rules into the database so each user can have their own rules
- [ ] Build a UI or API for users to manage their label rules (add/edit/delete)
- [ ] Keep polling interval configurable per user or as a server-wide setting (used by pull and poll modes)

## Initial Scan (one-time per user)

Runs **once on signup** using a different code path from all three notification modes. Walks the entire inbox via `list_messages` (not `list_history`), applies label rules to every existing message, and builds the `sent_recipients` cache from Sent mail. Can take minutes for large inboxes. After it completes, `historyId` is written to the DB and the user switches to incremental processing via push/pull/poll.

This is **not** the same as poll mode — poll uses `list_history` and only touches new mail. The initial scan uses `list_messages` and touches everything.

- [ ] Trigger a **Cloud Run Job** on signup to run the initial inbox scan and sent recipients scan — must not block the OAuth callback or webhook handler
- [ ] Initial scan writes `historyId` to Neon on completion; this is the starting point for all subsequent incremental processing
- [ ] Scan is resumable via checkpoint in Neon (already implemented with `scan_checkpoint.json` — migrate to DB)
- [ ] Support running via CLI for local use — see CLI spec: `claven scan --user <email>`

## Notification Modes

These all share the same incremental processing logic: `list_history` since stored `historyId` → apply rules → update `historyId`. They differ only in how processing is triggered. **None of these replace the initial scan** — they only handle new mail after the scan has completed and a `historyId` is established.

### Push (primary — Pub/Sub push subscription → Cloud Run webhook)

- [ ] On user signup (after initial scan completes), call `gmail.users.watch()` to activate push notifications; `historyId` is already in DB from the scan
- [ ] Create a Pub/Sub **push subscription** pointing to `/webhook/gmail` on the Cloud Run service
- [ ] Implement `/webhook/gmail`: decode Pub/Sub notification, look up user by email, fetch Gmail history since stored `historyId`, process new messages, update `historyId` in DB
- [ ] Return 2xx within Pub/Sub's delivery deadline (acknowledge before processing completes if needed, or process synchronously for small batches)
- [ ] `watch()` subscriptions expire after 7 days — Cloud Scheduler hits `/internal/renew-watches` every 6 days

### Pull (fallback — Pub/Sub pull subscription → scheduled Cloud Run)

- [ ] Create a second Pub/Sub **pull subscription** on the same topic (separate from the push subscription so both receive all notifications independently)
- [ ] Implement `/internal/pull`: pull all pending messages from the pull subscription, deduplicate by `historyId`, run incremental processing for each user, update Neon
- [ ] Create a Cloud Scheduler job to hit `/internal/pull` on a configurable interval (e.g. every 5 minutes) as a reliability backstop
- [ ] Pull mode should work without a public endpoint for local development — see CLI spec: `claven pull --once`

### Poll (direct fallback — scheduled Cloud Run polls Gmail history API)

- [ ] Implement `/internal/poll`: iterate all active users, call `list_history()` since stored `historyId` for each, run incremental processing, update Neon
- [ ] Create a Cloud Scheduler job to hit `/internal/poll` on a configurable interval as a fallback when Pub/Sub is unavailable
- [ ] Poll mode must work fully locally with no GCP infrastructure — see CLI spec: `claven poll --once` or `claven poll --interval 60`
- [ ] Remove the old `while running:` polling loop from `main.py` once poll mode is implemented via the new path

## CLI

### Design principles

- **`--output json`** (global flag) — all commands emit structured JSON to stdout instead of log lines; errors go to stderr as JSON
- **Fully headless** — no interactive prompts; all inputs are flags or environment variables
- **Exit codes**: 0 = success, 1 = usage/input error, 2 = runtime/API error
- **`DATABASE_URL`** env var is the primary way to point at Neon; overridable with `--db-url`
- **`--user <email>`** is required on most commands; omitting it operates on all users where it makes sense (e.g. `watch renew`, `poll`)
- Implemented with `click` (subcommand groups, composable, good help output)

### Output shapes

Success (stdout):
```json
{ "ok": true, "data": { ... } }
```

Error (stderr):
```json
{ "ok": false, "error": "<snake_case_type>", "message": "<human readable detail>" }
```

Progress events during long-running commands (stdout, one JSON object per line):
```json
{ "event": "progress", "processed": 120, "total": 1500, "pct": 8 }
```

### Command reference

#### `claven auth`

```
claven auth login  [--user <email>]
claven auth logout  --user <email>
claven auth status [--user <email>]
```

- `login` — starts the OAuth flow; prints the authorization URL for headless environments (no browser auto-open); exchanges the code and stores encrypted tokens in Neon
- `logout` — revokes tokens and deletes the user's row from `gmail_tokens`
- `status` — reports token validity and expiry for one user or all users

`auth status --output json` example:
```json
{
  "ok": true,
  "data": {
    "user": "user@example.com",
    "token_valid": true,
    "expires_at": "2026-04-24T10:00:00Z"
  }
}
```

#### `claven scan`

```
claven scan --user <email> [--max-messages N]
```

Runs the one-time initial inbox scan using `list_messages` (not `list_history`). Applies label rules to all existing inbox messages, builds the `sent_recipients` cache from Sent mail, writes `historyId` to Neon on completion. Resumable — safe to interrupt and re-run.

`scan --output json` streams progress events then a final summary:
```json
{ "event": "progress", "processed": 500, "total": 1500, "pct": 33 }
{ "event": "done", "processed": 1500, "labeled": 42, "history_id": "87654321" }
```

#### `claven watch`

```
claven watch start  --user <email>
claven watch renew [--user <email>]
claven watch stop   --user <email>
```

- `start` — calls `gmail.users.watch()`; requires a `historyId` already present in Neon (i.e. scan must have run first); stores watch expiry in DB
- `renew` — renews expiring subscriptions; operates on all users if `--user` is omitted; safe to run on a schedule
- `stop` — calls `gmail.users.stop()` and clears the watch record from DB

#### `claven pull`

```
claven pull [--user <email>] [--once]
```

Pulls pending messages from the Pub/Sub pull subscription, runs incremental processing (`list_history` since stored `historyId`) for each notified user, updates Neon. With `--once`, exits after draining the current backlog. Without `--once`, loops at the configured interval (for local development use).

#### `claven poll`

```
claven poll [--user <email>] [--once] [--interval N]
```

Polls the Gmail History API directly — no Pub/Sub required. Iterates all active users (or one if `--user` is given), calls `list_history` since stored `historyId`, processes new messages, updates Neon. `--interval N` runs continuously every N seconds (default 60). `--once` exits after a single pass.

#### `claven status`

```
claven status [--user <email>]
```

Shows current state for one user or all users: token validity, last processed timestamp, current `historyId`, watch expiry, scan completion status.

```json
{
  "ok": true,
  "data": [{
    "user": "user@example.com",
    "scan_complete": true,
    "history_id": "87654321",
    "last_processed_at": "2026-04-23T09:15:00Z",
    "watch_expires_at": "2026-04-30T09:00:00Z",
    "token_valid": true
  }]
}
```

#### `claven rules` _(future)_

```
claven rules list   --user <email>
claven rules add    --user <email> --name <label> [--from <pattern>] [--subject <pattern>]
claven rules delete --user <email> --name <label>
```

Manages per-user label rules stored in Neon. Not blocking on initial implementation — `config.yaml` rules can be migrated to DB as a later step.

### Implementation tasks

- [ ] Set up `click` with a top-level group and subcommand groups (`auth`, `scan`, `watch`, `pull`, `poll`, `status`, `rules`)
- [ ] Implement global `--output json` flag and a shared output helper that switches between log lines and JSON
- [ ] Implement global `--server-url` flag (default: `$CLAVEN_SERVER_URL`) — all commands route to this base URL
- [ ] Implement shared HTTP client with JSON error handling: maps non-2xx responses to stderr JSON + exit code 2
- [ ] Implement streaming response handling for long-running commands (`scan`, `pull`, `poll`) — server sends newline-delimited JSON progress events, CLI forwards them to stdout
- [ ] Implement `auth login`, `auth logout`, `auth status`
- [ ] Implement `scan`
- [ ] Implement `watch start`, `watch renew`, `watch stop`
- [ ] Implement `pull --once` and `pull` (loop)
- [ ] Implement `poll --once`, `poll --interval N`
- [ ] Implement `status`
- [ ] Implement `rules list`, `rules add`, `rules delete` _(can follow DB migration)_

## Web Server

- [ ] Add a web framework (FastAPI, Flask, Django — pick one) to serve:
  - OAuth start/callback endpoints
  - User dashboard (connected accounts, label rules, status)
  - `/webhook/gmail` — Pub/Sub push handler
  - `/internal/scan` — trigger initial inbox scan Cloud Run Job for a new user
  - `/internal/pull` — pull pending Pub/Sub messages (triggered by Cloud Scheduler)
  - `/internal/poll` — poll Gmail history directly (triggered by Cloud Scheduler)
  - `/internal/renew-watches` — renew all active `watch()` subscriptions
- [ ] Implement session management (JWT or server-side sessions)

## Google's App Verification

- [ ] Add a privacy policy and terms of service page (required before submitting for verification)
- [ ] Submit the OAuth app for Google verification — `gmail.modify` is a restricted scope; unverified apps are capped at 100 users
- [ ] Plan for the CASA Tier 2 security assessment (required for sensitive Gmail scopes in production)

## Infrastructure (Cloud Run + Neon)

### Platform decision
- [x] **Serverless platform: Cloud Run** — chosen for native GCP integration (Pub/Sub, Scheduler, Secret Manager, Artifact Registry); free tier sufficient for early stage
- [ ] **Revisit if needed:** Fly.io is a viable alternative with always-on free instances and hard spending limits — evaluate if Cloud Run billing risk or cold start latency becomes a real problem for users
- [ ] Set up a GCP budget alert at $10/month to catch unexpected charges early; investigate Cloud Function billing kill-switch before going to production
- [ ] Decide on `min-instances` setting: start at 0 (free, cold starts); upgrade to 1 (~$10–15/month) when interactive CLI latency matters to paying users

### Neon (database)
- [ ] Create a Neon project and grab the connection string — free tier gives one Postgres database
- [ ] Store the connection string as a secret (not in source); inject via environment variable at runtime
- [ ] Enable Neon's connection pooling (PgBouncer) — Cloud Run spins up many short-lived instances, so direct connections would exhaust Postgres connection limits fast

### Cloud Run (app)
- [ ] Containerize the app — write a `Dockerfile` that installs dependencies and runs the web server
- [ ] Push the image to **Google Artifact Registry** (free tier covers storage for one region)
- [ ] Deploy to Cloud Run: set `min-instances=0` initially (scales to zero when idle); 256MB memory is likely sufficient for the webhook handler
- [ ] Store all secrets (Neon connection string, OAuth client secret, token encryption key) in **Google Secret Manager** and mount them as environment variables in the Cloud Run service

### Pub/Sub (push + pull subscriptions)
- [ ] Create a Pub/Sub topic; grant Gmail permission to publish (`gmail-api-push@system.gserviceaccount.com` needs `roles/pubsub.publisher`)
- [ ] Create a **push subscription** pointing to `/webhook/gmail` on the Cloud Run service; verify the domain with Google
- [ ] Create a **pull subscription** on the same topic for the scheduled fallback path
- [ ] Set message retention on the pull subscription to at least 1 hour so scheduled pulls don't miss notifications during brief outages

### Cloud Scheduler
- [ ] Watch renewal: every 6 days → `/internal/renew-watches`
- [ ] Pull fallback: configurable interval (default 5 min) → `/internal/pull`
- [ ] Poll fallback: configurable interval → `/internal/poll` (can be disabled when push is healthy)

### CI/CD
- [ ] Set up a GitHub Actions workflow: on push to `main`, build the Docker image, push to Artifact Registry, and deploy to Cloud Run (`gcloud run deploy`)

## What's Already Reusable

The Gmail API call logic and the rule engine are clean and don't need significant changes — they move into `claven/core/` as-is:
- `labeler.py` → `claven/core/rules.py` — pure logic, no changes needed
- `gmail_service.py` → `claven/core/gmail.py` — all API calls are reusable; only auth/token plumbing and file I/O need replacing
- `process_message`, `poll_new_messages`, `initial_scan` in `main.py` → `claven/core/process.py` and `claven/core/scan.py` — logic is sound; just need DB-backed state passed in instead of `data_dir`
