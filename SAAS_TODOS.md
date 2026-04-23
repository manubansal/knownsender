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

### Secrets and config

All secrets (Neon connection string, OAuth client secret, token encryption key) are stored in Google Secret Manager and mounted as environment variables. Nothing sensitive is baked into the container image.

---

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
- [ ] Implement shared JSON error handler that catches exceptions, writes to stderr, and exits with code 2
- [ ] Implement `auth login`, `auth logout`, `auth status`
- [ ] Implement `scan` with progress streaming and resumable checkpoint via Neon
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

### Neon (database)
- [ ] Create a Neon project and grab the connection string — free tier gives one Postgres database
- [ ] Store the connection string as a secret (not in source); inject via environment variable at runtime
- [ ] Enable Neon's connection pooling (PgBouncer) — Cloud Run spins up many short-lived instances, so direct connections would exhaust Postgres connection limits fast

### Cloud Run (app)
- [ ] Containerize the app — write a `Dockerfile` that installs dependencies and runs the web server
- [ ] Push the image to **Google Artifact Registry** (free tier covers storage for one region)
- [ ] Deploy to Cloud Run: set min instances to 0 (scales to zero when idle), configure memory/CPU for the webhook handler (256MB is likely enough)
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

The Gmail API call logic and the rule engine are clean and don't need significant changes:
- `labeler.py` — pure logic, no changes needed
- `gmail_service.py` — all the API calls (`list_messages`, `list_history`, `get_message_headers`, `apply_label`, etc.) are reusable; just the auth/token plumbing and file I/O need replacing
- `process_message`, `poll_new_messages`, `initial_scan` — the logic is sound; they just need DB-backed state passed in instead of `data_dir`
