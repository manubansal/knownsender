# Claven

Claven is a Gmail labeling service. It applies user-defined label rules to incoming email, using Gmail's History API for incremental processing and a known-senders cache (built from Sent mail) to distinguish first-time senders.

It is being migrated from a local script to a stateless SaaS service. See `SAAS_TODOS.md` for the full plan.

## Current state of the codebase

The code is still in its pre-migration, flat-script form:

- `main.py` — entry point and business logic (mixed together, to be separated)
- `gmail_service.py` — Gmail API calls and file-based state
- `labeler.py` — label rule matching
- `config.yaml` — label rules (per-user rules will move to the DB)

The target structure is a `claven/` package — see `SAAS_TODOS.md` "Code restructure" section. **Do not add new features to the flat scripts.** New work goes into the `claven/` package shape.

## Architectural constraints

These apply to all code in this repo. Violating them undermines the SaaS architecture.

**1. No logic in entry points.**
`cli.py`, `server.py`, and `job.py` are thin wrappers. They parse input (CLI args, HTTP requests, env vars), call `claven/core/`, and format output. Business logic — anything that touches Gmail, the database, or label rules — belongs in `claven/core/`.

**2. The CLI is a thin HTTP client. It never imports core directly.**
`cli.py` makes HTTP requests to `$CLAVEN_SERVER_URL`. It does not call `claven/core/` functions. For local development, `CLAVEN_SERVER_URL` points at a local `server.py` instance. This keeps core logic in one place and eliminates version drift.

**3. All state lives in Neon. No file I/O for application state.**
The `accounts/` directory and `*.json` checkpoint files are the pre-migration approach. In the new architecture, all reads and writes go through `claven/core/db.py`. Do not add new file-based state.

**4. Operations must be idempotent.**
Push, pull, and poll modes can process the same user concurrently. Label application must check before applying. `historyId` updates must use optimistic or pessimistic locking at the DB level (`SELECT ... FOR UPDATE SKIP LOCKED`).

**5. No secrets in code or config files.**
Secrets (OAuth client secret, Neon connection string, token encryption key) are injected via environment variables at runtime. Do not hardcode or commit credentials.

## Development approach

This project follows test-driven development. **Tests are written before implementation.** Do not write implementation code for a feature or module without a corresponding test written first. The test plan lives in `tests/README.md`.

## Active branch

`saas` is the active development branch. `main` is protected — PRs only, no direct pushes.

## Git workflow

Before opening any PR, rebase the branch onto its base branch:

```
git fetch origin && git rebase origin/main && git push origin <branch> --force-with-lease
```

## Key decisions

- **Serverless platform:** Cloud Run (`min-instances=0` to start; upgrade to 1 when interactive CLI latency matters)
- **Database:** Neon free plan Postgres with PgBouncer connection pooling
- **Notification modes:** push (Pub/Sub, primary), pull (Pub/Sub pull subscription, fallback), poll (Gmail History API, local dev fallback)
- **Initial scan vs. incremental processing:** the one-time scan uses `list_messages`; all incremental processing uses `list_history` since a stored `historyId` — these are distinct code paths, never conflated
