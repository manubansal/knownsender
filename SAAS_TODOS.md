# SaaS Migration Todos

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
- [ ] Keep `polling_interval_seconds` configurable per user or as a server-wide setting

## Background Workers

- [ ] Switch from polling to **Gmail push notifications** (Pub/Sub `watch` API) — Gmail calls your Cloud Run endpoint when new mail arrives; eliminates the need for a persistent polling worker entirely
- [ ] On user connect, call `gmail.users.watch()` to register a Pub/Sub subscription for their inbox; store the returned `historyId` in the DB
- [ ] `watch` subscriptions expire after 7 days — set up a Cloud Scheduler job to renew all active subscriptions before expiry
- [ ] Handle the Pub/Sub webhook: decode the notification, look up the user, fetch history since stored `historyId`, process new messages
- [ ] The long-running initial scan and sent recipients scan still need to run once per new user — trigger as a Cloud Run job (one-off container execution) on signup so it doesn't block the webhook handler

## Web Server

- [ ] Add a web framework (FastAPI, Flask, Django — pick one) to serve:
  - OAuth start/callback endpoints
  - User dashboard (connected accounts, label rules, status)
  - Webhook endpoint if using Gmail push notifications
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

### Pub/Sub (Gmail push)
- [ ] Create a Pub/Sub topic and subscription in GCP; grant Gmail permission to publish to the topic (`gmail-api-push@system.gserviceaccount.com` needs `roles/pubsub.publisher`)
- [ ] Configure the Pub/Sub subscription as a **push subscription** pointing to your Cloud Run webhook URL (e.g. `/webhook/gmail`)
- [ ] Verify the webhook endpoint with Google (Pub/Sub push requires a verified domain)

### Cloud Scheduler (watch renewal)
- [ ] Create a Cloud Scheduler job that runs every 6 days, hits a `/internal/renew-watches` endpoint on Cloud Run, which calls `gmail.users.watch()` for all active users

### CI/CD
- [ ] Set up a GitHub Actions workflow: on push to `main`, build the Docker image, push to Artifact Registry, and deploy to Cloud Run (`gcloud run deploy`)

## What's Already Reusable

The Gmail API call logic and the rule engine are clean and don't need significant changes:
- `labeler.py` — pure logic, no changes needed
- `gmail_service.py` — all the API calls (`list_messages`, `list_history`, `get_message_headers`, `apply_label`, etc.) are reusable; just the auth/token plumbing and file I/O need replacing
- `process_message`, `poll_new_messages`, `initial_scan` — the logic is sound; they just need DB-backed state passed in instead of `data_dir`
