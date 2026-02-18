# KnownSender

An intelligent Gmail labeling service that automatically categorizes incoming emails based on configurable rules.

## Features

- Monitors your Gmail inbox and applies labels based on rules defined in a YAML config
- **Known Sender Detection**: Label emails from people you've previously emailed
- **Content Matching**: Label emails where fields like `from`, `subject`, or `to` contain keywords
- Efficiently polls for new messages using Gmail's history API (only processes changes, not the full inbox)
- Maintains a local cache of all addresses you've ever sent email to
- **Resumable initial scan**: progress is checkpointed so interrupted scans pick up where they left off
- Logs scan progress at every 10% and gracefully handles `Ctrl+C` mid-scan
- Logs progress during the sent recipients scan (per page for full scans, per 10% for incremental updates); scan is interruptible with `Ctrl+C` and resumes from the exact page where it left off on the next run

## Prerequisites

- Python 3.x
- A Google Cloud project with the Gmail API enabled
- OAuth 2.0 credentials (Desktop/Installed app type) downloaded as `credentials.json`

## Installation

```bash
pip install -r requirements.txt
```

## Google Cloud Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create a project
2. Enable the **Gmail API**
3. Create an **OAuth 2.0 Client ID** (type: Desktop app)
4. Download the credentials JSON and save it as `credentials.json` in the project root

On first run, a browser window will open to authorize Gmail access. The token is saved as `token.json` for subsequent runs.

## Usage

```bash
python main.py
```

**Options:**

| Flag | Description |
|------|-------------|
| `--max-messages N` | Limit the initial inbox scan to N messages (useful for large inboxes or testing) |

**Example:**
```bash
python main.py --max-messages 500
```

The service polls continuously (default: every 60 seconds) and shuts down gracefully on `Ctrl+C` or `SIGTERM`.

The initial scan logs progress every 10% and can be interrupted with `Ctrl+C` at any time — the checkpoint is saved and the next run will resume from where it left off.

## Configuration

Edit `config.yaml` to define your polling interval and labeling rules:

```yaml
polling_interval_seconds: 60

labels:
  - name: "Known"
    rules:
      - field: "from"
        known_sender: true

  - name: "Newsletter"
    rules:
      - field: "subject"
        contains: ["newsletter", "unsubscribe", "weekly digest"]
```

### Rule Types

- **`known_sender: true`** — matches if the sender is in your sent recipients cache
- **`contains: [...]`** — matches if any keyword appears in the specified field (`from`, `subject`, `to`)

Multiple rules per label use **OR** logic — any matching rule will apply the label.

## Files

| File | Description |
|------|-------------|
| `main.py` | Entry point; argument parsing and polling loop |
| `gmail_service.py` | Gmail API integration; auth, fetching, labeling, caching |
| `labeler.py` | Rule evaluation engine |
| `config.yaml` | Polling interval and label rule definitions |
| `credentials.json` | OAuth credentials (not committed) |
| `token.json` | OAuth token (not committed) |
| `sent_recipients_cache.json` | Local cache of sent addresses (not committed) |
| `scan_checkpoint.json` | Tracks processed message IDs for scan resumption (not committed) |
