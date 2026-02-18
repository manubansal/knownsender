# KnownSender

An intelligent Gmail labeling service that automatically categorizes incoming emails based on configurable rules.

## Features

- Monitors your Gmail inbox and applies labels based on rules defined in a YAML config
- **Known Sender Detection**: Label emails from people you've previously emailed
- **Content Matching**: Label emails where fields like `from`, `subject`, or `to` contain keywords
- **Multi-account support**: run against any number of accounts; each account's credentials and state are isolated under `accounts/<name>/`
- Efficiently polls for new messages using Gmail's history API (only processes changes, not the full inbox)
- Maintains a local cache of all addresses you've ever sent email to
- **Resumable scans**: both the inbox scan and sent recipients scan are checkpointed — interrupted scans resume exactly where they left off
- Both scans are interruptible with `Ctrl+C` and log progress every 10 messages with an accurate `i/total (pct%)` meter
- Sent recipients full scan fetches all message IDs upfront so the total is known before processing begins

## Prerequisites

- Python 3.x
- A Google Cloud project with the Gmail API enabled
- OAuth 2.0 credentials (Desktop/Installed app type) downloaded as `credentials.json` for each account

## Installation

```bash
pip install -r requirements.txt
```

## Setting Up a New Account

When you run with a new account name for the first time, the program will print setup instructions and exit. Follow these steps:

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create a project (or select an existing one)
2. Enable the **Gmail API**: APIs & Services > Enable APIs > search "Gmail API"
3. Create OAuth credentials: APIs & Services > Credentials > **Create Credentials > OAuth client ID**
   - Application type: **Desktop app**
4. Download the credentials JSON and save it to:
   ```
   accounts/<account>/credentials.json
   ```
5. Re-run the command — a browser window will open to authorize Gmail access

The OAuth token is saved as `accounts/<account>/token.json` and reused on subsequent runs.

## Usage

```bash
python main.py --account <name>
```

**Options:**

| Flag | Description |
|------|-------------|
| `--account NAME` | Account name to run as; state is stored under `accounts/<name>/` (required) |
| `--max-messages N` | Limit the initial inbox scan to N messages (useful for large inboxes or testing) |

**Example:**
```bash
python main.py --account personal
python main.py --account work --max-messages 500
```

The service polls continuously (default: every 60 seconds) and shuts down gracefully on `Ctrl+C` or `SIGTERM`.

Both the initial inbox scan and the sent recipients scan log progress every 10 messages and can be interrupted with `Ctrl+C` at any time — the checkpoint is saved and the next run resumes from where it left off.

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
| `accounts/<name>/credentials.json` | OAuth credentials for the account (not committed) |
| `accounts/<name>/token.json` | OAuth token for the account (not committed) |
| `accounts/<name>/sent_recipients_cache.json` | Local cache of sent addresses (not committed) |
| `accounts/<name>/scan_checkpoint.json` | Tracks processed message IDs for scan resumption (not committed) |
