# How Claven Works

Claven automatically labels your Gmail inbox messages as **known-sender** or **unknown-sender** based on your Sent mail history. If you've ever emailed someone, they're a known sender. Everyone else is unknown.

This lets you focus on mail from people you know and deal with the rest on your own schedule.

## What happens when you connect

Three scans run in sequence:

### 1. Sent scan

Reads your entire Sent mail to build a list of everyone you've ever emailed. This is your known senders list. Each processed sent message is marked with a `claven/sent-scanned` label so it's not reprocessed on future runs.

The sent scan always completes before any labeling begins. This ensures the known senders list is complete before any decisions are made.

### 2. Relabel scan

Checks for messages that were previously labeled `unknown-sender` but whose sender is now known (e.g., you replied to them since the last scan). For each newly discovered known sender, finds their `unknown-sender` messages and atomically swaps the label to `known-sender`.

This fixes mislabeled messages without requiring a full rescan. Each sender is processed individually — if the scan is interrupted, remaining senders are picked up on the next run.

### 3. Label scan (inbox scan)

Goes through every unlabeled message and applies a label:
- `known-sender` if the sender is in your known senders list
- `unknown-sender` if the sender is not

The scope can be set to **Inbox** (default — only labels inbox messages) or **All mail** (labels every message in your account). The label scan only processes messages that don't already have either label.

### After the initial scans

**Live labeling** begins. New incoming mail is labeled automatically as it arrives via Gmail push notifications. If any scan fails or is interrupted, it automatically resumes on the next dashboard load.

## Labels are on messages, not threads

Gmail labels are applied to **individual messages**, not threads. A single thread (email conversation) can contain messages with different labels. For example:

- A message from someone you haven't emailed yet arrives and gets labeled `unknown-sender`
- You reply to them — they're now a known sender
- Their next message in the same thread gets labeled `known-sender`

The thread now has both labels. This is expected behavior. Gmail shows a thread in your inbox as long as any message in it has the INBOX label.

## Gmail labels managed by Claven

Claven creates and manages three Gmail labels. These are visible in your Gmail sidebar and search.

### Labels added

| Label | Added by | When | To which messages |
|---|---|---|---|
| `claven/sent-scanned` | Sent scan | After extracting recipients from a sent message | Sent messages, after their recipients are saved to the database |
| `known-sender` | Label scan | When an unlabeled message's sender is in the known senders list | Unlabeled inbox messages (or all mail, depending on scope) |
| `unknown-sender` | Label scan | When an unlabeled message's sender is NOT in the known senders list | Unlabeled inbox messages (or all mail, depending on scope) |

### Labels swapped

| From | To | By | When |
|---|---|---|---|
| `unknown-sender` | `known-sender` | Relabel scan | When a sender was previously unknown but is now in the known senders list (e.g., you replied to them). Both labels are swapped atomically in a single API call — there is no moment where the message has neither label. |

### Labels removed

| Label | Removed by | When |
|---|---|---|
| `INBOX` | Archive action | When the user clicks "Archive unknown-sender" on the dashboard. Removes the INBOX label from individual messages with the `unknown-sender` label, moving them out of the inbox. The `unknown-sender` label itself stays on the message. |

### Labels Claven never modifies

Claven does not add, remove, or modify any Gmail labels other than the three listed above and the INBOX label (via the archive action only). It does not touch UNREAD, STARRED, IMPORTANT, SPAM, TRASH, or any user-created labels.

## Inbox-only labeling

By default, Claven only labels messages that are currently in your inbox (scope = Inbox). When set to All mail, it labels every message in your account. Archived, trashed, or spam messages are not labeled in Inbox scope. If you archive a labeled message, the label stays on it but Claven won't re-label it if it returns to the inbox through a different path.

## The known senders list

Your known senders list is built from the **To**, **Cc**, and **Bcc** fields of every message in your Sent mail. If you've ever included someone on an email, they're known.

The list updates incrementally:
- When you send a new email, the recipients are added to your known senders list
- The sent scan marks processed messages with a `claven/sent-scanned` label so it doesn't reprocess them

## What "Noise reduced" means

The noise reduced percentage shows how much of your labeled mail came from unknown senders:

```
Noise reduced = unknown-sender messages / total labeled messages
```

This is based on **all messages ever labeled**, including messages that have since been archived or moved out of your inbox. It's a lifetime metric, not a snapshot of your current inbox.

## Archive unknown-sender action

The "Archive unknown-sender" action removes the INBOX label from all messages that have the `unknown-sender` label. This moves them out of your inbox without deleting them — they're still in All Mail.

Because labels are per-message (not per-thread), archiving only affects the specific messages labeled `unknown-sender`. If a thread contains both known and unknown messages, only the unknown ones are archived. The thread stays in your inbox because the known messages still have the INBOX label.

The action shows progress as it works through your messages and can be cancelled at any time. Partial progress is kept — cancelled messages stay archived, remaining messages stay in your inbox.

## Dashboard metrics

| Metric | What it measures |
|---|---|
| Allmail labeled | Total messages with known-sender or unknown-sender label (all mail, not just inbox) |
| Allmail known-sender | Messages labeled known-sender (all mail) |
| Allmail unknown-sender | Messages labeled unknown-sender (all mail) |
| Inbox unlabeled | Inbox messages without either label — these still need processing |
| Last fetched | When the system last checked for unlabeled messages |
| Last labeled | When the system last applied a label to a message |
| Newest email | Date of the newest message in your inbox |
| Newest labeled | Date of the newest message that has a label |

"Allmail" counts include archived messages because `labels.get()` counts all messages with a label regardless of location. In practice this is accurate because Claven only applies these labels to inbox messages — the counts only diverge if you archive labeled messages.

## When labels might be wrong

Labels are applied once and not automatically reconsidered. There are cases where a message could have the wrong label:

- **You email someone after their message was labeled**: Their inbox message was labeled `unknown-sender` before you replied. After you reply, they become a known sender, but the existing label isn't updated. A future relabel (removing all labels and rescanning) will fix this.

- **Multiple workers scanning simultaneously**: This was a bug that has been fixed. The sent scan now always completes before the inbox scan starts, ensuring the known senders list is complete.

If you suspect labels are wrong, you can remove all `known-sender` and `unknown-sender` labels and let the system rescan. The known senders list (from Sent mail) is preserved — only the inbox labels are reapplied.

## Best practices

### Let auto-archive do the heavy lifting

Auto-archive is on by default. It moves unknown-sender messages out of your inbox as they're labeled, so your inbox only shows mail from people you know. You don't need to manually archive — just check All Mail periodically for anything you missed.

### Process unknown-sender mail in batches

Don't check unknown-sender messages one by one as they arrive. Instead, set aside time (daily or weekly) to go through your unknown-sender messages in All Mail. You'll find:
- Newsletters and marketing you can unsubscribe from
- Legitimate contacts you should reply to (which adds them to known senders)
- Spam that Gmail's filter missed

### Reply to promote senders

The simplest way to make someone a known sender is to reply to them. Once you reply, Claven picks up the new recipient on the next sent scan and relabels their future messages as known-sender. Their existing unknown-sender messages get relabeled too.

### Use Gmail filters alongside Claven

Claven handles the known/unknown split. Gmail filters handle everything else. Good combinations:
- Gmail filter to auto-label newsletters → Claven won't touch messages that already have your labels
- Gmail filter to star messages from VIPs → stars are preserved regardless of Claven labels
- Gmail filter to skip inbox for certain senders → Claven only labels inbox messages (in default scope)

### Reset sent scan after major email changes

If you've migrated email accounts, merged mailboxes, or sent a large batch of emails, use the "Reset" button on the sent scan to rebuild your known senders list from scratch. This ensures no recipients are missed.

### Scope: Inbox vs All Mail

- **Inbox** (default): only labels messages currently in your inbox. Best for most users — fast, focused.
- **All Mail**: labels every message in your account. Use this for a one-time cleanup of your entire mailbox. Switch back to Inbox afterwards to keep scans fast.

### Use top known senders to prioritize

The "Top known senders" section shows which known senders have the most unread messages in your inbox right now. Use it to:
- Spot senders you're falling behind on — a high count means you owe them attention
- Identify senders whose volume is noise even though they're "known" (e.g., automated notifications from a service you once emailed) — consider demoting them or filtering in Gmail
- Quickly jump to the sender with the most unread by copying their email and searching in Gmail: `from:alice@example.com is:unread in:inbox`. Servicing the top sender first cuts your unread known-sender count the fastest. Processing by sender is also more efficient than processing by recency — you have the full context for that sender in your head while you work through their messages

### Check the activity log

The activity log at the bottom of the dashboard shows what Claven has been doing. If something looks wrong (repeated errors, unexpected cancellations), the log will tell you what happened. Error codes are clickable — copy them for support.
