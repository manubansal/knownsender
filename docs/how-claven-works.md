# How Claven Works

Claven automatically labels your Gmail inbox messages as **known-sender** or **unknown-sender** based on your Sent mail history. If you've ever emailed someone, they're a known sender. Everyone else is unknown.

This lets you focus on mail from people you know and deal with the rest on your own schedule.

## What happens when you connect

1. **Sent scan** runs first. Claven reads your entire Sent mail to build a list of everyone you've ever emailed. This is your known senders list.

2. **Inbox scan** runs after the sent scan completes. Claven goes through every message in your inbox and applies a label:
   - `known-sender` if the sender is in your known senders list
   - `unknown-sender` if the sender is not

3. **Live labeling** begins. New incoming mail is labeled automatically as it arrives via Gmail push notifications.

The sent scan always finishes before the inbox scan starts. This ensures no one gets mislabeled because the known senders list was incomplete.

## Labels are on messages, not threads

Gmail labels are applied to **individual messages**, not threads. A single thread (email conversation) can contain messages with different labels. For example:

- A message from someone you haven't emailed yet arrives and gets labeled `unknown-sender`
- You reply to them — they're now a known sender
- Their next message in the same thread gets labeled `known-sender`

The thread now has both labels. This is expected behavior. Gmail shows a thread in your inbox as long as any message in it has the INBOX label.

## Inbox-only labeling

Claven only labels messages that are currently in your inbox. Archived, trashed, or spam messages are not labeled, even if they match a rule. If you archive a labeled message, the label stays on it but Claven won't re-label it if it returns to the inbox through a different path.

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
