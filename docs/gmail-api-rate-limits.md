# Gmail API Rate Limits

Reference: [Usage limits | Gmail API](https://developers.google.com/workspace/gmail/api/reference/quota)

## Quota system

The Gmail API uses **quota units** per method call. The per-user limit is **6,000 quota units per minute per project**.

## Quota cost per operation

| Operation | Units | Notes |
|---|---|---|
| `messages.list` | 5 | Used for finding unlabeled messages |
| `messages.get` | 20 | Used for fetching headers |
| `messages.modify` | 5 | Used for applying/removing labels |
| `messages.batchModify` | 50 | Batch label operations |
| `labels.get` | 1 | Used for exact label counts |
| `labels.list` | 1 | Used for label ID lookup |
| `users.getProfile` | 5 | Used for all-mail count |

## Our scan loop budget

Per batch of 50 messages:
- 1 `messages.list` = 5 units
- 50 `messages.get` (header fetch) = 1,000 units
- 50 `messages.modify` (label apply) = 250 units
- **Total: ~1,255 units per batch**

At 6,000 units/minute: **~4.7 batches per minute** before hitting the limit.

With 1-second sleep between batches, we run ~4-5 batches per minute — right at the quota boundary. The existing exponential backoff retry handles 429 errors when we exceed.

## Batch HTTP requests

Gmail's batch API allows up to **100 individual requests per batch HTTP call**. This reduces HTTP overhead but doesn't change quota unit consumption — each individual request in the batch still costs its normal quota units.

Our `_BATCH_LIMIT` controls how many requests we bundle into one HTTP call. Setting it to 50 (matching `_BATCH_SIZE`) means one HTTP call per batch instead of 10 calls of 5.

## Rate limit error handling

When quota is exceeded, Gmail returns HTTP 429. Our retry logic:
- `batch_get_message_metadata`: retries failed messages with 5s → 10s → 20s backoff
- `batch_apply_labels`: same retry pattern
- `batch_swap_labels`: same retry pattern

A 429 error is not data loss — the request simply isn't processed. Retrying after the 60-second quota window resets succeeds.

## Concurrent request limit

Gmail also enforces a per-user concurrent request limit (separate from the per-minute rate limit). This is shared across all API clients accessing the same user. Multiple parallel requests to the same user can trigger 429 even within the per-minute quota.

Our batch API calls are sequential (one batch at a time per user), so concurrent limits are not a concern.

## Configuration

| Setting | Value | Rationale |
|---|---|---|
| `_BATCH_SIZE` | 50 | Messages processed per logical batch |
| `_BATCH_LIMIT` | 50 | Requests per HTTP batch call (matches BATCH_SIZE) |
| `_SAMPLE_POOL_MULTIPLIER` | 5 | Fetch 250 candidates, sample 50 (desynchronizes workers) |
| Inter-batch sleep | 1 second | Paces batches to stay under quota |
