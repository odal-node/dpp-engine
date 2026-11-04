# Signed webhooks

The node can POST each passport event to your own systems (ERP, PLM, an automation
tool). Every delivery is signed with HMAC-SHA256, so the receiver can check that it
came from your node and was not modified.

## Subscribe

```bash
odal webhook add https://hooks.example.com/odal                     # every event
odal webhook add https://hooks.example.com/odal \
  --events dpp.passport.published,dpp.passport.transferred          # selected events
```

The response contains the signing secret (`whsec_…`). It is shown once and cannot be
retrieved later; store it with the receiver.

```bash
odal webhook list
odal webhook test <id>      # queue a signed dpp.webhook.test delivery
odal webhook remove <id>    # stop new deliveries; queued ones still go out
```

The same operations over the API need an `admin` key:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/vault/api/v1/webhooks` | List subscriptions (secrets redacted) |
| `POST` | `/vault/api/v1/webhooks` | Create a subscription; returns the secret once |
| `DELETE` | `/vault/api/v1/webhooks/{id}` | Deactivate a subscription |
| `POST` | `/vault/api/v1/webhooks/{id}/test` | Queue a test delivery |

### Events

A subscription receives the events in its filter, or every event when the filter is
`*` (the default). The subjects are listed in
[EVENT-BUS.md](../architecture/EVENT-BUS.md#subjects): `dpp.passport.created`,
`updated`, `published`, `suspended`, `superseded`, `retired`, `deactivated` and
`transferred`; `dpp.import.completed` and `dpp.import.failed`; plus `dpp.webhook.test`
for test deliveries.

## What the receiver gets

A `POST` with the event envelope as the body:

| Header | Value |
|---|---|
| `X-Odal-Signature` | `t=<unix-seconds>,v1=<hex HMAC>` |
| `X-Odal-Delivery` | Delivery id, stable across retries. De-duplicate on it |
| `X-Odal-Event` | The subject, for example `dpp.passport.published` |
| `Content-Type` | `application/json` |

```json
{
  "version": 1,
  "eventId": "0198f2c4-5a1b-7e3d-8c2f-1a9b3c5d7e0f",
  "eventType": "dpp.passport.published",
  "timestamp": "2026-07-11T10:30:00Z",
  "operatorId": "self_hosted",
  "data": { "passportId": "…", "status": "active", "qrCodeUrl": "…" }
}
```

## Verify the signature

`v1` is the hex HMAC-SHA256 of `"{t}.{raw body}"` under the subscription secret.
Compute it over the raw request bytes, not re-serialised JSON. Compare in constant
time, and reject a `t` older than a few minutes to limit replay.

### Node.js

```js
const crypto = require("crypto");

function verify(secret, header, rawBody, toleranceSec = 300) {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=")));
  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${parts.t}.${rawBody}`)
    .digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(parts.v1 ?? "");
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  const fresh = Math.abs(Date.now() / 1000 - Number(parts.t)) < toleranceSec;
  return ok && fresh;
}
// With Express, use express.raw({ type: "application/json" }) so req.body holds the raw bytes.
```

### Python

```python
import hashlib, hmac, time

def verify(secret: str, header: str, raw_body: bytes, tolerance: int = 300) -> bool:
    parts = dict(kv.split("=", 1) for kv in header.split(","))
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + raw_body,
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts.get("v1", "")):
        return False
    return abs(time.time() - int(parts["t"])) < tolerance
```

### Go

```go
func Verify(secret, header string, rawBody []byte, tolerance time.Duration) bool {
    parts := map[string]string{}
    for _, kv := range strings.Split(header, ",") {
        if k, v, ok := strings.Cut(kv, "="); ok {
            parts[k] = v
        }
    }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(parts["t"] + "."))
    mac.Write(rawBody)
    expected := hex.EncodeToString(mac.Sum(nil))
    if !hmac.Equal([]byte(expected), []byte(parts["v1"])) {
        return false
    }
    ts, err := strconv.ParseInt(parts["t"], 10, 64)
    if err != nil {
        return false
    }
    return time.Since(time.Unix(ts, 0)).Abs() < tolerance
}
```

## Delivery behaviour

| Behaviour | Detail |
|---|---|
| Queueing | Deliveries are queued right after the passport change commits. If the node stops between the commit and the queueing, that event's deliveries are not sent |
| Retries | Any non-`2xx` answer or connection error is retried with exponential backoff (2, 4, 8 … seconds, capped at one hour, with ±25% jitter) |
| Attempt limit | 8 attempts, after which the delivery is marked `exhausted` |
| Duplicates | Possible, for example when the node stops after your `2xx` but before recording it. De-duplicate on `X-Odal-Delivery` |
| Order | Not guaranteed; retries reorder. Use the envelope's `timestamp` |
| Redirects | Not followed. A `3xx` counts as a failed attempt, because the redirect target was never checked. Subscribe the final URL |

Answer `2xx` as soon as the delivery is stored on your side, and process it
afterwards.

## Security

- Receiver URLs must use `https` and resolve to a public address. The host is
  re-resolved at every delivery and the connection is pinned to the approved
  addresses, so a name that later points at an internal address (including through
  DNS rebinding) is refused.
- `WEBHOOK_ALLOW_PRIVATE_TARGETS=true` allows private addresses and plain `http`, for
  a self-hosted node delivering inside its own network. Do not set it on a node that
  untrusted users can configure.
- The node stores the signing secrets in order to sign deliveries. Encrypt the
  database and its backups at rest.
