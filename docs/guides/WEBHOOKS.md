# Signed Outbound Webhooks

Your node can POST an event to your own systems (ERP, PLM, a no-code automation)
every time a passport changes — created, updated, published, suspended, archived,
deactivated, or transferred. Deliveries are **signed** so your receiver can prove
the request really came from your node.

---

## Managing subscriptions

Via the CLI:

```sh
# Subscribe to everything (the default when --events is omitted)
odal webhook add https://hooks.example.com/odal

# Subscribe to specific events only
odal webhook add https://hooks.example.com/odal \
  --events dpp.passport.published,dpp.passport.transferred

odal webhook list
odal webhook test <id>     # send a synthetic dpp.webhook.test delivery
odal webhook remove <id>   # stop delivering (existing queued deliveries still drain)
```

Or via the API (`Bearer` admin credential required):

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/vault/api/v1/webhooks` | List subscriptions (secret redacted) |
| `POST` | `/vault/api/v1/webhooks` | Create — **the signing secret is returned once** |
| `DELETE` | `/vault/api/v1/webhooks/{id}` | Soft-remove (`active=false`) |
| `POST` | `/vault/api/v1/webhooks/{id}/test` | Enqueue a test delivery |

The signing secret is shown **only** in the create response. Store it now; it
cannot be recovered later.

### Event subjects

`dpp.passport.created`, `dpp.passport.updated`, `dpp.passport.published`,
`dpp.passport.suspended`, `dpp.passport.archived`, `dpp.passport.deactivated`,
`dpp.passport.transferred`, and `dpp.webhook.test`. Use `*` to receive all.

---

## The request your receiver sees

`POST` with a JSON body (the event envelope) and these headers:

| Header | Meaning |
|---|---|
| `X-Odal-Signature` | `t=<unix-seconds>,v1=<hex>` — see verification below |
| `X-Odal-Delivery`  | Unique delivery id — **use it to de-duplicate** (see semantics) |
| `X-Odal-Event`     | The event type, e.g. `dpp.passport.published` |
| `Content-Type`     | `application/json` |

Body:

```json
{
  "version": 1,
  "eventId": "0198f...",
  "eventType": "dpp.passport.published",
  "timestamp": "2026-07-11T10:30:00Z",
  "operatorId": "self_hosted",
  "data": { "passportId": "…", "status": "active", "qrCodeUrl": "…" }
}
```

---

## Verifying the signature

The signature is `HMAC-SHA256(secret, "{timestamp}.{raw_body}")`, hex-encoded, in
the `v1=` field of `X-Odal-Signature`. **Sign the raw request bytes** — do not
re-serialize the parsed JSON. Reject deliveries whose `t` is too old (a few
minutes) to blunt replay, and compare using a constant-time function.

### Node.js

```js
const crypto = require("crypto");

function verify(secret, header, rawBody, toleranceSec = 300) {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=")));
  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${parts.t}.${rawBody}`)
    .digest("hex");
  const ok = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1));
  const fresh = Math.abs(Date.now() / 1000 - Number(parts.t)) < toleranceSec;
  return ok && fresh;
}
// Express: use express.raw({ type: "application/json" }) so req.body is the raw bytes.
```

### Python

```python
import hashlib, hmac, time

def verify(secret: str, header: str, raw_body: bytes, tolerance=300) -> bool:
    parts = dict(kv.split("=", 1) for kv in header.split(","))
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + raw_body,
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts["v1"]):
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
    ts, _ := strconv.ParseInt(parts["t"], 10, 64)
    return time.Since(time.Unix(ts, 0)).Abs() < tolerance
}
```

---

## Delivery semantics

- **At-least-once.** On a crash between your `2xx` and the node recording success,
  a delivery may repeat. **De-duplicate on `X-Odal-Delivery`** — the id is stable
  across retries of the same delivery.
- **Retries with backoff.** Any non-`2xx` response (or a connection error) is
  retried with exponential backoff and jitter, up to a fixed attempt cap, after
  which the delivery is marked `exhausted` and stops. Return `2xx` promptly
  (ideally after enqueuing the work, not after processing it).
- **Order is not guaranteed.** Backoff can reorder deliveries; use the event
  `timestamp` if ordering matters.
- **Removing a subscription** stops new deliveries; already-queued ones still drain.

## Security notes

- Receiver URLs must be **https** and resolve to a **public** address. A
  self-hosted node delivering to its own internal network can opt out with
  `WEBHOOK_ALLOW_PRIVATE_TARGETS=true` (this also permits plain http) — never set
  this on a node reachable from untrusted networks.
- The signing secret is stored by the node so it can sign every delivery.
  Encrypt your database at rest.
