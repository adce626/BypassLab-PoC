# Subscription Model Testing Checklist — Practical, Professional, PoC‑ready

**Scope & warning:** for authorized testing only (CTF / staging / pentest under scope). This is a tactical, no‑fluff checklist covering common mistakes in subscription systems: enforcement gaps, billing logic, trial abuse, webhook weaknesses, info leakage, rate abuse, and practical PoCs you can run in Burp/curl. For each section: what to test → why it matters → quick PoC / observables → mitigation.

## Quick priorities (where to start)
- Authentication & plan enforcement (is access checked server‑side?)
- Billing & price integrity (is client data trusted?)
- Webhook validation (are providers verified?)
- Trial and plan bypasses (trial reuse, cookies, metadata tampering)
- Business logic and ID enumeration (predictable invoice/order IDs)
- Info exposure (guessable invoice URLs, client JS leaks)
- Rate limits & abuse (trial creation, discount brute force)

**Triage:** run a baseline user with free vs paid accounts; record requests/responses and compare behavior.

---

## 1 — Authentication & Plan Enforcement

**What to test**  
- Can free users call paid endpoints directly (API URLs) and receive paid content?  
- Is access control enforced only in the frontend (JS checks) but not server‑side?  
- Can hidden/form fields or localStorage/sessionStorage be manipulated to elevate plan?  
- Are plan/view flags modifiable in requests (e.g., `plan: "premium"` in JSON)?

**Why it matters**  
If enforcement is client‑side only, any user can flip a flag and get premium features without paying.

**PoC / Examples**  
```bash
# change JSON body to claim premium
curl -X POST https://app.example/api/feature -H "Authorization: Bearer <token>"   -H "Content-Type: application/json" -d '{"resourceId":123, "plan":"premium"}'
```

**Observables**  
Server returns premium data (200) while user is free; content identical to paid user.

**Mitigation**  
Enforce plan checks server‑side for every protected endpoint; read plan from DB/session only.

---

## 2 — Billing Logic (amount integrity & price overrides)

**What to test**  
- Can the client submit arbitrary amount or price fields?  
- Does server recalculate total from `productId` or trust client?  
- Test rounding, floating precision, negative/zero values, string vs number types.  
- Hidden fields: price or discount sent as hidden inputs in checkout pages.

**Why it matters**  
Attacker paying less, getting credit, or bypassing payment.

**PoC / Examples**  
```bash
curl -X POST https://app.example/checkout -H "Authorization: Bearer <token>"  -H "Content-Type: application/json"  -d '{"productId":123,"amount":1,"currency":"USD"}'
# Duplicate param trick:
# POST /checkout?amount=999 with body amount=1
# Precision exploit: -d '{"amount":403.0000001}'
```

**Observables**  
Order created with lower amount; invoice shows wrong total; order fulfilled.

**Mitigation**  
Server computes final price from product catalog; use integer minor units; reconcile provider amount before fulfillment.

---

## 3 — Trial & Plan Bypass

**What to test**  
- Can trial be reactivated with new emails or temp inboxes repeatedly?  
- Can cookies, localStorage, or plan metadata be tampered to re-enable trial?  
- Can user retain premium features after cancellation or downgrade?

**Why it matters**  
Unlimited free trials or persistent premium access costs revenue.

**PoC / Examples**  
```js
// In browser console
localStorage.setItem('user_plan', 'premium')
# Automate signups with temp-mail to trigger trial reuse
```

**Observables**  
Feature access persists after plan change; trial re‑trigger works repeatedly.

**Mitigation**  
Server stores trial start timestamp and enforces eligibility server‑side; revoke access on cancelation server‑side.

---

## 4 — Business Logic Flaws (IDs, references, admin flags)

**What to test**  
- Predictable IDs: `/invoices/1234.pdf` — can you enumerate?  
- Can you cancel/change plans by ID manipulation?  
- Can you view other users’ billing info by guessing invoice IDs?

**PoC / Examples**  
```bash
curl -I https://app.example/invoices/1000.pdf
curl -I https://app.example/invoices/1001.pdf
```

**Observables**  
Invoices returned without auth; subscription updated by ID-based calls.

**Mitigation**  
Authorize access strictly; use UUIDs/unguessable tokens; ACL checks; avoid exposing admin functions.

---

## 5 — Webhook & Payment Integration (Stripe/PayPal)

**What to test**  
- Can you spoof/replay webhook events to mark subscription as paid?  
- Are webhook signatures and timestamps validated?

**PoC / Examples**  
```bash
curl -X POST https://app.example/webhook/stripe -H "Content-Type: application/json"   -d '{"type":"invoice.payment_succeeded","data":{"object":{"id":"ch_1","amount_paid":100}}}'
```

**Observables**  
Account becomes active; webhook logs show unverified requests processed.

**Mitigation**  
Verify webhook signatures, timestamps; reconcile with provider API before marking paid.

---

## 6 — Insecure Storage & Info Disclosure

**What to test**  
- Are invoices, receipts, or pricing config exposed via unauthenticated endpoints or guessable URLs?  
- Is pricing config shipped in frontend JS?

**PoC / Examples**  
```bash
GET https://app.example/uploads/invoices/2024/INV-0001.pdf
# Search frontend for window.__PRICE_CONFIG__ or inline JSON
```

**Mitigation**  
Require auth for invoice access; use signed expiring download tokens; keep pricing server‑side.

---

## 7 — Rate Limiting, Abuse & Enumeration

**What to test**  
- Can attackers create many trials quickly? Brute force discount codes?  
- Are API limits on paid features enforced?

**PoC / Examples**  
Automate signups with temp-mail API; brute coupon endpoint with wordlist.

**Mitigation**  
Rate limit critical endpoints; CAPTCHAs on signup; anti-bot measures.

---

## 8 — Tools & Techniques

- Burp Suite (Intruder/Repeater), ZAP, Postman.  
- DevTools: inspect localStorage, hidden fields.  
- Temp-mail and webhook tools: RequestBin, ngrok, Stripe CLI.  
- Scripting: Python `requests`, concurrency for race tests.

---

## 9 — Race Conditions & Concurrency Tests

**What to test**  
- Concurrent requests to change plans, cancel/upgrade, or same idempotencyKey with different amounts.

**PoC sketch** (Python threading):
```python
import requests, threading
url = "https://app.example/subscribe"
p1 = {"user":1,"plan":"free"}
p2 = {"user":1,"plan":"premium"}
def send(p): print(requests.post(url,json=p).status_code)
t1 = threading.Thread(target=send,args=(p1,))
t2 = threading.Thread(target=send,args=(p2,))
t1.start(); t2.start(); t1.join(); t2.join()
```

**Mitigation**  
Use DB transactions/locks; canonicalize on first request; validate idempotency server‑side.

---

## 10 — Reporting Template (what to include)

- Title / summary, environment, account IDs, timestamps.  
- Steps to reproduce: exact raw requests (headers + body).  
- Observables: response body, status code, screenshots, provider evidence.  
- PoC: minimal payload.  
- Impact and fix recommendation.

---

## 11 — Quick mitigations checklist

- Server‑side plan enforcement for every protected resource.  
- Server computes price; never trust client price/hidden fields.  
- Verify webhook signatures and reconcile with provider.  
- Unpredictable IDs + ACL checks for invoices/orders.  
- Limit trials per identity/device/IP; require verification.  
- Rate limiting & anti‑automation on signup/discount endpoints.  
- Signed, expiring download tokens for invoices.  

---

## Final practical checklist (one‑page actions)

- Intercept upgrade/protected requests — toggle plan flag.  
- Tamper checkout amount, currency, productId — observe reaction.  
- Replay or forge webhooks — check signature enforcement.  
- Attempt trial replays with temp emails & localStorage tamper.  
- Enumerate invoice/order IDs and check auth enforcement.  
- Brute coupon endpoint with rate limits.  
- Run concurrent cancel/upgrade for race conditions.  
- Search frontend assets for pricing/config leaks.
