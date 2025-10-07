# Account Takeover via Password Reset — Email Payloads & Practical Test Plan — OmniWatch (adce626)

**Scope & warning:** practical playbook for abusing password‑reset flows via email payloads and parser edge cases. For authorized security testing, red‑team, or CTF environments only. Do not test production systems without explicit permission. Log everything.

## Objective

Find weaknesses in password‑reset flows that allow an attacker to cause a reset token or link to be issued to an attacker‑controlled mailbox or to otherwise reset a victim’s password and take over the account.

**Success (CTF):** obtain a valid reset token/link for the target account and use it to set a new password and log in.

## Threat model & assumptions

- Attacker can send HTTP(S) requests to the target reset endpoint.
- Attacker controls at least one mailbox or domain (catch‑all preferred).
- Target environment may have parser, canonicalization, template, or routing inconsistencies.
- Tests must be performed in staging / lab or with explicit authorization.

## Tools & test environment

- Burp Suite (Repeater/Intruder), curl, wfuzz/ffuf.
- Python (requests), concurrency for race tests.
- A catch‑all mailbox (or controlled mail server) to receive test emails.
- Logging: capture raw requests, raw responses, and incoming email headers/bodies.

## Testing methodology (practical)

- **Baseline:** perform a legitimate reset for a known test account. Capture request/response, outgoing email (headers + body), link/token format, and token lifetime.
- **Low‑risk phase:** test whitespace, case, alternate fields, common encodings. Observe responses.
- **Escalation phase (staging only):** test null bytes, control chars, double‑encoding, XML entities, large payloads, and race conditions.
- **Reproduce minimal PoC:** when you find a positive result, strip the payload to the smallest form that reproduces it; this isolates root cause.
- **Document everything:** raw requests, timestamps, mail headers, screenshots of successful login or token use.

## What to look for (observable success indicators)

- HTTP status changing from 4xx/403 → 200 for manipulated payloads.
- Outgoing reset e‑mail delivered to an attacker‑controlled address.
- Reset link or token present in the email body for an attacker recipient.
- Changes in Content‑Length, Location header, Set‑Cookie, or other headers.
- Template errors, stack traces, or unusual latency that reveal internal behavior.

## Detailed test cases — 20 focused categories

Each category contains: what to test, why it matters, practical payloads/examples, what to observe, and mitigation notes.

### 1) Empty / omitted fields

**What:** Submit reset requests with the email field missing, empty, or null (form & JSON).  
**Why:** Some flows treat missing fields as wildcards or fallback to default addresses (admin, support) or perform different lookup logic.  
**Examples:** JSON: `{}`, `{"email":""}`, `{"email":null}`. Form: omit `email=` or send `email=` empty.  
**Observe:** `200` with success message; reset email to fallback/admin/catch‑all; logs showing default selection.  
**Mitigation:** Require non‑empty validated email; return clear `4xx` for missing data; rate‑limit.

### 2) Whitespace simulation

**What:** Prefix/suffix spaces, tabs, or newlines in the email field.  
**Why:** Inconsistent trimming across layers can cause the lookup and notification layers to disagree. Templates may be corrupted (header bleed).  
**Examples:** `{"email":" victim@example.com"}`, `email=victim@example.com%20`, `{"email":"victim@example.com
"}`.  
**Observe:** Successful reset only for whitespace variant; header injection; email delivered to attacker mailbox.  
**Mitigation:** Trim and canonicalize inputs before validation and before template inclusion; escape template values.

### 3) Duplicate parser / parameter pollution

**What:** Send the same parameter in multiple places (query string + JSON body) or duplicate keys in multipart/form-data.  
**Why:** Different parsers may pick first/last occurrence; auth and notification paths may read different sources.  
**Examples:** `POST /reset?email=attacker@b.com` with body `{"email":"victim@a.com"}`; multipart: part1 `email=victim@a.com`, part2 `payload={"email":"attacker@b.com"}`.  
**Observe:** Reset email delivered to attacker address only when duplicates exist; inconsistent responses.  
**Mitigation:** Establish strict parameter precedence; reject conflicting parameters; log duplicates.

### 4) Form‑encoded specifics

**What:** Test `application/x-www-form-urlencoded` nested keys and JSON-as-string in form fields.  
**Why:** Legacy parsers or frameworks might bind form fields directly to ORM models enabling mass‑assignment or alternate code paths.  
**Examples:** `user[email]=victim@example.com`, `payload={"email":"attacker@b.com"}` (as form value).  
**Observe:** Reset accepted only for form variants; emails to unexpected recipients.  
**Mitigation:** Separate parsing and binding; validate field shapes; avoid direct mass‑assignment.

### 5) Plus (+) tag / subaddressing

**What:** Use plus addressing: `victim+tag@example.com`.  
**Why:** Mail servers may canonicalize/strip `+tag` while the app matches exact stored address; catch‑all domains allow attackers to receive mails for victim+tag.  
**Examples:** `{"email":"victim+reset@domain.com"}`.  
**Observe:** Reset email received by catch‑all attacker mailbox.  
**Mitigation:** Require exact match to verified account email for resets.

### 6) Case variation / Unicode homoglyphs

**What:** Try different casing and replace characters with lookalike unicode glyphs (Cyrillic, Greek, etc.).  
**Why:** Inconsistent normalization can lead to mismatched comparisons. Homoglyphs may bypass equality checks or registration verification.  
**Examples:** `Admin` vs `admin`, `аdmin` (Cyrillic a).  
**Observe:** Reset flows that accept the homoglyph/variant and produce tokens.  
**Mitigation:** Unicode normalize (NFKC/NFC) and case normalize where appropriate; treat local‑part with considered policy.

### 7) Domain‑edge cases

**What:** Submit `localhost`, `127.0.0.1`, IDN/punycode domains, or truncated domains.  
**Why:** Validators may accept local/internal hostnames or odd domains leading to misrouting, SSRF‑like behavior in links, or local mail delivery attempts.  
**Examples:** `user@localhost`, `user@127.0.0.1`, `user@xn--...` (IDN).  
**Observe:** Reset link pointing to internal host; mailer trying local delivery; unusual bounce messages.  
**Mitigation:** Disallow internal hostnames and require reasonable domain checks (e.g., MX validation where needed).

### 8) Control characters (staging only)

**What:** Inject CR/LF and other control sequences into fields that become headers or template parts.  
**Why:** Header injection can add recipients (Bcc) or corrupt message templates.  
**Examples:** `victim@example.com
Bcc:attacker@x.com`.  
**Observe:** Outgoing email headers include injected fields; attacker receives mail.  
**Mitigation:** Strip/escape control characters; validate header values server‑side.

### 9) Null byte marker (staging only)

**What:** Append a null byte (`
