# Password Reset Testing Checklist — Practical & Concise

**Scope & warning:** authorized testing only. Use staging or a test account. Log raw requests/responses for PoC.

## 1. Discovery & baseline
**What:** Confirm reset UI & request flow (where to submit email).  
**Test / PoC:**
```bash
curl -i -X POST "https://target.example/auth/forgot"   -H "Content-Type: application/json"   -d '{"email":"test@example.com"}'
```
**Observe:** status code, response body (must be generic).  
**Mitigation:** Generic success response: “If an account exists, you’ll receive an email.”

## 2. User enumeration (response timing/content)
**What:** Does the app reveal whether an email exists?  
**Test:** Submit known registered and fake emails; compare body, headers, timing.  
**PoC:** If `test@real.com` returns 200 and `nope@x.com` 404 or different message → enumeration.  
**Mitigation:** Always return same generic response and similar timing.

## 3. Rate‑limiting & anti‑automation
**What:** Throttling/CAPTCHA on repeated reset requests.  
**Test:** Send multiple requests from same IP quickly; watch for 429 or CAPTCHA.  
**Mitigation:** Rate limit per IP/account, apply CAPTCHA after threshold, monitor abuse.

## 4. Token design & guessability
**What:** Token length, randomness and format.  
**Why:** Short or predictable tokens allow brute force takeover.  
**Guideline:** Use CSPRNG ≥128‑bit entropy; store tokens hashed server‑side; TTL short (15–60m).  
**Mitigation:** Non‑guessable tokens, hashed storage, short TTL, one‑time use.

## 5. Token mapping & DOR (Direct Object Reference)
**What:** Does token embed user id/email or allow ID swapping?  
**Test:** Try modifying token URL parts (lab only).  
**Mitigation:** Map token → user server‑side; never include usable identifiers in token.

## 6. Token expiry & one‑time use
**What:** Token expiration and reuse prevention.  
**Test:** Use token twice; wait TTL then try again — must fail.  
**Mitigation:** Mark token used immediately; enforce TTL.

## 7. Link transport security & headers
**What:** Link must be HTTPS; pages use HSTS, X‑Frame‑Options, CSP.  
**Test:** Open link, confirm https:// and security headers.  
**Mitigation:** Force HTTPS; set HSTS, CSP, X‑Frame‑Options DENY.

## 8. Reset page protections (CSRF)
**What:** Reset form must have valid CSRF token.  
**Test / PoC:** GET reset page → capture CSRF token → POST with and without token; latter must fail.  
**Mitigation:** Enforce CSRF on POST; use same‑site cookies.

## 9. Password policy & confirmation
**What:** Enforce password complexity and confirmation.  
**Test:** Submit weak/mismatched passwords; ensure rejection.  
**Mitigation:** Enforce complexity server‑side.

## 10. Post‑reset behavior (sessions, MFA, notifications)
**What:** Invalidate old sessions, trigger notification, re‑prompt MFA.  
**Test:** Reset password, try access with old session cookie — must be invalidated.  
**Mitigation:** Revoke sessions on reset; send confirmation; require MFA re‑auth.

## 11. CSRF + open redirect / link manipulation
**What:** Ensure reset link cannot cause open redirect or referrer token leakage.  
**Test:** Inspect link and follow redirect chain in lab.  
**Mitigation:** Use dedicated pages, Referrer-Policy, no open redirects.

## 12. Logging & monitoring
**What:** Log reset attempts and token usage (IP, UA, timestamp).  
**Mitigation:** Secure logs; alert on anomalous volume.

## 13. Email content & privacy
**What:** Emails should not include sensitive data; token only via URL.  
**Test:** Capture raw email in staging.  
**Mitigation:** Minimal info in email; one‑time link only.

## 14. Rate & abuse edge cases
**What:** Test mass signups/resets with temp‑mail; multi‑IP attempts.  
**Mitigation:** Rate limit, CAPTCHA, block abusive IPs, require verification for new trials.

## 15. Race conditions & concurrency
**What:** Check race windows where token validity overlaps other ops.  
**Test (lab):** Parallel flows: reset→use token vs simultaneous login with old session.  
**Mitigation:** Atomic DB ops: mark token used in transaction, revoke sessions immediately.

## 16. Edge cases
- Deactivated accounts: resets should be rejected or require extra verification.  
- Reset while logged in: behave consistently.  
- Multilingual & low‑bandwidth: ensure robustness.
**Test:** Try deactivated account, logged‑in reset, different locales.  
**Mitigation:** Document behavior, server‑side checks.

## 17. Blind / OOB verification
**Note:** Rare for resets; use timing/OOB only in extreme template/tests. Focus on token security.

## 18. Minimal PoC submission checklist
Include raw requests (forgot + reset), raw email (headers/body), reset GET/POST, minimal repro steps, evidence (screenshot/session cookie), and suggested fix (e.g., hashed tokens, TTL 15m, revoke sessions).

## Quick example PoCs (curl)

**Request reset (baseline):**
```bash
curl -i -X POST "https://target.example/auth/forgot"   -H "Content-Type: application/json"   -d '{"email":"victim@staging.example"}'
```

**Use token (example):**
```bash
curl -i -X POST "https://target.example/auth/reset"   -H "Content-Type: application/json"   -d '{"token":"<TOKEN_FROM_EMAIL>","password":"NewP@ssw0rd!"}'
```

## One‑page practical checklist (copy/paste)

- Reset endpoint discovered and baseline logged  
- Generic response for unknown email (no enumeration)  
- Rate limit / CAPTCHA in place  
- Token is long, random, hashed in storage, TTL short  
- Token is one‑time use; reuse fails  
- No sensitive info in URL / email body  
- Reset page enforces CSRF + password rules  
- Sessions revoked after reset; MFA re‑prompt next login  
- Logs capture IP/UA/timestamp for requests  
- Admin audit trail available  
- Edge cases covered (deactivated accounts, logged‑in reset)  
- Race conditions handled atomically
