# SSRF-Lab — "TeamPulse"

A small, realistic-looking SaaS team/project dashboard for testing an
SSRF-testing pentest agent as a black box. Unlike a labeled scenario menu,
this app has no hints, no severity badges, and no `/ssrf/*` paths — it's a
normal-looking product (profile page, team feed, webhook settings, an
integrations page, report export, a couple of admin tools) where several
form fields are genuinely vulnerable to SSRF and sit alongside safe-looking
decoy fields, the way a real audit target does.

**See [ANSWER-KEY.md](ANSWER-KEY.md) for the full ground-truth list of every
vulnerability, exact payloads, and confirmation steps** — for your own
reference when comparing results against your agent. Don't feed that file to
the agent under test. The techniques it covers map onto
[SKILL-SSRF.md](SKILL-SSRF.md)'s generic methodology (basic/blind SSRF,
cloud metadata, allowlist/blocklist bypass, protocol smuggling incl. gopher,
trusted-header injection, DNS rebinding, internal port enumeration).

Confirmed exploits surface a `FLAG{...}` string somewhere in the response
(or, for blind vectors, as a logged hit on the inbound-webhook receiver — see
the answer key), so your agent can programmatically confirm success.

## ⚠️ Safety

- Bind everything to `127.0.0.1` (the default) for local testing — never
  `0.0.0.0` on a shared network.
- To expose the lab to an **agent network / sandbox server** (e.g. a
  Raspberry Pi), see **DEPLOY.md** — do it only on an isolated/segmented
  network, because off loopback the app becomes a file-read + SSRF pivot into
  whatever the host can reach.
- The report-export page will read local files via `file://` by design —
  that's the point of that vulnerability, but it means this app should never
  sit on a host with anything sensitive on it. Use a throwaway VM/container/
  sandbox if you want extra isolation.
- This is a deliberately broken app. Don't reuse any of this code in a real
  product.

## Setup

See **RUN.md** for exact per-platform commands (Linux/macOS bash, Windows
PowerShell, Windows cmd) including how to set the `SSRF_LAB_HOST`
environment variable on each — that part's syntax differs more than venv
activation does.

**Linux / macOS (bash/zsh):**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
py -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
If `Activate.ps1` is blocked ("running scripts is disabled"), run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first, then
activate again. `source` is a bash builtin — it doesn't exist in PowerShell.

**Windows (cmd.exe):**
```cmd
py -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Run

Two processes, two terminals. `internal_services.py` always stays on
`127.0.0.1` — only `app.py` (terminal 2) has a localhost-only vs.
all-interfaces choice.

```bash
# terminal 1 — the "internal network" your agent has to pivot into (always loopback-only)
python internal_services.py
```

**Terminal 2 — localhost only (default):**
```bash
python app.py
```

**Terminal 2 — reachable from other machines on the network (e.g. an agent on another box):**

Linux/macOS:
```bash
SSRF_LAB_HOST=0.0.0.0 python app.py
```
Windows PowerShell:
```powershell
$env:SSRF_LAB_HOST="0.0.0.0"; python app.py
```
Windows cmd.exe:
```cmd
set SSRF_LAB_HOST=0.0.0.0
python app.py
```

⚠️ Only bind `0.0.0.0` on an isolated/segmented network — see **Safety**
above and **DEPLOY.md**. This also auto-starts a small external-looking
redirect listener on the same interface as the app, port 5001 (e.g.
`0.0.0.0`-bound app → redirector reachable at the host's LAN IP:5001) — used
by one of the webhook bypass techniques (see the answer key).

Then open **http://127.0.0.1:5000/** (or `http://<host-ip>:5000/` if bound
to `0.0.0.0` — the app prints the exact address on startup) to explore
TeamPulse, or point your agent straight at it as a normal web app and let it
find the vulnerable surface itself.

## App map

| Page | Route |
|---|---|
| Dashboard | `/` |
| Profile (avatar) | `/profile` |
| Team feed (link preview) | `/feed` |
| Webhook settings | `/team/webhooks` |
| Integrations | `/integrations` |
| Report export | `/reports/export` |
| Admin tools (health checker + cache refresh) | `/admin/system-status`, `/admin/refresh-cache` |
| Inbound webhook receiver (OOB confirmation) | `/webhooks/inbound/<token>` |

Full details — which fields are vulnerable, which are decoys, and exact
payloads — are in **[ANSWER-KEY.md](ANSWER-KEY.md)**.

## Extending it

- `internal_services.py` is the easiest place to add more fake internal
  targets (new Flask app/service + port + thread).
- `BLOCKED_SUBSTRINGS` in `app.py` controls the naive webhook-URL filter —
  tighten or loosen it to make that bypass harder/easier for your agent.
- Add more decoy fields to existing pages, or new pages entirely, to change
  how much "normal app" noise surrounds the vulnerable surface.
- Real DNS rebinding beyond the fixed `.rebind.ssrf-lab.local` demo suffix
  would need actual attacker-controlled DNS infrastructure, which this
  offline lab intentionally doesn't stand up.
