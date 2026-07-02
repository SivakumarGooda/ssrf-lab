# Deploying SSRF-Lab on a Raspberry Pi (or any sandbox server)

Short answer: yes. It's pure Python + Flask, so it runs on a Pi (ARM), a
small VM, or a container — anything that can run Python 3.9+. Below is how to
expose the **vulnerable app** to your agent network while keeping the fake
internal services loopback-only.

## The one thing that changes off loopback

On your laptop everything was bound to `127.0.0.1`, so nothing but processes
on that host could reach it. To let your agent hit the lab, the vulnerable
app now has to listen on a network interface. That's fine — but understand
what you're exposing:

- The report-export page reads local files via `file://` **by design**.
  Anyone who can reach the app can read files the app's user can read *on
  the Pi*.
- The profile avatar, team feed, webhook, integrations, and admin-tools
  pages all turn the Pi into an **SSRF pivot**. On loopback they only
  reached the fake internal services; on a real network they can now reach
  whatever the Pi itself can reach.

So this is a deliberately-vulnerable box. Treat it like one: put it on an
isolated segment/VLAN, or a network that only your agent and the lab share.
Don't drop it on your home/office LAN with production hosts next to it.

## What stays loopback (don't change this)

`internal_services.py` binds to `127.0.0.1:7001-7005` on purpose. Those fake
services must only be reachable *through* the app's SSRF, never directly —
that's what makes the pivot realistic. Leave them on loopback. The app runs
on the same host, so it still reaches them fine.

## Manual run (quick test)

```bash
# on the Pi
sudo apt update && sudo apt install -y python3-venv
git clone/copy the ssrf-lab folder to the Pi, then:
cd ssrf-lab
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# terminal 1 — fake internal network (loopback-only)
python internal_services.py

# terminal 2 — vulnerable app, exposed to the network
SSRF_LAB_HOST=0.0.0.0 SSRF_LAB_PORT=5000 python app.py
```

From your agent host, confirm reachability:
```bash
curl http://<pi-ip>:5000/
```

## Run as a service (survives reboots)

Copy the folder to `/opt/ssrf-lab`, create the venv there, then install the
two unit files in `deploy/` (edit `User=` and paths first if needed):

```bash
sudo cp deploy/ssrf-lab-internal.service /etc/systemd/system/
sudo cp deploy/ssrf-lab-app.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssrf-lab-internal.service
sudo systemctl enable --now ssrf-lab-app.service
sudo systemctl status ssrf-lab-app.service
```

The app unit depends on the internal-services unit, so they start in order.

## Isolation checklist (do at least a couple of these)

- **Dedicated box/VM/container.** A cheap Pi or a throwaway VM that holds
  nothing sensitive is ideal — the `file://` read then leaks nothing real.
- **Segmented network.** Put the lab and the agent on their own VLAN/subnet
  with no route to production. This contains the SSRF pivot.
- **Host firewall.** Restrict who can hit port 5000 to just your agent's IP:
  ```bash
  sudo ufw default deny incoming
  sudo ufw allow from <agent-ip> to any port 5000 proto tcp
  sudo ufw enable
  ```
- **Minimal user.** Run the service as an unprivileged user (the units use
  `User=pi`) so the file-read primitive can't reach root-owned secrets.
- **Kill it when done.** `sudo systemctl stop ssrf-lab-app` between test runs
  if the box shares a network with anything you care about.

## Windows host, attacking from Kali (your setup)

This is a faithful "real-world server vs. attacker" topology: the Windows box
is the target server, Kali is the attacker. Same files, no edits needed.

On the **Windows** target:

1. Install Python 3 (python.org), then in the lab folder:
   ```powershell
   py -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Start the fake internal network (leave 127.0.0.1 — it's correct on Windows):
   ```powershell
   python internal_services.py
   ```
3. In a second terminal, expose the vulnerable app to the network. Env-var
   syntax differs from Linux:
   ```powershell
   # PowerShell
   $env:SSRF_LAB_HOST="0.0.0.0"; python app.py
   ```
   ```cmd
   REM cmd.exe
   set SSRF_LAB_HOST=0.0.0.0
   python app.py
   ```
   On startup the app prints the exact `http://<windows-lan-ip>:5000/` address
   to use from Kali, and the redirect listener comes up on the same IP.
4. Allow inbound 5000 through Windows Firewall (only from your Kali IP is best):
   ```powershell
   New-NetFirewallRule -DisplayName "SSRF-Lab 5000" -Direction Inbound `
     -Protocol TCP -LocalPort 5000,5001 -RemoteAddress <kali-ip> -Action Allow
   ```

From **Kali**: point your agent / browser / curl at `http://<windows-ip>:5000/`.
See **ANSWER-KEY.md** for exact payloads — substitute the printed LAN IP for
`127.0.0.1`/`localhost` where relevant. The internal services on 7001-7005
stay unreachable directly from Kali (verified) — you can only touch them
*through* the app's vulnerabilities, which is the whole point.

Cross-platform notes baked in:
- The redirect listener binds to the app's interface (not the Linux-only
  `127.0.0.2`), so the webhook redirect-chaining bypass works on Windows.
- `file://` payloads need an OS-correct absolute path (`file:///C:/.../secret.txt`
  on Windows, `file:///home/.../secret.txt` on Linux).

Persistence on Windows (optional): wrap `python app.py` with
[NSSM](https://nssm.cc/) as a service, or a Task Scheduler task set to run at
startup. The systemd units in `deploy/` are Linux-only.

## Sandbox server instead of a Pi

Identical steps — any Linux host reachable from the agent network works. In a
container, publish only the app port and keep the internal services on the
container's loopback:
```bash
docker run -d --name ssrf-lab -p 5000:5000 \
  -e SSRF_LAB_HOST=0.0.0.0 your-image
```
(You'd bundle a small entrypoint that launches `internal_services.py` in the
background, then `app.py`.) The container boundary gives you the isolation
for free — the SSRF pivot only reaches what the container can reach.
