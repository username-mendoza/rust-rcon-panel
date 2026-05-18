# Rust RCON Panel

A self-hosted web management panel for Rust dedicated servers. Single-file Python backend with a full embedded frontend — no build step, no framework, no database.

```
  .-.
 (☠.☠)   RCON · Console · Chat · Map · Players · Bans
  )=(
 /   \
```

---

## Features

- **RCON console** — send commands, see live server output
- **Chat tab** — monitor and send in-game chat
- **Interactive map** — canvas-based terrain overlay with monument markers, player positions, tier filters, pan & zoom
- **Live world info** — seed and world size read live from RCON on connect, rustmaps.com deep-link auto-populated
- **Players tab** — online players with ping, full session history, playtime tracking
- **Ban management** — view ban list, unban players with one click
- **Multi-server profiles** — save multiple RCON connections, auto-connects to last-used server on login
- **Remote panel support** — point a secondary panel at the primary to share map image and monuments over HTTP
- **About popup** — version, Python, aiohttp info accessible from the UI
- **HTTPS** — self-signed, custom certificate, or Let's Encrypt
- **Session auth** — login with panel password; sessions expire after 24 hours
- **Encrypted storage** — RCON passwords encrypted with Fernet; web password hashed with PBKDF2-HMAC-SHA256 (260k iterations)
- **Full-stack installer** — installs SteamCMD, Rust, Oxide/uMod, plugins, and the panel in one go

---

## Requirements

- Debian 12 / Ubuntu 22.04+ (or compatible)
- Python 3.11+
- `python3-aiohttp`, `python3-cryptography`
- Root access for installation

---

## Quick Install

Download and run the installer as root:

```bash
curl -fsSL https://raw.githubusercontent.com/username-mendoza/rust-rcon-panel/main/install.sh -o install.sh
sudo bash install.sh
```

The installer presents an interactive TUI — use arrow keys to navigate:

1. **Select components** — choose what to install (all enabled by default)
2. **Configure server** — hostname, ports, RCON password, world settings
3. **Set panel password**
4. **Choose SSL mode** — None / Self-signed / Custom cert / Let's Encrypt
5. Confirm and install

All passwords are auto-generated if left blank. Nothing is stored in plaintext.

---

## Manual Setup (panel only)

If you already have a Rust server running:

```bash
# 1. Install dependencies
sudo apt-get install -y python3-aiohttp python3-cryptography

# 2. Deploy panel
sudo mkdir -p /home/steam/rcon-panel
sudo curl -fsSL https://raw.githubusercontent.com/username-mendoza/rust-rcon-panel/main/app.py \
     -o /home/steam/rcon-panel/app.py

# 3. Create config
cat > /home/steam/rcon-panel/config.json << 'EOF'
{
  "web": {
    "host": "0.0.0.0",
    "port": 80,
    "password": ""
  },
  "map": {
    "world_size": 3000,
    "seed": 0,
    "image_url": "",
    "image_path": "/home/steam/rustserver/oxide/data/MapRenderer/map.png"
  }
}
EOF

# 4. Run setup (installs systemd service)
sudo bash setup.sh
```

On first start, the panel hashes the plaintext password and replaces it in `config.json`. Passwords can be changed from the Settings panel in the UI.

---

## Remote Panel (secondary / read-only view)

You can run a second panel instance — on a different machine or container — that displays the same map without direct filesystem access to the game server. The secondary panel fetches the map image and monument data from the primary panel over HTTP.

**Primary panel** — no config change required. The endpoints `/mapimg` and `/monuments` are public (no auth needed), so the secondary can pull from them freely.

**Secondary panel `config.json`:**

```json
{
  "web": {
    "host": "0.0.0.0",
    "port": 80,
    "password": "..."
  },
  "map": {
    "world_size": 4500,
    "seed": 0,
    "image_url": "http://<primary-panel-ip>/mapimg",
    "image_path": ""
  }
}
```

- `image_url` — points to the primary panel's `/mapimg` endpoint. The secondary fetches and caches the PNG at startup, with automatic retry if the primary is temporarily unreachable.
- Monuments are fetched automatically from `/monuments` on the same host as `image_url`.
- World seed and size are still read live from RCON if the secondary has RCON configured; otherwise set them in `config.json`.

---

## HTTPS Configuration

Add an `ssl` block to `config.json`:

**Self-signed** (browser will warn — fine for LAN/private use):
```bash
sudo mkdir -p /home/steam/rcon-panel/ssl
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /home/steam/rcon-panel/ssl/key.pem \
  -out /home/steam/rcon-panel/ssl/cert.pem \
  -days 3650 -nodes -subj "/CN=rust-rcon-panel"
```

```json
{
  "web": {
    "host": "0.0.0.0",
    "port": 443,
    "http_port": 80,
    "password": "...",
    "ssl": {
      "mode": "self_signed",
      "cert": "/home/steam/rcon-panel/ssl/cert.pem",
      "key":  "/home/steam/rcon-panel/ssl/key.pem"
    }
  }
}
```

**Let's Encrypt** (requires a public domain pointed at your server):
```json
"ssl": {
  "mode": "letsencrypt",
  "cert": "/etc/letsencrypt/live/yourdomain.com/fullchain.pem",
  "key":  "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
}
```

When SSL is active, HTTP on `http_port` automatically redirects to HTTPS.

---

## Server Profiles

Profiles are stored encrypted in `profiles.json`. Add and switch servers from the **Connect** overlay inside the panel — no restart required.

On first login with no saved profiles, the panel prompts for server connection details directly. The last-used profile is remembered across restarts.

Each profile stores:
- Display name
- Host / IP
- RCON port
- RCON password (Fernet-encrypted)

---

## Map Rendering

The panel includes a companion Oxide plugin (`MapRenderer.cs`) that renders the terrain to a PNG on server start, wipe, or on-demand via RCON command.

Install the plugin by copying it to your Oxide plugins directory:
```
/home/steam/rustserver/oxide/plugins/MapRenderer.cs
```

The rendered map and monument data are saved to:
```
/home/steam/rustserver/oxide/data/MapRenderer/map.png
/home/steam/rustserver/oxide/data/MapRenderer/monuments.json
```

These paths should match `map.image_path` in `config.json`. The panel serves the image at `/mapimg` and monument data at `/monuments` (both unauthenticated — safe for LAN use; do not expose raw to the public internet without a reverse proxy).

To re-render manually via RCON console:
```
maprender.generate
```

---

## Service Management

```bash
# Status
systemctl status rust-rcon-panel
systemctl status rust-server

# Restart
systemctl restart rust-rcon-panel
systemctl restart rust-server

# Logs (live)
journalctl -u rust-rcon-panel -f
journalctl -u rust-server -f
```

Both services are enabled for autostart on boot.

---

## Config Reference

```json
{
  "web": {
    "host":      "0.0.0.0",
    "port":      443,
    "http_port": 80,
    "password":  "pbkdf2:...",
    "ssl": {
      "mode": "self_signed | custom | letsencrypt | none",
      "cert": "/path/to/cert.pem",
      "key":  "/path/to/key.pem"
    }
  },
  "map": {
    "world_size": 3000,
    "seed":       12345678,
    "image_url":  "http://<other-panel>/mapimg",
    "image_path": "/path/to/MapRenderer/map.png"
  }
}
```

`image_url` and `image_path` can coexist — `image_url` is used for serving `/mapimg` to browsers; `image_path` is read for the local `/monuments` endpoint. Set only `image_url` (and leave `image_path` empty) on a remote panel with no local game server.

`profiles.json` is auto-managed by the panel — do not edit manually.

---

## File Layout

```
/home/steam/rcon-panel/
  app.py          — backend + embedded frontend (all-in-one)
  config.json     — web + map config (gitignored — contains hashed password)
  profiles.json   — RCON server profiles (gitignored — contains encrypted passwords)
  .secret_key     — Fernet encryption key (gitignored — keep safe)
  players.json    — player session history (gitignored — runtime data)
  install.sh      — full-stack installer
  setup.sh        — panel-only service installer
  static/
    favicon.svg

/home/steam/rustserver/oxide/plugins/
  MapRenderer.cs  — Oxide plugin for terrain map rendering

/home/steam/rustserver/oxide/data/MapRenderer/
  map.png         — rendered terrain image (written by MapRenderer.cs)
  monuments.json  — monument list with coordinates and tiers (written by MapRenderer.cs)
```

---

## Security Notes

- Web password: PBKDF2-HMAC-SHA256, 260,000 iterations
- RCON passwords: AES-128 (Fernet) with a per-installation secret key
- Sessions: 32-byte random token, 24-hour expiry, httponly + SameSite=Lax cookie
- Login: rate-limited to 10 attempts per IP per 10 minutes
- CSRF: Origin/Referer header checked on all state-changing requests
- `/mapimg` and `/monuments` are intentionally unauthenticated — put the panel behind a VPN or firewall; do not expose port 80/443 directly to the internet without one
- Never expose RCON port (default 28016) to the public internet

---

## License

MIT
