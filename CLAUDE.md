# Rust RCON Panel — Project Guide

## What This Is

A self-hosted web RCON panel for a Rust dedicated server. Single Python file (`app.py`) using `aiohttp` — serves HTTP, WebSocket, and proxies RCON to the game server. No framework, no build step. Also includes a custom Oxide/uMod C# plugin (`MapRenderer.cs`) that renders the terrain map to a PNG.

## Infrastructure

- **Host machine**: Debian 12 Proxmox VM
- **Panel runs on**: `/home/steam/rcon-panel/app.py` as systemd service `rust-rcon-panel`
- **Game server RCON**: `ws://<server-ip>:28016/<rcon-password>`
- **Panel listens**: `0.0.0.0:80`
- **HAProxy** fronts the panel (external traffic → panel on port 80)
- **Service user**: `steam`; must `su root` (password: not stored) to restart

## Files

```
/home/steam/rcon-panel/
  app.py          # Main app — all Python backend + full embedded HTML/CSS/JS
  config.json     # RCON + web config (host, port, password, map settings)
  install.sh      # Self-contained installer v1.5.0 (embeds app.py + MapRenderer.cs as base64 blobs)
  setup.sh        # Installs aiohttp + systemd service (run once)
  static/
    favicon.svg   # Skull icon served at /favicon.svg
  players.json    # Auto-created at runtime — player session history DB

/home/steam/rustserver/oxide/plugins/
  MapRenderer.cs  # Oxide plugin v1.0.7 — renders terrain PNG on wipe/startup/command
```

## config.json

```json
{
  "rcon":  { "host": "<server-ip>", "port": 28016, "password": "..." },
  "web":   { "host": "0.0.0.0", "port": 80, "password": "" },
  "map":   { "world_size": 4500, "seed": 1603105674, "image_url": "",
             "image_path": "/home/steam/rustserver/oxide/data/MapRenderer/map.png" }
}
```

## Python Backend

`app.py` is ~1980 lines. Top section is pure Python; the HTML constant `HTML` contains all frontend code.

### API Routes

| Route | Handler | Purpose |
|-------|---------|---------|
| `GET /` | `_handle_index` | Serve HTML |
| `GET /favicon.svg` | `_handle_favicon` | Read from `static/favicon.svg` |
| `GET /ws` | `_handle_ws` | WebSocket — panel↔browser bridge |
| `GET /api/cfg` | `_handle_api_cfg` | Map config (world_size, seed) |
| `GET /api/time` | `_handle_time` | Server time + timezone from `/etc/timezone` |
| `GET /api/players` | `_handle_players_api` | Full player history from `players.json` |
| `GET /api/monuments` | `_handle_monuments` | Monument list from RCON |
| `GET /mapimg` | `_handle_mapimg` | Serve map PNG from disk or URL |
| `GET /api/mapimg/refresh` | `_handle_mapimg_refresh` | Force re-fetch map image |

### Player Session Tracking

- `_player_db` dict loaded from `players.json` at startup
- Format: `{ "steamid": { "name": "...", "sessions": [{"j": ts, "l": ts}, ...] } }`
- `_process_join_leave(msg)` called on every RCON message, regex-parses join/leave events
- `_handle_players_api` returns sorted list with online status, total playtime, session count, etc.

### RCON Polling (silent background)

Every 60 seconds:
- `sendBg('playerlist')` → parsed as JSON array, updates live player list silently
- `sendBg('serverinfo')` → parsed as JSON, updates FPS + Memory in sidebar

On connect:
- `send('status')` at 300ms → updates hostname, players, map name
- `sendBg('serverinfo')` at 600ms → updates FPS + memory
- `sendBg('playerlist')` at 900ms → populates player list

Key RCON commands and their response formats:
- `fps` → `"95 FPS"` (number first — NOT "fps: 95")
- `status` → multi-line text with hostname/version/map/players. NO fps/memory
- `serverinfo` → JSON: `{"Framerate": 54.0, "Memory": 4968, "Hostname": "...", ...}`
- `playerlist` → JSON array: `[{"SteamID":"...","Username":"...","Ping":45}, ...]`
- `location` → player positions for map overlay

## Frontend (JS inside HTML constant)

### Tabs

`TABS = ['console', 'chat', 'map', 'players']`

`switchTab(name)` toggles `.active` on panel divs. Map tab triggers `initMapIfNeeded()`. Players tab calls `loadPlayersTab()`.

### Map

- Canvas-based, pan/zoom via `ctx.setTransform(scale, 0, 0, scale, ox, oy)`
- `MAP_BORDER = 500` — ocean border in pixels (must match `BORDER = 500f` in MapRenderer.cs)
- `mapRect()` — returns largest centered square within canvas to enforce 1:1 aspect ratio
- `worldToCanvas(x, z)` — converts world coords to canvas coords
- Monument tier filters: `safe`, `3`, `2`, `1`, `water`, `cave`, `other`
- Double-click to reset zoom; wheel to zoom; drag to pan
- `sendBg('location')` polled every 30s when map tab is active → draws player dots

### Players Tab

- `loadPlayersTab(force)` — fetches `/api/players`, caches 30s
- `renderPlayersTable()` — filters by search, sorts (online-first always), renders rows
- Click row → expands session history inline
- `livePlayers` dict updated by `renderPlayers()` (from playerlist poll) — provides real-time ping for Players tab
- Auto-refresh every 60s when players tab is active

### Give Item Modal

Right-click a player → "Give Item..." → modal with:
- Search input filtering `RUST_ITEMS` array (~130 items across 10 categories)
- Scrollable `<select>` grouped by category (optgroups)
- Amount input
- Executes: `inventory.give <steamid> <shortname> <amount>`

### Suppression Logic (onMsg)

Silent poll responses are parsed and swallowed before reaching the console log:
- `"No players found."` → suppressed
- JSON array starting with `[` → parsed as playerlist, suppressed
- JSON object starting with `{` containing `Framerate` key → parsed as serverinfo, suppressed
- `parseLocations(msg)` returning true → location data, suppressed

## MapRenderer.cs (Oxide Plugin v1.0.7)

Renders Rust terrain to PNG on:
- Server init (10s delay)
- New wipe (`OnNewSave`, 20s delay)
- RCON command `maprender.generate`

Key constants (must stay in sync with JS):
- `const float BORDER = 500f` — ocean border added around terrain (matches `MAP_BORDER = 500` in JS)
- `const int RES = 2048` — output image resolution

All `System.Drawing` types fully qualified (`System.Drawing.Graphics`, `System.Drawing.Color`, etc.) to avoid ambiguity with UnityEngine types.

River/water color matches ocean: blue family (`r=24-36, g=66-86, b=120-172`).

## Release Process

After editing `app.py` and/or `MapRenderer.cs`, update `install.sh` blobs:

```python
python3 - << 'PYEOF'
import base64
with open('/home/steam/rcon-panel/app.py','rb') as f: app_b64 = base64.b64encode(f.read()).decode()
with open('/home/steam/rustserver/oxide/plugins/MapRenderer.cs','rb') as f: cs_b64 = base64.b64encode(f.read()).decode()
with open('/home/steam/rcon-panel/install.sh','r') as f: lines = f.readlines()
replaced = 0
for i, line in enumerate(lines):
    s = line.strip()
    if s.startswith("data = b'''") and s.endswith("'''"):
        lines[i] = f"data = b'''{app_b64}'''\n" if replaced==0 else f"data = b'''{cs_b64}'''\n"
        replaced += 1
print(f"Replaced {replaced} blobs")
with open('/home/steam/rcon-panel/install.sh','w') as f: f.writelines(lines)
PYEOF
```

Also bump `VERSION="x.y.z"` on line 9 and the comment on line 3 of `install.sh`.

Current version: **v1.5.0**

## Service Management

```bash
# Restart (requires root password)
echo "<password>" | su -c "systemctl restart rust-rcon-panel" root

# Logs
journalctl -u rust-rcon-panel -n 50

# Syntax check before restart
python3 -m py_compile app.py
```

## Rules & Constraints

- **Never embed base64 images inline** in HTML or Python. Use external file paths (`/static/...`).
- **Never print base64/binary data to stdout** in bash — it breaks the Claude Code API session.
- **Never read binary files** (.ico, .png, .jpg, .gif) into context with the Read tool.
- Favicon lives at `static/favicon.svg` (served by `_handle_favicon` reading from disk).
- `install.sh` embeds **two** base64 blobs: first is `app.py`, second is `MapRenderer.cs`.
- The static/ directory is NOT currently copied by install.sh — if redeploying, copy manually or add to installer.

## Known RCON Command Formats

| Command | Response format |
|---------|----------------|
| `fps` | `"95 FPS"` — number first, no colon |
| `status` | Multi-line text, no fps/memory |
| `serverinfo` | JSON with `Framerate`, `Memory`, `Hostname`, `Players`, etc. |
| `playerlist` | JSON array with `SteamID`, `Username`, `Ping` |
| `location` | Text lines: `steamid "Name" pos(x,y,z) ...` |
| `inventory.give <id> <item> <amt>` | Give item to player |
| `maprender.generate` | Triggers MapRenderer plugin to re-render map |
