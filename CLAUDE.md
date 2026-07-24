# Rust RCON Panel — Project Guide

## What This Is

A self-hosted web RCON panel for a Rust dedicated server. Single Python file (`app.py`) using `aiohttp` — serves HTTP, WebSocket, and proxies RCON to the game server. No framework, no build step. Also includes a custom Oxide/uMod C# plugin (`MapRenderer.cs`) that renders the terrain map and underground tunnel network to PNG files.

## Infrastructure

- **Host machine**: Debian 12 Proxmox VM
- **Panel runs on**: `/home/steam/rcon-panel/app.py` as systemd service `rust-rcon-panel`
- **Game server RCON**: `ws://192.168.55.20:28016/<rcon-password>` (password encrypted in `profiles.json`)
- **Panel listens**: `0.0.0.0:80`
- **HAProxy** fronts the panel (external traffic → panel on port 80)
- **Service user**: `steam`; must `su root` (sudo_password in config.json) to restart systemd units
- **Secret key**: `/home/steam/rcon-panel/.secret_key` (root-owned, 600) — used by Fernet to encrypt RCON passwords stored in `profiles.json`

## Files

```
/home/steam/rcon-panel/
  app.py          # Main app — all Python backend + full embedded HTML/CSS/JS
  config.json     # Web config + map settings (no rcon section — stored in profiles.json)
  profiles.json   # RCON connection profiles with Fernet-encrypted passwords
  install.sh      # Self-contained installer v1.20.46 (embeds app.py + MapRenderer.cs as base64 blobs)
  setup.sh        # Installs aiohttp + systemd service (run once)
  static/
    favicon.svg   # Skull icon served at /favicon.svg
  players.json    # Auto-created at runtime — player session history DB
  geoip_cache.json # Auto-created at runtime — ip -> country lookup cache
  chat_log.json   # Auto-created at runtime — persisted in-game chat history (cleared on wipe)
  .secret_key     # Fernet key (root-owned) for encrypting RCON passwords

/home/steam/rustserver/oxide/plugins/
  MapRenderer.cs  # Oxide plugin v1.0.9 — renders surface + underground PNG maps

/home/steam/rustserver/oxide/data/MapRenderer/
  map.png           # Surface terrain map (1024×1024)
  underground.png   # Underground tunnel network map (1024×1024)
  monuments.json    # Monument positions exported alongside map.png
```

## config.json

```json
{
  "web": { "host": "0.0.0.0", "port": 80, "password": "<pbkdf2hash>",
           "sudo_password": "...", "last_profile_id": "..." },
  "map": { "world_size": 4500, "seed": 473831323, "image_url": "",
           "image_path": "/home/steam/rustserver/oxide/data/MapRenderer/map.png" }
}
```

Note: `rcon` section is absent — RCON credentials live in `profiles.json` encrypted with Fernet.

## Python Backend

`app.py` is ~5800 lines. Version: `_APP_VERSION = '1.20.45'` (line 23). Top section is pure Python; the HTML constant `HTML` contains all frontend code.

### API Routes

| Route | Handler | Purpose |
|-------|---------|---------|
| `GET /` | `_handle_index` | Serve HTML |
| `GET /favicon.svg` | `_handle_favicon` | Read from `static/favicon.svg` |
| `GET /ws` | `_handle_ws` | WebSocket — panel↔browser bridge |
| `GET /api/cfg` | `_handle_api_cfg` | Map config (world_size, seed) |
| `GET /api/time` | `_handle_time` | Server time + timezone from `/etc/timezone` |
| `GET /api/players` | `_handle_players_api` | Full player history from `players.json` |
| `GET /api/monuments` | `_handle_monuments` | Monument list from local file or RCON |
| `GET /mapimg` | `_handle_mapimg` | Serve surface map PNG from disk or URL |
| `GET /mapimg/underground` | `_handle_mapimg_underground` | Serve underground PNG from disk |
| `GET /api/mapimg/refresh` | `_handle_mapimg_refresh` | Force re-fetch map image from URL |

Both `/mapimg` and `/mapimg/underground` are exempt from auth (in the `_auth` middleware allowlist).

### Map Image Caching

```python
_mapimg_path_cache: bytes          # surface map bytes
_mapimg_path_mtime: float          # surface map mtime
_mapimg_underground_cache: bytes   # underground map bytes
_mapimg_underground_mtime: float   # underground map mtime
```

Cache invalidated by mtime check on every request.

### Player Session Tracking

- `_player_db` dict loaded from `players.json` at startup
- Format: `{ "steamid": { "name": "...", "sessions": [{"j": ts, "l": ts}, ...], "ip": "...", "cc": "US", "country": "United States" } }`
- `_process_join_leave(msg)` called on every RCON message, regex-parses join/leave events
- `_handle_players_api` returns sorted list with online status, total playtime, session count, etc.

### Stale Map After Wipe (fixed v1.20.63)

The Map tab never automatically reloaded `/mapimg` after the first load (`loadMapImg()` was
only called once per tab-open, on layer toggle, or on load error). Since a wiped `map.png` is
deleted then re-rendered by MapRenderer — observed taking **up to ~18 minutes** in practice,
well past the plugin's nominal 30s/40s scheduling delays — the panel kept showing the pre-wipe
map (and stale player dots on top of it) for the entire gap, with no user-visible signal that a
new map was even coming.

Fix: `GET /api/mapimg/meta` returns `{surface_mtime, underground_mtime}` from `os.path.getmtime`.
`captureWipeMapBaseline()` snapshots this right when a wipe is kicked off (`startWipe()`). Once
`pollWipeStatus()` sees `d.done && d.ok` for a wipe (guarded by `_wipeMapBaseline` being set, so
plain server *updates* don't trigger this), `beginPostWipeMapWatch()`:
- Immediately nulls `mapImg` and clears `mapPlayers` so the canvas falls back to the existing
  "Waiting for MapRenderer to generate the map…" placeholder instead of showing the stale image
- Polls `/api/mapimg/meta` every 20s (~30 min ceiling) until `surface_mtime` advances past the
  baseline, then reloads the map image, re-checks underground availability, and re-fetches
  `/api/monuments` (monument positions regenerate with the new map)

Player position dots need no separate fix — `mapPlayers` is repopulated continuously from live
`location` RCON polling once cleared; the stale entries were only a symptom of the stale map
image being drawn underneath them.

### Chat History

- Previously chat was purely client-side (DOM only) — reset on every browser refresh/login. Now persisted server-side.
- `_recv()` inspects every RCON message envelope; when `d['Type'] == 'Chat'`, `_parse_chat_msg()` (Python port of the frontend's `parseChat()`) extracts who/class/text and appends to `_chat_log` (ring buffer, `_CHAT_LOG_MAX = 500`), persisted to `chat_log.json`
- `GET /api/chat` returns the buffer (auth-gated, same as `/api/players`)
- Frontend calls `loadChatHistory()` once on page load (before `connect()`) to backfill `#chat-log` with `silent=true` (no unread-badge spam), using each message's real timestamp via `ts(epoch)`
- Cleared on wipe: `_run_wipe_task()` clears `_chat_log` right after save files are deleted (same spot stale map images are cleared) — chat is scoped to a wipe cycle, not kept forever

### GeoIP (player origin country)

- `playerlist` RCON response includes an `Address` field (`"ip:port"`), not documented by Rust but confirmed live — parsed in `_sync_online_players`
- On new/changed IP, `_lookup_geoip(sid, ip)` fires as a background task (`asyncio.create_task`, non-blocking)
- Private/loopback/link-local/reserved IPs (LAN testing) are skipped and cached as `None` — never geolocated
- Public IPs are resolved via `http://ip-api.com/json/<ip>` (free tier, no key, 45 req/min limit, plain HTTP not HTTPS)
- Results cached forever in `_geoip_cache` (ip → `{cc, country}`), persisted to `geoip_cache.json`, so each IP is looked up once
- Country code + name land on the player record (`cc`, `country`) and are returned by `/api/players`
- Frontend: Players tab has a sortable Country column; `ccFlag(cc)` renders a flag emoji client-side from the 2-letter code (no image assets)

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

#### Surface/Underground Layer Toggle

- `mapLayer` JS variable: `'surface'` or `'underground'`
- `setMapLayer(layer)` — switches active button, reloads map image
- `checkUndergroundAvailable()` — HEAD `/mapimg/underground`; shows `#map-layer-toggle` if 200, polls every 30s up to 6× if 404
- `loadMapImg()` — uses `/mapimg/underground` when layer is underground; only retries on surface 404 (underground 404 = not yet rendered, no retry)
- Toggle is hidden by default (`display:none`), shown automatically when `underground.png` exists
- After `maprender.generate`, `rerenderMap()` rechecks underground availability after 5s delay

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

## MapRenderer.cs (Oxide Plugin v1.0.9)

Renders Rust terrain to PNG on:
- Server init (surface: 30s delay, underground: 40s delay)
- New wipe (`OnNewSave`, same delays)
- RCON command `maprender.generate` (resets `_rendered`/`_undergndRendered` flags first, always re-renders)

### Output files

| File | Description |
|------|-------------|
| `map.png` | 1024×1024 surface terrain map with hillshading, roads, rails |
| `underground.png` | 1024×1024 tunnel network: dark bg, amber rails, station dots |
| `monuments.json` | Monument positions (written alongside `map.png`) |

### Key constants (must stay in sync with JS)

- `const float BORDER = 500f` — ocean border added around terrain (matches `MAP_BORDER = 500` in JS)
- `const int RES = 1024` — output image resolution

### Underground rendering

Data source: `FindObjectsOfType<TrainTrackSpline>()` filtered by `transform.position.y < -5f`.

**Critical**: `TrainTrackSpline.points` is `Vector3[]` in **local space**. Must call `spline.transform.TransformPoint(points[i])` to get world-space coordinates before mapping to pixels. Using raw `points[i].x/z` directly produces wrong results (lines cluster near image origin).

Station detection: `TrainTrackSpline.isStation` (bool field, accessible via reflection).

`TerrainMeta.Path.Rails` contains surface-only rails — zero underground segments even on servers with the underground train network. Don't use it for underground.

### Oxide C# constraints

- **No `dynamic` keyword** — Oxide's compiler lacks `Microsoft.CSharp.RuntimeBinder`. Use `object` + explicit reflection.
- **`DungeonGrid` not in scope** — not accessible from Oxide plugins.
- **All `System.Drawing` types must be fully qualified** to avoid ambiguity with UnityEngine types.

### RCON Commands

| Command | Purpose |
|---------|---------|
| `maprender.generate` | Force re-render both surface + underground maps |
| `maprender.debug` | Diagnostic: rail point counts by Y threshold, TrainTrackSpline count/fields, sample positions |

### Hooks

- `OnServerInitialized()` — reads config, schedules renders if files don't exist
- `OnNewSave(filename)` — resets flags, schedules both renders
- Skip scheduling if file already exists (avoids stacking timers during rapid Oxide reloads)
- `DoRender()` / `DoRenderUnderground()` guard with `_rendered` / `_undergndRendered` flags

All `System.Drawing` types fully qualified. PNG writing done off main thread via `ThreadPool.QueueUserWorkItem`.

## Release Process

After editing `app.py` and/or `MapRenderer.cs`, update `install.sh` blobs:

```python
python3 - << 'PYEOF'
import base64
with open('/home/steam/rcon-panel/app.py','rb') as f: app_b64 = base64.b64encode(f.read()).decode()
with open('/home/steam/rustserver/oxide/plugins/MapRenderer.cs','rb') as f: cs_b64 = base64.b64encode(f.read()).decode()
with open('/home/steam/rustserver/oxide/plugins/RconPanelItems.cs','rb') as f: items_b64 = base64.b64encode(f.read()).decode()
with open('/home/steam/rcon-panel/install.sh','r') as f: lines = f.readlines()
replaced = 0
blobs = [app_b64, cs_b64, items_b64]
for i, line in enumerate(lines):
    s = line.strip()
    if s.startswith("data = b'''") and s.endswith("'''"):
        if replaced < len(blobs): lines[i] = f"data = b'''{blobs[replaced]}'''\n"
        replaced += 1
print(f"Replaced {replaced} blobs")
with open('/home/steam/rcon-panel/install.sh','w') as f: f.writelines(lines)
PYEOF
```

Also bump `VERSION="x.y.z"` on line 9 and the comment on line 3 of `install.sh`.

Current version: **v1.20.63** (install.sh) / **v1.20.63** (app.py) / **v1.0.11** (MapRenderer.cs) / **v1.0.1** (RconPanelItems.cs)

**Panel runs as `steam`, not root** (systemd unit has `User=steam`, `Group=steam`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` to bind :80 unprivileged). `su root` (via `web.sudo_password`, Fernet-encrypted in `config.json` like RCON passwords) is used only for the handful of things that genuinely need root: `systemctl` start/stop/restart of both services, and editing `/etc/systemd/system/rust-server.service` for seed changes.

## Service Management

```bash
# Restart (requires root password from config.json web.sudo_password)
echo "<sudo_password>" | su -c "systemctl restart rust-rcon-panel" root

# Logs (must run as root)
echo "<sudo_password>" | su -c "journalctl -u rust-rcon-panel -n 50 --no-pager" root

# Syntax check before restart
python3 -m py_compile app.py

# Decrypt RCON password (run as root)
python3 -c "
from cryptography.fernet import Fernet; import json
key = open('/home/steam/rcon-panel/.secret_key','rb').read().strip()
profiles = json.load(open('/home/steam/rcon-panel/profiles.json'))
for p in profiles:
    pwd = p['password']; dec = Fernet(key).decrypt(pwd[4:].encode()).decode() if pwd.startswith('enc:') else pwd
    print(p['host'], p['port'], dec)
"
```

## Rules & Constraints

- **Never embed base64 images inline** in HTML or Python. Use external file paths (`/static/...`).
- **Never print base64/binary data to stdout** in bash — it breaks the Claude Code API session.
- **Never read binary files** (.ico, .png, .jpg, .gif) into context with the Read tool.
- Favicon lives at `static/favicon.svg` (served by `_handle_favicon` reading from disk).
- `install.sh` embeds **three** base64 blobs, in order: `app.py`, `MapRenderer.cs`, `RconPanelItems.cs`.
- The static/ directory is NOT currently copied by install.sh — if redeploying, copy manually or add to installer.

## Known RCON Command Formats

| Command | Response format |
|---------|----------------|
| `fps` | `"95 FPS"` — number first, no colon |
| `status` | Multi-line text, no fps/memory |
| `serverinfo` | JSON with `Framerate`, `Memory`, `Hostname`, `Players`, etc. |
| `playerlist` | JSON array with `SteamID`, `Username`/`DisplayName`, `Ping`, `Address` (`"ip:port"`), `ConnectedSeconds`, `Health`, etc. |
| `location` | Text lines: `steamid "Name" pos(x,y,z) ...` |
| `inventory.giveto "<display_name>" <item> <amt>` | Give item to player (requires display name, not steamid — `inventory.give <steamid>` silently does nothing) |
| `maprender.generate` | Re-renders surface + underground maps (resets render flags) |
| `maprender.debug` | Diagnostic output: rail Y-counts, TrainTrackSpline count + field list |
