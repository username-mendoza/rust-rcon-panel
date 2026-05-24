#!/usr/bin/env python3
"""Rust Game Server RCON Web Panel"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import os
import platform
import re
import ssl
import sys
import time
from html import escape as _he
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from cryptography.fernet import Fernet, InvalidToken
from aiohttp import web, WSMsgType
import aiohttp

_APP_VERSION = '1.20.5'

CONFIG = {}

# ── Player history database ───────────────────────────────────────────────────
_player_db: dict = {}   # { steamid: {name, sessions:[{j,l?},...]} }
_player_db_path: str = ''

_profiles: list = []
_profiles_path: str = ''
_active_profile_id: str = ''
_rcon_cfg: dict = {}
_rcon_restart: asyncio.Event = None

_sessions: dict = {}  # token -> expiry_ts
_fernet: Fernet = None
_secret_key_path: str = ''
_rcon_pending: dict = {}  # identifier -> asyncio.Future
_login_attempts: dict = {}  # ip -> [timestamp, ...]
_profiles_lock: asyncio.Lock = None  # initialised in _startup

_RE_JOIN         = re.compile(r'(\d{17,18})/(.+?)\s+joined')
_RE_LEAVE        = re.compile(r'(\d{17,18})/(.+?)\s+(?:disconnect|left the game)', re.I)
_RE_STEAMID      = re.compile(r'^\d{17}$')
_RE_BAN_SID      = re.compile(r'\b(\d{17})\b')
_RE_BAN_IDX      = re.compile(r'^\d+[.):\s]+')
_RE_WORLDCFG_VAL = re.compile(r'"(-?\d+)"')
_RE_OX_PLUGIN    = re.compile(
    r'^\d+\s+(.+?)\s+\(([^)]+)\)\s+by\s+(.+?)(?:\s+--\s+(.+))?$'
)


def _valid_port(port) -> bool:
    try:
        return 1 <= int(port) <= 65535
    except (TypeError, ValueError):
        return False


def _valid_steamid(sid: str) -> bool:
    return bool(_RE_STEAMID.match(str(sid)))

def _parse_oxide_version(raw: str) -> str:
    # "Oxide.Rust Version: 2.0.7338\nOxide.Rust Branch: master"
    m = re.search(r'Version:\s*([\d.]+)', raw, re.IGNORECASE)
    if m:
        return 'Oxide ' + m.group(1)
    m = re.search(r'(?:Oxide|uMod)\s+[\d.]+', raw, re.IGNORECASE)
    return m.group(0) if m else raw.split('\n')[0].strip()

def _parse_oxide_plugins(raw: str) -> list:
    plugins = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or '[Oxide]' in line or '[uMod]' in line:
            continue
        m = _RE_OX_PLUGIN.match(line)
        if m:
            raw_author = m.group(3).strip()
            # ".cs" filename at end of author field is the uMod lookup key
            m_cs = re.search(r'-\s+(\w+)\.cs$', raw_author)
            slug = m_cs.group(1) if m_cs else ''
            # Strip load stats like "(0.01s / 24 KB) - Plugin.cs"
            author = re.sub(r'\s+\([\d.].*$', '', raw_author)
            name = m.group(1).strip().strip('"')
            plugins.append({
                'name':        name,
                'slug':        slug or re.sub(r'\s+', '', name),
                'version':     m.group(2).strip(),
                'author':      author,
                'description': (m.group(4) or '').strip(),
            })
    return plugins

def _load_player_db():
    global _player_db
    if _player_db_path and os.path.exists(_player_db_path):
        try:
            with open(_player_db_path) as f:
                _player_db = json.load(f)
        except Exception:
            _player_db = {}

def _save_player_db():
    if _player_db_path:
        try:
            with open(_player_db_path, 'w') as f:
                json.dump(_player_db, f, separators=(',', ':'))
        except Exception:
            pass

def _new_session() -> str:
    token = os.urandom(32).hex()
    _sessions[token] = time.time() + 86400
    return token

def _valid_session(token: str) -> bool:
    exp = _sessions.get(token)
    if not exp:
        return False
    if time.time() > exp:
        _sessions.pop(token, None)
        return False
    return True

def _delete_session(token: str):
    _sessions.pop(token, None)


def _init_fernet():
    global _fernet
    if os.path.exists(_secret_key_path):
        with open(_secret_key_path, 'rb') as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(_secret_key_path, 'wb') as f:
            f.write(key)
        os.chmod(_secret_key_path, 0o600)
    _fernet = Fernet(key)


def _encrypt_pwd(pwd: str) -> str:
    if not pwd:
        return ''
    return 'enc:' + _fernet.encrypt(pwd.encode()).decode()


def _decrypt_pwd(stored: str) -> str:
    if not stored or not stored.startswith('enc:'):
        return ''
    try:
        return _fernet.decrypt(stored[4:].encode()).decode()
    except (InvalidToken, Exception):
        return ''


def _hash_web_pwd(pwd: str) -> str:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt.encode(), 260_000)
    return f'pbkdf2:{salt}:{base64.b64encode(dk).decode()}'


def _verify_web_pwd(given: str, stored: str) -> bool:
    if not stored or not stored.startswith('pbkdf2:'):
        return False
    try:
        _, salt, dk_b64 = stored.split(':', 2)
        dk = hashlib.pbkdf2_hmac('sha256', given.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(base64.b64encode(dk).decode(), dk_b64)
    except Exception:
        return False


def _load_profiles():
    global _profiles
    if _profiles_path and os.path.exists(_profiles_path):
        try:
            with open(_profiles_path) as f:
                _profiles = json.load(f)
        except Exception:
            _profiles = []

def _save_profiles():
    if _profiles_path:
        try:
            with open(_profiles_path, 'w') as f:
                json.dump(_profiles, f, separators=(',', ':'), indent=2)
        except Exception:
            pass

def _migrate_profile_passwords():
    changed = False
    for p in _profiles:
        pwd = p.get('password', '')
        if pwd and not pwd.startswith('enc:'):
            p['password'] = _encrypt_pwd(pwd)
            changed = True
    if changed:
        _save_profiles()

def _profile_for_api(p: dict) -> dict:
    """Return profile with decrypted password for frontend use."""
    return {**p, 'password': _decrypt_pwd(p.get('password', ''))}


def _process_join_leave(msg: str) -> bool:
    now = int(time.time())
    changed = False
    for line in msg.splitlines():
        line = line.strip()
        m = _RE_JOIN.search(line)
        if m:
            sid, name = m.group(1), m.group(2).strip()
            if sid not in _player_db:
                _player_db[sid] = {'name': name, 'sessions': []}
            else:
                _player_db[sid]['name'] = name
            # Close any stale open session first
            for s in _player_db[sid]['sessions']:
                if 'l' not in s:
                    s['l'] = now
            _player_db[sid]['sessions'].append({'j': now})
            changed = True
            continue
        m = _RE_LEAVE.search(line)
        if m:
            sid = m.group(1)
            if sid in _player_db:
                for s in reversed(_player_db[sid]['sessions']):
                    if 'l' not in s:
                        s['l'] = now
                        break
                changed = True
    return changed

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In — Rust RCON Panel</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#111215;--bg2:#1a1c21;--bg3:#22252d;--border:#2e3138;--accent:#cd4214;--accent2:#e05a2a;--text:#c8ccd6;--dim:#6b7280;--red:#ef4444;--green:#4caf50}}
html,body{{height:100%;font-family:'Consolas','Menlo','Monaco',monospace;background:var(--bg);color:var(--text);font-size:13px;display:flex;align-items:center;justify-content:center}}
#card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;width:360px;max-width:calc(100vw - 32px);padding:32px 28px;box-shadow:0 20px 60px rgba(0,0,0,.6)}}
.logo{{display:flex;align-items:center;gap:10px;margin-bottom:22px}}
.logo-title{{color:var(--accent);font-size:18px;font-weight:bold}}
.logo-sub{{color:var(--dim);font-size:11px;margin-top:2px}}
.servers{{margin-bottom:20px;border:1px solid var(--border);border-radius:6px;overflow:hidden}}
.servers-hdr{{padding:7px 12px;font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;background:var(--bg3);border-bottom:1px solid var(--border)}}
.srv-row{{display:flex;align-items:center;gap:10px;padding:9px 12px;cursor:pointer;border-left:2px solid transparent;transition:background .12s,border-color .12s}}
.srv-row+.srv-row{{border-top:1px solid var(--border)}}
.srv-row:hover{{background:rgba(255,255,255,.04)}}
.srv-row.sel{{background:rgba(205,66,20,.08);border-left-color:var(--accent)}}
.srv-dot{{width:7px;height:7px;border-radius:50%;background:var(--dim);flex-shrink:0}}
.srv-row.sel .srv-dot{{background:var(--accent)}}
.srv-name{{font-size:12px;font-weight:bold;color:var(--text)}}
.srv-addr{{font-size:10px;color:var(--dim);margin-top:1px}}
.no-srv{{padding:10px 12px;font-size:12px;color:var(--dim)}}
.field{{margin-bottom:16px}}
label{{display:block;font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}}
input[type=password]{{width:100%;background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:6px;font-family:inherit;font-size:13px;outline:none;transition:border-color .2s}}
input[type=password]:focus{{border-color:var(--accent)}}
#signin{{width:100%;padding:10px;border:none;border-radius:6px;background:var(--accent);color:#fff;font-weight:bold;font-family:inherit;font-size:14px;cursor:pointer;transition:background .2s;margin-top:4px}}
#signin:hover{{background:var(--accent2)}}
#err{{color:var(--red);font-size:12px;margin-top:12px;text-align:center;min-height:18px}}
::-webkit-scrollbar{{width:5px}}::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
</style>
</head>
<body>
<div id="card">
  <div class="logo">
    <svg width="24" height="26" viewBox="0 0 32 36" fill="none" xmlns="http://www.w3.org/2000/svg"><ellipse cx="16" cy="13" rx="11" ry="11" fill="#cd4214"/><circle cx="11.5" cy="12" r="2.8" fill="#1a1c20"/><circle cx="20.5" cy="12" r="2.8" fill="#1a1c20"/><rect x="10" y="22" width="12" height="2" rx="1" fill="#1a1c20" opacity=".35"/><rect x="11.5" y="24" width="3" height="7" rx="1.5" fill="#cd4214"/><rect x="17.5" y="24" width="3" height="7" rx="1.5" fill="#cd4214"/><rect x="9" y="30" width="14" height="2.5" rx="1.2" fill="#cd4214" opacity=".4"/></svg>
    <div><div class="logo-title">RCON Panel</div><div class="logo-sub">Rust Game Server</div></div>
  </div>
  {servers_html}
  <form method="POST" action="/login">
    <div class="field">
      <label for="pw">Panel Password</label>
      <input id="pw" name="password" type="password" placeholder="&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;" autocomplete="current-password" autofocus>
    </div>
    <input type="hidden" name="profile_id" id="pid">
    <button type="submit" id="signin">Sign In</button>
  </form>
  <div id="err">{error_msg}</div>
</div>
<script>
var rows = document.querySelectorAll('.srv-row');
rows.forEach(function(row) {{
  row.addEventListener('click', function() {{
    rows.forEach(function(r) {{ r.classList.remove('sel'); }});
    row.classList.add('sel');
    document.getElementById('pid').value = row.dataset.id;
  }});
  if (row.classList.contains('sel')) document.getElementById('pid').value = row.dataset.id;
}});
</script>
</body>
</html>"""

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rust RCON Panel</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #111215;
  --bg2:     #1a1c21;
  --bg3:     #22252d;
  --border:  #2e3138;
  --accent:  #cd4214;
  --accent2: #e05a2a;
  --text:    #c8ccd6;
  --dim:     #6b7280;
  --green:   #4caf50;
  --red:     #ef4444;
  --yellow:  #f59e0b;
  --blue:    #60a5fa;
}

html, body { height: 100%; font-family: 'Consolas','Menlo','Monaco',monospace; background: var(--bg); color: var(--text); font-size: 13px; }

/* ── Header ── */
#header {
  display: flex; align-items: center; gap: 14px;
  padding: 0 16px; height: 46px;
  background: var(--bg2); border-bottom: 1px solid var(--border); flex-shrink: 0;
}
#hdr-logo   { color: var(--accent); font-size: 15px; font-weight: bold; white-space: nowrap; }
#hdr-server { color: var(--dim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
#hdr-status {
  display: flex; align-items: center; gap: 6px;
  font-size: 11px; font-weight: bold; padding: 3px 10px; border-radius: 20px; transition: all .3s;
}
#hdr-status.ok  { color: var(--green); background: rgba(76,175,80,.12);  border: 1px solid rgba(76,175,80,.3); }
#hdr-status.err { color: var(--red);   background: rgba(239,68,68,.12);   border: 1px solid rgba(239,68,68,.3); }
#status-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }

/* ── Layout ── */
#app { display: flex; height: calc(100vh - 46px); overflow: hidden; }
#left { display: flex; flex-direction: column; flex: 1; min-width: 0; border-right: 1px solid var(--border); }

/* ── Tab bar ── */
#tabbar {
  display: flex; background: var(--bg2);
  border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.tab {
  padding: 9px 20px; cursor: pointer; font-size: 12px;
  color: var(--dim); border-bottom: 2px solid transparent;
  transition: all .15s; user-select: none; position: relative; white-space: nowrap;
}
.tab:hover { color: var(--text); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tbadge {
  display: none; position: absolute; top: 5px; right: 4px;
  background: var(--accent); color: #fff; font-size: 9px; font-weight: bold;
  padding: 1px 4px; border-radius: 8px; min-width: 14px; text-align: center;
}
.tbadge.show { display: inline-block; }

/* ── Panel base ── */
.panel { display: none; flex-direction: column; flex: 1; overflow: hidden; }
.panel.active { display: flex; }

/* ── Console ── */
#console {
  flex: 1; overflow-y: auto; padding: 8px 12px;
  font-size: 12px; line-height: 1.65;
}
.ln { display: flex; gap: 8px; }
.ln-t { color: var(--dim); flex-shrink: 0; font-size: 11px; padding-top: 1px; }
.ln-m { flex: 1; word-break: break-word; white-space: pre-wrap; }
.ln.sys  .ln-m { color: var(--dim); font-style: italic; }
.ln.sent .ln-m { color: var(--accent2); }
.ln.err  .ln-m { color: var(--red); }
.ln.warn .ln-m { color: var(--yellow); }
.ln.info .ln-m { color: var(--blue); }
.ln.ok   .ln-m { color: var(--green); }

#cmd-bar {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 12px; background: var(--bg2); border-top: 1px solid var(--border);
}
#cmd-pfx { color: var(--accent); font-weight: bold; flex-shrink: 0; }
#cmd-in {
  flex: 1; background: var(--bg3); border: 1px solid var(--border);
  color: var(--text); padding: 6px 10px; font-family: inherit; font-size: 13px;
  border-radius: 4px; outline: none; transition: border-color .2s;
}
#cmd-in:focus { border-color: var(--accent); }
#cmd-in:disabled { opacity: .45; }
#cmd-go, #clear-btn {
  border: none; padding: 6px 16px; border-radius: 4px;
  cursor: pointer; font-weight: bold; font-family: inherit; transition: all .2s;
}
#cmd-go { background: var(--accent); color: #fff; }
#cmd-go:hover:not(:disabled) { background: var(--accent2); }
#cmd-go:disabled { opacity: .4; cursor: not-allowed; }
#clear-btn { background: transparent; border: 1px solid var(--border); color: var(--dim); }
#clear-btn:hover { border-color: var(--accent); color: var(--text); }
#ascroll-btn {
  background: transparent; border: 1px solid var(--border); color: var(--dim);
  padding: 5px 9px; border-radius: 4px; cursor: pointer; font-size: 11px;
  font-family: inherit; transition: all .15s; display: flex; align-items: center; gap: 5px;
  white-space: nowrap;
}
#ascroll-btn.on  { border-color: var(--green); color: var(--green); }
#ascroll-btn.off { border-color: var(--dim);   color: var(--dim); }
#ascroll-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex-shrink: 0; }
#ascroll-btn.on #ascroll-dot { animation: blink 1.8s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }

/* ── Chat ── */
#chat-log {
  flex: 1; overflow-y: auto; padding: 8px 12px;
  font-size: 13px; line-height: 1.75;
}
.cm { display: flex; gap: 8px; align-items: baseline; padding: 1px 0; }
.cm-t   { color: var(--dim); font-size: 11px; flex-shrink: 0; }
.cm-who { font-weight: bold; flex-shrink: 0; }
.cm-who.player { color: var(--blue); }
.cm-who.server { color: var(--accent); }
.cm-sep  { color: var(--dim); flex-shrink: 0; }
.cm-text { flex: 1; word-break: break-word; }

#chat-bar {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 12px; background: var(--bg2); border-top: 1px solid var(--border);
}
#chat-pfx { color: var(--accent); font-size: 11px; font-weight: bold; flex-shrink: 0; }
#chat-in {
  flex: 1; background: var(--bg3); border: 1px solid var(--border);
  color: var(--text); padding: 6px 10px; font-family: inherit; font-size: 13px;
  border-radius: 4px; outline: none; transition: border-color .2s;
}
#chat-in:focus { border-color: var(--accent); }
#chat-in:disabled { opacity: .45; }
#chat-go {
  background: var(--accent); color: #fff; border: none;
  padding: 6px 18px; border-radius: 4px; cursor: pointer;
  font-weight: bold; font-family: inherit; transition: background .2s;
}
#chat-go:hover:not(:disabled) { background: var(--accent2); }
#chat-go:disabled { opacity: .4; cursor: not-allowed; }

/* ── Map ── */
#map-toolbar {
  display: flex; align-items: center; gap: 8px;
  padding: 7px 12px; background: var(--bg2); border-bottom: 1px solid var(--border);
  font-size: 11px; flex-shrink: 0;
}
#map-toolbar span { color: var(--dim); }
#map-refresh, #map-rerender, #map-resetview {
  background: var(--bg3); border: 1px solid var(--border); color: var(--text);
  padding: 3px 10px; border-radius: 3px; cursor: pointer; font-size: 11px;
  font-family: inherit; transition: all .15s;
}
#map-refresh:hover  { border-color: var(--accent); color: var(--accent); }
#map-rerender:hover { border-color: var(--blue);   color: var(--blue); }
#map-rerender:disabled { opacity:.45; cursor:not-allowed; }
#map-resetview:hover { border-color: var(--dim); color: var(--text); }
#map-updated { color: var(--dim); margin-left: auto; font-size: 11px; }
#map-coords  { color: var(--dim); font-size: 11px; font-family: 'Consolas','Menlo',monospace; min-width: 120px; }

#map-canvas-wrap { flex: 1; position: relative; overflow: hidden; background: #0a120a; }
#map-canvas { position: absolute; top: 0; left: 0; display: block; cursor: crosshair; }

/* Map info bar */
#map-infobar {
  position: absolute; bottom: 6px; left: 6px; z-index: 5;
  background: rgba(17,18,21,0.82); border: 1px solid rgba(46,49,56,0.8);
  border-radius: 4px; padding: 4px 8px; font-size: 10px;
  color: rgba(200,204,214,0.65); pointer-events: none; line-height: 1.5;
}

#map-tooltip {
  position: absolute; pointer-events: none; display: none;
  background: var(--bg2); border: 1px solid var(--border);
  padding: 5px 9px; border-radius: 4px; font-size: 11px; z-index: 10;
  white-space: nowrap;
}
#map-tooltip .tt-name { color: var(--text); font-weight: bold; }
#map-tooltip .tt-grid { color: var(--accent); }
#map-tooltip .tt-id   { color: var(--dim); font-size: 10px; }

/* ── Sidebar ── */
#sidebar { width: 265px; flex-shrink: 0; display: flex; flex-direction: column; overflow: hidden; }
.sb-hdr {
  display: flex; align-items: center; justify-content: space-between;
  padding: 7px 12px; background: var(--bg2); border-bottom: 1px solid var(--border);
  font-size: 10px; font-weight: bold; text-transform: uppercase; letter-spacing: .8px; color: var(--dim);
  flex-shrink: 0;
}
.sb-badge {
  background: var(--bg3); border: 1px solid var(--border);
  padding: 1px 7px; border-radius: 10px; font-size: 11px; color: var(--text); font-weight: normal;
}
#qcmd-wrap { flex-shrink: 0; display: none; }
#sidebar.cmd-mode #qcmd-wrap { display: block; }
#quickcmds { padding: 8px; display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid var(--border); }
.qcmd {
  background: var(--bg3); border: 1px solid var(--border); color: var(--dim);
  padding: 3px 9px; border-radius: 3px; cursor: pointer; font-size: 11px;
  font-family: inherit; transition: all .15s;
}
.qcmd:hover { border-color: var(--accent); color: var(--text); background: var(--bg2); }
#srv-info { padding: 8px 12px; font-size: 12px; border-bottom: 1px solid var(--border); }
.si { display: flex; justify-content: space-between; padding: 2px 0; }
.si-k { color: var(--dim); }
.si-v { color: var(--text); }

/* ── Map sidebar section ── */
#map-sidebar-section { display: none; flex-direction: column; flex-shrink: 0; }
#sidebar.map-mode #map-sidebar-section { display: flex; }
#map-sb-info { padding: 8px 12px; font-size: 12px; border-bottom: 1px solid var(--border); }
#map-filters { padding: 7px 12px; border-bottom: 1px solid var(--border); display: flex; flex-direction: column; gap: 1px; }
.mf-row {
  display: flex; align-items: center; gap: 8px;
  padding: 4px 2px; cursor: pointer; font-size: 12px; color: var(--dim);
  user-select: none; border-radius: 3px; transition: color .12s;
}
.mf-row:hover { color: var(--text); }
.mf-row input[type=checkbox] { cursor: pointer; accent-color: var(--accent); }
.mf-icon { width: 10px; height: 10px; flex-shrink: 0; display: inline-block; border-radius: 50%; }
.mf-diamond { border-radius: 1px; transform: rotate(45deg); }
.mf-triangle {
  width: 0; height: 0; background: transparent !important;
  border-left: 5px solid transparent; border-right: 5px solid transparent;
  border-bottom: 9px solid currentColor; /* overridden via style */
}
.mf-label { flex: 1; }
.mf-count { color: var(--dim); font-size: 11px; min-width: 16px; text-align: right; }
#player-list { flex: 1; overflow-y: auto; padding: 4px; }
.player {
  display: flex; align-items: center; justify-content: space-between;
  padding: 5px 8px; border-radius: 3px; cursor: pointer;
  border-left: 2px solid transparent; margin-bottom: 2px; transition: all .12s;
}
.player:hover { background: var(--bg3); border-left-color: var(--accent); }
.p-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
.p-ping { color: var(--dim); font-size: 11px; flex-shrink: 0; margin-left: 8px; }
.p-ping.g { color: var(--green); }
.p-ping.m { color: var(--yellow); }
.p-ping.b { color: var(--red); }

/* ── Players tab ── */
#panel-players { padding: 0; }
#pl-subtabs {
  display: flex; background: var(--bg2); border-bottom: 1px solid var(--border);
  padding: 0 12px; flex-shrink: 0;
}
.pl-stab {
  padding: 8px 16px; cursor: pointer; font-size: 12px; color: var(--dim);
  border-bottom: 2px solid transparent; transition: all .15s; user-select: none;
}
.pl-stab:hover { color: var(--text); }
.pl-stab.active { color: var(--accent); border-bottom-color: var(--accent); }
.pl-stab-badge {
  display: inline-block; background: var(--accent); color: #fff;
  font-size: 9px; font-weight: bold; padding: 1px 5px; border-radius: 8px;
  margin-left: 5px; min-width: 16px; text-align: center;
}
#pl-banned-wrap { flex: 1; overflow-y: auto; }
#pl-banned-table { width: 100%; border-collapse: collapse; font-size: 12px; table-layout: fixed; }
#pl-banned-table th {
  padding: 7px 10px; text-align: left; color: var(--dim); font-size: 11px;
  font-weight: normal; border-bottom: 1px solid var(--border);
  background: var(--bg2); position: sticky; top: 0;
}
#pl-banned-table col.col-sid    { width: 155px; }
#pl-banned-table col.col-name   { width: 22%; }
#pl-banned-table col.col-reason { }
#pl-banned-table col.col-act    { width: 72px; }
#pl-banned-table td { padding: 7px 10px; border-bottom: 1px solid rgba(46,49,56,.5); vertical-align: middle; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#pl-banned-table tr:hover td { background: rgba(255,255,255,.02); }
#pl-banned-table td.col-reason { white-space: normal; word-break: break-word; }
.ban-unban {
  background: none; border: 1px solid var(--border); color: var(--dim);
  font-family: inherit; font-size: 11px; padding: 3px 9px; border-radius: 4px;
  cursor: pointer; transition: all .15s;
}
.ban-unban:hover { border-color: var(--green); color: var(--green); }
#pl-toolbar {
  display: flex; align-items: center; gap: 8px; padding: 8px 12px;
  background: var(--bg2); border-bottom: 1px solid var(--border); flex-shrink: 0;
}
#pl-search {
  flex: 1; background: var(--bg3); border: 1px solid var(--border);
  color: var(--text); padding: 5px 10px; border-radius: 4px; font-family: inherit;
  font-size: 12px; outline: none; transition: border-color .15s;
}
#pl-search:focus { border-color: var(--accent); }
#pl-refresh { background: var(--bg3); border: 1px solid var(--border); color: var(--dim); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px; transition: all .15s; }
#pl-refresh:hover { border-color: var(--accent); color: var(--accent); }
#pl-count { color: var(--dim); font-size: 11px; white-space: nowrap; }
#pl-scroll { flex: 1; overflow-y: auto; }
#pl-table { width: 100%; border-collapse: collapse; font-size: 12px; }
#pl-table th {
  position: sticky; top: 0; background: var(--bg2); border-bottom: 1px solid var(--border);
  padding: 7px 10px; text-align: left; font-size: 10px; text-transform: uppercase;
  letter-spacing: .6px; color: var(--dim); cursor: pointer; user-select: none; white-space: nowrap;
}
#pl-table th:hover { color: var(--text); }
#pl-table th.sort-asc::after  { content: ' ▲'; }
#pl-table th.sort-desc::after { content: ' ▼'; }
#pl-table td { padding: 6px 10px; border-bottom: 1px solid rgba(46,49,56,.5); vertical-align: middle; }
.pl-row { cursor: pointer; transition: background .1s; }
.pl-row:hover td { background: var(--bg3); }
.pl-row.online td { background: rgba(76,175,80,.04); }
.pl-row.online:hover td { background: rgba(76,175,80,.08); }
.pl-row.expanded td { background: var(--bg3); }
.pl-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--dim); display: inline-block; flex-shrink: 0; }
.pl-dot.on { background: var(--green); box-shadow: 0 0 5px var(--green); }
.pl-name { font-weight: bold; }
.pl-row.online .pl-name { color: var(--green); }
.pl-sid { color: var(--dim); font-size: 11px; font-family: monospace; cursor: pointer; }
.pl-sid:hover { color: var(--blue); text-decoration: underline; }
.pl-ping.g { color: var(--green); }
.pl-ping.m { color: var(--yellow); }
.pl-ping.b { color: var(--red); }
.pl-sessions-row td { padding: 0; background: var(--bg3) !important; }
.pl-sessions-inner { padding: 8px 16px 10px 36px; }
.pl-sessions-hdr { font-size: 10px; text-transform: uppercase; letter-spacing: .6px; color: var(--dim); margin-bottom: 6px; }
.pl-sess-list { display: flex; flex-direction: column; gap: 3px; max-height: 220px; overflow-y: auto; }
.pl-sess { display: flex; gap: 16px; font-size: 11px; color: var(--dim); padding: 2px 0; }
.pl-sess-n { color: var(--dim); min-width: 28px; }
.pl-sess-date { color: var(--text); }
.pl-sess-dur { color: var(--blue); }
.pl-empty { text-align: center; padding: 40px; color: var(--dim); }

/* ── Player menu ── */
#pmenu {
  position: fixed; z-index: 500; background: var(--bg2);
  border: 1px solid var(--border); border-radius: 5px; padding: 4px 0;
  min-width: 170px; box-shadow: 0 6px 20px rgba(0,0,0,.5); font-size: 12px;
}
.pmi {
  padding: 7px 14px; cursor: pointer; color: var(--text);
  transition: background .1s; display: flex; align-items: center; gap: 8px;
}
.pmi:hover { background: var(--bg3); }
.pmi.danger { color: var(--red); }
.pmi.sep { border-top: 1px solid var(--border); margin-top: 3px; padding-top: 7px; }
.pmi-ico { width: 14px; text-align: center; font-size: 11px; opacity: .7; }

/* ── Modal ── */
#modal-overlay {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0,0,0,.65); display: flex; align-items: center; justify-content: center;
}
#modal-box {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 22px 24px; min-width: 320px;
  box-shadow: 0 8px 30px rgba(0,0,0,.6);
}
#modal-box h3 { color: var(--accent); margin-bottom: 16px; font-size: 14px; }
.modal-field { margin-bottom: 12px; }
.modal-field label { display: block; color: var(--dim); font-size: 11px; margin-bottom: 5px; }
.modal-input {
  width: 100%; background: var(--bg3); border: 1px solid var(--border);
  color: var(--text); padding: 7px 10px; border-radius: 4px;
  font-family: inherit; font-size: 13px; outline: none; transition: border-color .2s;
}
.modal-input:focus { border-color: var(--accent); }
.modal-btns { display: flex; gap: 8px; margin-top: 18px; }
.modal-btn {
  flex: 1; padding: 8px; border-radius: 4px; cursor: pointer;
  font-weight: bold; font-family: inherit; font-size: 13px; border: none; transition: opacity .15s;
}
.modal-btn:hover { opacity: .85; }
.modal-btn.primary { background: var(--red); color: #fff; }
.modal-btn.secondary { background: var(--bg3); color: var(--text); border: 1px solid var(--border); }
.modal-btn.ok { background: var(--accent); color: #111; }
#give-search { margin-bottom: 6px; }
#give-select {
  width: 100%; height: 170px; background: var(--bg3); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-family: inherit; font-size: 12px; outline: none;
}
#give-select:focus { border-color: var(--accent); }
#give-select optgroup { color: var(--dim); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }
#give-select option { color: var(--text); padding: 2px 4px; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #444; }

/* ── Login overlay ── */
#login-overlay {
  position: fixed; inset: 0; z-index: 2000;
  background: rgba(0,0,0,.88); backdrop-filter: blur(6px);
  display: flex; align-items: center; justify-content: center;
}
#login-overlay.hidden { display: none; }
#login-card {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
  width: 680px; max-width: calc(100vw - 32px); max-height: calc(100vh - 40px);
  display: flex; flex-direction: column; overflow: hidden;
  box-shadow: 0 20px 60px rgba(0,0,0,.7);
}
#login-hdr {
  padding: 18px 22px 14px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px; flex-shrink: 0;
}
#login-hdr-title { color: var(--accent); font-size: 16px; font-weight: bold; }
#login-hdr-sub { color: var(--dim); font-size: 11px; margin-left: auto; }
#login-close-btn {
  background: none; border: none; color: var(--dim); font-size: 18px; cursor: pointer;
  padding: 2px 6px; border-radius: 4px; transition: all .15s; line-height: 1;
}
#login-close-btn:hover { color: var(--text); background: var(--bg3); }
#login-body { display: flex; overflow: hidden; flex: 1; min-height: 0; }
#login-profiles-panel {
  width: 210px; min-width: 210px; flex-shrink: 0; border-right: 1px solid var(--border);
  display: flex; flex-direction: column; overflow: hidden;
}
#login-profiles-hdr {
  padding: 12px 14px 6px; font-size: 10px; color: var(--dim);
  text-transform: uppercase; letter-spacing: .07em; flex-shrink: 0;
}
#login-profiles-list { overflow-y: auto; flex: 1; }
.lp-item {
  padding: 10px 14px; cursor: pointer; border-left: 3px solid transparent;
  transition: background .12s, border-color .12s; user-select: none;
  display: flex; align-items: center; gap: 6px;
}
.lp-item:hover { background: var(--bg3); }
.lp-item.active { border-left-color: var(--accent); background: var(--bg3); }
.lp-info { flex: 1; min-width: 0; }
.lp-name { font-size: 12px; font-weight: bold; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.lp-host { font-size: 10px; color: var(--dim); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.lp-del {
  opacity: 0; color: var(--dim); font-size: 13px; padding: 3px 5px;
  border-radius: 3px; transition: all .12s; flex-shrink: 0; background: none; border: none; cursor: pointer;
}
.lp-item:hover .lp-del { opacity: 1; }
.lp-del:hover { color: var(--red); background: rgba(239,68,68,.12); }
#login-new-btn {
  margin: 8px; padding: 8px 12px; border: 1px dashed var(--border); border-radius: 6px;
  color: var(--dim); font-size: 12px; text-align: center; cursor: pointer;
  transition: all .15s; flex-shrink: 0; user-select: none;
}
#login-new-btn:hover { border-color: var(--accent); color: var(--accent); }
#login-form {
  flex: 1; padding: 20px 24px; overflow-y: auto; display: flex;
  flex-direction: column; gap: 14px;
}
.lf-label { font-size: 10px; color: var(--dim); text-transform: uppercase; letter-spacing: .07em; margin-bottom: 5px; }
.lf-input {
  width: 100%; background: var(--bg3); border: 1px solid var(--border); color: var(--text);
  padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 13px;
  outline: none; transition: border-color .2s;
}
.lf-input:focus { border-color: var(--accent); }
.lf-row-inline { display: flex; gap: 12px; }
.lf-row-inline > div { display: flex; flex-direction: column; }
#lf-host-wrap { flex: 1; }
#lf-port-wrap { flex: 0 0 100px; }
#login-connect-btn {
  padding: 10px; border: none; border-radius: 6px; background: var(--accent);
  color: #fff; font-weight: bold; font-family: inherit; font-size: 14px;
  cursor: pointer; transition: background .2s; margin-top: 2px;
}
#login-connect-btn:hover:not(:disabled) { background: var(--accent2); }
#login-connect-btn:disabled { opacity: .5; cursor: not-allowed; }
#login-save-btn {
  padding: 8px; border: 1px solid var(--border); border-radius: 6px;
  background: transparent; color: var(--dim); font-family: inherit; font-size: 12px;
  cursor: pointer; transition: all .2s;
}
#login-save-btn:hover { border-color: var(--accent); color: var(--text); }
#login-status { font-size: 12px; color: var(--dim); text-align: center; min-height: 16px; }
/* ── Settings modal ── */
#settings-overlay {
  position: fixed; inset: 0; z-index: 2000;
  background: rgba(0,0,0,.75); backdrop-filter: blur(4px);
  display: flex; align-items: center; justify-content: center;
}
#settings-overlay.hidden { display: none; }
#settings-card {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
  width: 420px; max-width: calc(100vw - 32px);
  box-shadow: 0 20px 60px rgba(0,0,0,.7); overflow: hidden;
}
#settings-hdr {
  display: flex; align-items: center; justify-content: space-between;
  padding: 16px 20px; border-bottom: 1px solid var(--border);
}
#settings-hdr-title { font-size: 14px; font-weight: bold; color: var(--text); }
#settings-close {
  background: none; border: none; color: var(--dim); font-size: 18px;
  cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: all .15s; line-height: 1;
}
#settings-close:hover { color: var(--text); background: var(--bg3); }
#settings-body { padding: 20px; display: flex; flex-direction: column; gap: 16px; }
.settings-section-title {
  font-size: 10px; color: var(--dim); text-transform: uppercase;
  letter-spacing: .07em; margin-bottom: 12px;
}
.settings-field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 12px; }
.settings-label { font-size: 11px; color: var(--dim); }
.settings-input {
  background: var(--bg3); border: 1px solid var(--border); color: var(--text);
  padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 13px;
  outline: none; transition: border-color .2s;
}
.settings-input:focus { border-color: var(--accent); }
#settings-save-pwd {
  padding: 9px; border: none; border-radius: 6px; background: var(--accent);
  color: #fff; font-weight: bold; font-family: inherit; font-size: 13px;
  cursor: pointer; transition: background .2s; width: 100%;
}
#settings-save-pwd:hover { background: var(--accent2); }
#settings-msg { font-size: 12px; text-align: center; min-height: 16px; }

/* ── About modal ── */
#about-overlay {
  position: fixed; inset: 0; z-index: 2000;
  background: rgba(0,0,0,.75); backdrop-filter: blur(4px);
  display: flex; align-items: center; justify-content: center;
}
#about-overlay.hidden { display: none; }
#about-card {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
  width: 380px; max-width: calc(100vw - 32px);
  box-shadow: 0 20px 60px rgba(0,0,0,.7); overflow: hidden;
}
#about-hdr {
  display: flex; align-items: center; justify-content: space-between;
  padding: 16px 20px; border-bottom: 1px solid var(--border);
}
#about-hdr-title { font-size: 14px; font-weight: bold; color: var(--text); }
#about-close {
  background: none; border: none; color: var(--dim); font-size: 18px;
  cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: all .15s; line-height: 1;
}
#about-close:hover { color: var(--text); background: var(--bg3); }
#about-body { padding: 20px; display: flex; flex-direction: column; gap: 0; }
.about-skull {
  text-align: center; font-size: 32px; margin-bottom: 10px;
  animation: skull-bob 3s ease-in-out infinite;
}
@keyframes skull-bob {
  0%, 100% { transform: translateY(0); }
  50%       { transform: translateY(-4px); }
}
.about-name {
  text-align: center; font-size: 15px; font-weight: bold;
  color: var(--text); margin-bottom: 2px;
}
.about-tagline {
  text-align: center; font-size: 11px; color: var(--dim); margin-bottom: 18px;
}
.about-rows { display: flex; flex-direction: column; gap: 8px; }
.about-row {
  display: flex; justify-content: space-between; align-items: center;
  font-size: 12px; padding: 7px 10px; border-radius: 6px; background: var(--bg3);
}
.about-row-label { color: var(--dim); }
.about-row-val   { color: var(--text); font-family: monospace; }
.about-footer {
  margin-top: 18px; text-align: center;
}
.about-footer a {
  font-size: 11px; color: var(--accent); text-decoration: none;
}
.about-footer a:hover { text-decoration: underline; }

/* ── Oxide tab ─────────────────────────────────────────────────────────────── */
#oxide-toolbar {
  display: flex; align-items: center; gap: 8px; padding: 8px 10px;
  border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap;
}
#oxide-toolbar button {
  background: var(--bg2); border: 1px solid var(--border); color: var(--text);
  font-family: inherit; font-size: 12px; padding: 4px 10px; border-radius: 4px;
  cursor: pointer; transition: all .15s;
}
#oxide-toolbar button:hover { border-color: var(--accent); color: var(--accent); }
#oxide-toolbar button:disabled { opacity: .4; cursor: default; }
#oxide-version { font-size: 11px; color: var(--dim); margin-left: auto; }
#oxide-status-msg { font-size: 11px; color: var(--dim); }
#oxide-scroll { flex: 1; overflow-y: auto; }
#oxide-table { width: 100%; border-collapse: collapse; font-size: 12px; }
#oxide-table th {
  text-align: left; padding: 5px 10px; border-bottom: 1px solid var(--border);
  color: var(--dim); font-weight: 500; font-size: 11px; white-space: nowrap;
  position: sticky; top: 0; background: var(--bg); z-index: 1;
}
#oxide-table td { padding: 5px 10px; border-bottom: 1px solid #22252d; vertical-align: middle; }
#oxide-table tr:hover td { background: var(--bg2); }
.ox-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--green); }
.ox-act {
  background: none; border: 1px solid var(--border); color: var(--dim);
  font-family: inherit; font-size: 10px; padding: 2px 7px; border-radius: 3px;
  cursor: pointer; transition: all .15s; white-space: nowrap;
}
.ox-act:hover { border-color: var(--accent); color: var(--accent); }
.ox-act.unload:hover { border-color: var(--red); color: var(--red); }
.ox-act.update { border-color: var(--green); color: var(--green); }
.ox-act.update:hover { background: rgba(76,175,80,.1); }
.ox-act.ext-link { text-decoration: none; display: inline-block; }
.ox-upd-badge { font-size: 10px; color: var(--yellow); margin-left: 5px; }
.ox-up-to-date { font-size: 10px; color: var(--green); margin-left: 5px; }

/* switch server + logout buttons in header */
#hdr-switch, #hdr-settings, #hdr-about, #hdr-logout {
  background: none; border: 1px solid var(--border); color: var(--dim);
  font-family: inherit; font-size: 11px; padding: 4px 10px; border-radius: 4px;
  cursor: pointer; transition: all .15s; white-space: nowrap; text-decoration: none;
}
#hdr-switch:hover, #hdr-settings:hover, #hdr-about:hover { border-color: var(--accent); color: var(--text); }
#hdr-logout:hover { border-color: var(--red); color: var(--red); }
#hdr-logout.hidden { display: none; }
</style>
</head>
<body>

<!-- Login / Server selection overlay -->
<div id="login-overlay">
  <div id="login-card">
    <div id="login-hdr">
      <svg width="20" height="20" viewBox="0 0 32 36" fill="none" xmlns="http://www.w3.org/2000/svg"><ellipse cx="16" cy="13" rx="11" ry="11" fill="#cd4214"/><circle cx="11.5" cy="12" r="2.8" fill="#1a1c20"/><circle cx="20.5" cy="12" r="2.8" fill="#1a1c20"/><rect x="10" y="22" width="12" height="2" rx="1" fill="#1a1c20" opacity=".35"/><rect x="11.5" y="24" width="3" height="7" rx="1.5" fill="#cd4214"/><rect x="17.5" y="24" width="3" height="7" rx="1.5" fill="#cd4214"/><rect x="9" y="30" width="14" height="2.5" rx="1.2" fill="#cd4214" opacity=".4"/></svg>
      <span id="login-hdr-title">RCON Panel</span>
      <span id="login-hdr-sub">Connect to a Rust server</span>
      <button id="login-close-btn" onclick="loginClose()" title="Close">✕</button>
    </div>
    <div id="login-body">
      <div id="login-profiles-panel">
        <div id="login-profiles-hdr">Saved Profiles</div>
        <div id="login-profiles-list"></div>
        <div id="login-new-btn" onclick="loginNewProfile()">+ New Connection</div>
      </div>
      <div id="login-form">
        <div>
          <div class="lf-label">Profile Name <span style="color:var(--dim);font-size:10px;text-transform:none">(optional)</span></div>
          <input class="lf-input" id="lf-name" placeholder="e.g. Main Server" autocomplete="off">
        </div>
        <div class="lf-row-inline">
          <div id="lf-host-wrap">
            <div class="lf-label">Host / IP</div>
            <input class="lf-input" id="lf-host" placeholder="192.168.1.100" autocomplete="off">
          </div>
          <div id="lf-port-wrap">
            <div class="lf-label">RCON Port</div>
            <input class="lf-input" id="lf-port" type="number" value="28016" min="1" max="65535" autocomplete="off">
          </div>
        </div>
        <div>
          <div class="lf-label">RCON Password</div>
          <input class="lf-input" id="lf-pass" type="password" placeholder="••••••••" autocomplete="new-password">
        </div>
        <button id="login-connect-btn" onclick="loginConnect()">Connect</button>
        <button id="login-save-btn" onclick="loginSaveProfile()">Save Profile</button>
        <div id="login-status"></div>
      </div>
    </div>
  </div>
</div>

<!-- Settings modal -->
<div id="settings-overlay" class="hidden">
  <div id="settings-card">
    <div id="settings-hdr">
      <span id="settings-hdr-title">&#9881; Settings</span>
      <button id="settings-close" onclick="hideSettings()">✕</button>
    </div>
    <div id="settings-body">
      <div>
        <div class="settings-section-title">Change Panel Password</div>
        <div class="settings-field">
          <label class="settings-label">Current Password</label>
          <input class="settings-input" id="set-pwd-cur" type="password" autocomplete="current-password">
        </div>
        <div class="settings-field">
          <label class="settings-label">New Password</label>
          <input class="settings-input" id="set-pwd-new" type="password" autocomplete="new-password">
        </div>
        <div class="settings-field">
          <label class="settings-label">Confirm New Password</label>
          <input class="settings-input" id="set-pwd-confirm" type="password" autocomplete="new-password">
        </div>
        <button id="settings-save-pwd" onclick="settingsSavePassword()">Save Password</button>
        <div id="settings-msg" style="margin-top:10px"></div>
      </div>
    </div>
  </div>
</div>

<!-- About modal -->
<div id="about-overlay" class="hidden">
  <div id="about-card">
    <div id="about-hdr">
      <span id="about-hdr-title">&#9432; About</span>
      <button id="about-close" onclick="hideAbout()">✕</button>
    </div>
    <div id="about-body">
      <div class="about-skull">☠</div>
      <div class="about-name">Rust RCON Panel</div>
      <div class="about-tagline">Self-hosted web management for Rust dedicated servers</div>
      <div class="about-rows">
        <div class="about-row"><span class="about-row-label">Panel version</span><span class="about-row-val" id="ab-version">—</span></div>
        <div class="about-row"><span class="about-row-label">Python</span><span class="about-row-val" id="ab-python">—</span></div>
        <div class="about-row"><span class="about-row-label">aiohttp</span><span class="about-row-val" id="ab-aiohttp">—</span></div>
        <div class="about-row"><span class="about-row-label">Platform</span><span class="about-row-val" id="ab-platform">—</span></div>
      </div>
      <div class="about-footer">
        <a id="ab-github" href="https://github.com/username-mendoza/rust-rcon-panel" target="_blank" rel="noopener">&#128279; GitHub</a>
      </div>
    </div>
  </div>
</div>

<div id="header">
  <div id="hdr-logo"><svg width="22" height="24" viewBox="0 0 32 36" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align:-5px;margin-right:5px"><ellipse cx="16" cy="13" rx="11" ry="11" fill="#4fc3f7"/><circle cx="11.5" cy="12" r="2.8" fill="#1a1c20"/><circle cx="20.5" cy="12" r="2.8" fill="#1a1c20"/><rect x="10" y="22" width="12" height="2" rx="1" fill="#1a1c20" opacity=".35"/><rect x="11.5" y="24" width="3" height="7" rx="1.5" fill="#4fc3f7"/><rect x="17.5" y="24" width="3" height="7" rx="1.5" fill="#4fc3f7"/><rect x="9" y="30" width="14" height="2.5" rx="1.2" fill="#4fc3f7" opacity=".4"/></svg>RCON</div>
  <div id="hdr-server">Connecting...</div>
  <button id="hdr-switch" onclick="showLoginOverlay()" title="Switch server">⇄ Switch Server</button>
  <button id="hdr-settings" onclick="showSettings()" title="Settings">&#9881; Settings</button>
  <button id="hdr-about" onclick="showAbout()" title="About">&#9432; About</button>
  <a id="hdr-logout" href="/logout" title="Sign out">⏻ Logout</a>
  <div id="hdr-status" class="err">
    <div id="status-dot"></div>
    <span id="status-txt">Disconnected</span>
  </div>
</div>

<div id="app">
  <div id="left">
    <!-- Unified tab bar -->
    <div id="tabbar">
      <div class="tab active" id="t-console" onclick="switchTab('console')">Console</div>
      <div class="tab" id="t-chat" onclick="switchTab('chat')">Chat<span class="tbadge" id="chat-badge"></span></div>
      <div class="tab" id="t-map" onclick="switchTab('map')">Map</div>
      <div class="tab" id="t-players" onclick="switchTab('players')">Players<span class="tbadge" id="players-badge"></span></div>
      <div class="tab" id="t-oxide" onclick="switchTab('oxide')">Oxide</div>
    </div>

    <!-- Console panel -->
    <div class="panel active" id="panel-console">
      <div id="console"></div>
      <div id="cmd-bar">
        <div id="cmd-pfx">&gt;</div>
        <input id="cmd-in" type="text" placeholder="Enter RCON command..." disabled autocomplete="off" spellcheck="false">
        <button id="clear-btn">Clear</button>
        <button id="ascroll-btn" class="on" onclick="toggleAscroll()" title="Toggle auto-scroll to bottom">
          <span id="ascroll-dot"></span>Auto
        </button>
        <button id="cmd-go" disabled>Send</button>
      </div>
    </div>

    <!-- Chat panel -->
    <div class="panel" id="panel-chat">
      <div id="chat-log"></div>
      <div id="chat-bar">
        <span id="chat-pfx">[SERVER]</span>
        <input id="chat-in" type="text" placeholder="Send message as server..." disabled autocomplete="off" spellcheck="false">
        <button id="chat-go" disabled>Say</button>
      </div>
    </div>

    <!-- Map panel -->
    <div class="panel" id="panel-map">
      <div id="map-toolbar">
        <button id="map-refresh" onclick="refreshMap()">&#8635; Players</button>
        <button id="map-rerender" onclick="rerenderMap()" title="Re-render map image via MapRenderer plugin">&#128247; Re-render</button>
        <button id="map-resetview" onclick="resetView()" title="Reset zoom and pan (or double-click map)">&#8982; Reset</button>
        <span id="map-player-count">0 players</span>
        <span id="map-coords"></span>
        <a id="map-rmlink" href="https://rustmaps.com" target="_blank"
           style="color:var(--dim);font-size:11px;text-decoration:none;padding:2px 6px;border:1px solid var(--border);border-radius:3px;transition:color .15s"
           onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--dim)'"
           title="Find your map image URL on rustmaps.com">rustmaps.com ↗</a>
        <span id="map-updated"></span>
      </div>
      <div id="map-canvas-wrap">
        <canvas id="map-canvas"></canvas>
        <div id="map-tooltip">
          <div class="tt-name"></div>
          <div class="tt-grid"></div>
          <div class="tt-id"></div>
        </div>
        <div id="map-infobar"></div>
      </div>
    </div>

    <!-- Players tab -->
    <div class="panel" id="panel-players">
      <div id="pl-subtabs">
        <div class="pl-stab active" id="pst-online"  onclick="switchPlSubtab('online')">Online</div>
        <div class="pl-stab"        id="pst-history" onclick="switchPlSubtab('history')">History</div>
        <div class="pl-stab"        id="pst-banned"  onclick="switchPlSubtab('banned')">Banned</div>
      </div>
      <div id="pl-toolbar">
        <input id="pl-search" type="text" placeholder="Search players..." oninput="renderPlayersTable()">
        <span id="pl-count"></span>
        <button id="pl-refresh" onclick="plRefresh()">&#8635; Refresh</button>
      </div>
      <div id="pl-scroll">
        <table id="pl-table">
          <thead>
            <tr>
              <th style="width:14px"></th>
              <th onclick="plSort('name')">Name</th>
              <th onclick="plSort('id')">Steam ID</th>
              <th onclick="plSort('total_seconds')">Playtime</th>
              <th onclick="plSort('session_count')">Sessions</th>
              <th onclick="plSort('first_seen')">First Seen</th>
              <th onclick="plSort('last_seen')">Last Seen</th>
              <th>Ping</th>
            </tr>
          </thead>
          <tbody id="pl-tbody"></tbody>
        </table>
      </div>
      <div id="pl-banned-wrap" style="display:none">
        <table id="pl-banned-table">
          <colgroup>
            <col class="col-sid"><col class="col-name"><col class="col-reason"><col class="col-act">
          </colgroup>
          <thead><tr>
            <th>Steam ID</th><th>Name</th><th>Reason / Notes</th><th></th>
          </tr></thead>
          <tbody id="pl-banned-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- Oxide tab -->
    <div class="panel" id="panel-oxide">
      <div id="oxide-toolbar">
        <button id="oxide-reload-all-btn" onclick="oxideReloadAll()">&#8635; Reload All</button>
        <button id="oxide-refresh-btn" onclick="loadOxideTab(true)">&#8635; Refresh</button>
        <button id="oxide-updates-btn" onclick="oxideCheckUpdates()">&#8593; Check Updates</button>
        <span id="oxide-status-msg"></span>
        <span id="oxide-version"></span>
      </div>
      <div id="oxide-scroll">
        <table id="oxide-table">
          <thead><tr>
            <th style="width:14px"></th>
            <th>Plugin</th>
            <th>Version</th>
            <th>Author</th>
            <th>Description</th>
            <th style="min-width:130px"></th>
          </tr></thead>
          <tbody id="oxide-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Sidebar -->
  <div id="sidebar" class="cmd-mode">
    <div id="qcmd-wrap">
      <div class="sb-hdr">Quick Commands</div>
      <div id="quickcmds">
        <button class="qcmd" onclick="sc('status')">status</button>
        <button class="qcmd" onclick="sc('playerlist')">players</button>
        <button class="qcmd" onclick="sc('save')">save</button>
        <button class="qcmd" onclick="sc('server.fps')">fps</button>
        <button class="qcmd" onclick="sc('gc.collect')">gc</button>
        <button class="qcmd" onclick="sc('net.stats')">net stats</button>
        <button class="qcmd" onclick="sc('oxide.reload *')">reload all</button>
        <button class="qcmd" onclick="sc('oxide.plugins')">plugins</button>
        <button class="qcmd" onclick="sc('global.ban')">ban...</button>
        <button class="qcmd" onclick="sc('server.stop')">stop</button>
      </div>
    </div>

    <!-- Map-specific sidebar (shown only in map tab) -->
    <div id="map-sidebar-section">
      <div class="sb-hdr">Map</div>
      <div id="map-sb-info">
        <div class="si"><span class="si-k">World Size</span><span class="si-v" id="msi-size">--</span></div>
        <div class="si"><span class="si-k">Seed</span><span class="si-v" id="msi-seed">--</span></div>
        <div class="si"><span class="si-k">Monuments</span><span class="si-v" id="msi-total">--</span></div>
      </div>
      <div class="sb-hdr">Show Monuments</div>
      <div id="map-filters">
        <label class="mf-row"><input type="checkbox" checked data-tier="safe"><span class="mf-icon" style="background:#4caf50"></span><span class="mf-label">Safe Zone</span><span class="mf-count" id="mfc-safe"></span></label>
        <label class="mf-row"><input type="checkbox" checked data-tier="3"><span class="mf-icon mf-diamond" style="background:#ef4444"></span><span class="mf-label">Tier 3</span><span class="mf-count" id="mfc-3"></span></label>
        <label class="mf-row"><input type="checkbox" checked data-tier="2"><span class="mf-icon mf-diamond" style="background:#f97316"></span><span class="mf-label">Tier 2</span><span class="mf-count" id="mfc-2"></span></label>
        <label class="mf-row"><input type="checkbox" checked data-tier="1"><span class="mf-icon mf-diamond" style="background:#facc15"></span><span class="mf-label">Tier 1</span><span class="mf-count" id="mfc-1"></span></label>
        <label class="mf-row"><input type="checkbox" checked data-tier="water"><span class="mf-icon" style="background:#60a5fa"></span><span class="mf-label">Water</span><span class="mf-count" id="mfc-water"></span></label>
        <label class="mf-row"><input type="checkbox" checked data-tier="cave"><span class="mf-icon" style="background:#a78bfa"></span><span class="mf-label">Cave</span><span class="mf-count" id="mfc-cave"></span></label>
        <label class="mf-row"><input type="checkbox" checked data-tier="other"><span class="mf-icon" style="background:#888"></span><span class="mf-label">Other</span><span class="mf-count" id="mfc-other"></span></label>
      </div>
    </div>

    <div class="sb-hdr">Server Info</div>
    <div id="srv-info">
      <div class="si"><span class="si-k">Online</span><span class="si-v" id="si-pl">--</span></div>
      <div class="si"><span class="si-k">Joining</span><span class="si-v" id="si-joining">--</span></div>
      <div class="si"><span class="si-k">Sleeping</span><span class="si-v" id="si-sleeping">--</span></div>
      <div class="si"><span class="si-k">Map</span><span class="si-v" id="si-map">--</span></div>
      <div class="si"><span class="si-k">Game Time</span><span class="si-v" id="si-gametime">--</span></div>
      <div class="si"><span class="si-k">FPS</span><span class="si-v" id="si-fps">--</span></div>
      <div class="si"><span class="si-k">Memory</span><span class="si-v" id="si-mem">--</span></div>
    </div>

    <div class="sb-hdr">Players <span class="sb-badge" id="p-count">0</span></div>
    <div id="player-list"></div>
  </div>
</div>

<script>
'use strict';
/*__AUTH_ENABLED__*/
const $ = id => document.getElementById(id);

// Elements
const co    = $('console'),  ci = $('cmd-in'),   cb = $('cmd-go');
const chatL = $('chat-log'), ci2 = $('chat-in'), cb2 = $('chat-go');
const hs    = $('hdr-status'), ht = $('status-txt'), hsvr = $('hdr-server');

let ws, rconOk = false, hist = [], histIdx = -1;
let autoScroll = true, chatAutoScroll = true;
let activeTab = 'console', chatUnread = 0;

if (!AUTH_ENABLED) document.getElementById('hdr-logout').classList.add('hidden');

function setAutoScroll(on) {
  autoScroll = on;
  const btn = $('ascroll-btn');
  btn.className = on ? 'on' : 'off';
}
function toggleAscroll() {
  setAutoScroll(!autoScroll);
  if (autoScroll) co.scrollTop = co.scrollHeight;
}

// ── Tabs ───────────────────────────────────────────────────────────────────
const TABS = ['console', 'chat', 'map', 'players', 'oxide'];

function switchTab(name) {
  activeTab = name;
  TABS.forEach(t => {
    $('t-'+t).className    = 'tab' + (t === name ? ' active' : '');
    $('panel-'+t).className = 'panel' + (t === name ? ' active' : '');
  });
  if (name === 'chat') {
    chatUnread = 0;
    const b = $('chat-badge');
    b.textContent = ''; b.className = 'tbadge';
    chatL.scrollTop = chatL.scrollHeight;
  }
  $('sidebar').classList.toggle('map-mode', name === 'map');
  $('sidebar').classList.toggle('cmd-mode', name === 'console' || name === 'chat');
  if (name === 'map') {
    initMapIfNeeded();
    if (rconOk && Object.keys(mapPlayers).length === 0) refreshMap();
    // ResizeObserver fires automatically when panel becomes visible, triggering drawMap()
  }
  if (name === 'players') { if (plSubtab === 'banned') loadBannedTab(); else loadPlayersTab(); }
  if (name === 'oxide') loadOxideTab();
}

// ── Logging ────────────────────────────────────────────────────────────────
function ts() {
  return new Date().toLocaleTimeString('en-US', {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function autoClass(text) {
  const l = text.toLowerCase();
  if (/\b(joined|connected|spawned|joining)\b/.test(l)) return 'ok';
  if (/\b(leaving|disconnected|left|kicked|banned|timed out)\b/.test(l)) return 'warn';
  if (/\berror\b|exception|failed/i.test(l)) return 'err';
  return '';
}
function log(text, cls) {
  cls = cls || autoClass(String(text));
  const lines = String(text).split('\n');
  const f = document.createDocumentFragment();
  for (const line of lines) {
    if (!line.trim() && lines.length > 1) continue;
    const d = document.createElement('div');
    d.className = 'ln ' + cls;
    d.innerHTML = '<span class="ln-t">'+ts()+'</span><span class="ln-m">'+esc(line)+'</span>';
    f.appendChild(d);
  }
  co.appendChild(f);
  if (autoScroll) co.scrollTop = co.scrollHeight;
}

co.addEventListener('scroll', () => {
  const atBottom = co.scrollTop + co.clientHeight >= co.scrollHeight - 30;
  if (atBottom !== autoScroll) setAutoScroll(atBottom);
});
$('clear-btn').onclick = () => { co.innerHTML = ''; };

// ── Connection state ───────────────────────────────────────────────────────
function setOk(ok) {
  rconOk = ok;
  ci.disabled = ci2.disabled = !ok;
  cb.disabled = cb2.disabled = !ok;
  hs.className = ok ? 'ok' : 'err';
  ht.textContent = ok ? 'Connected' : 'Disconnected';
}

// ── RCON commands ──────────────────────────────────────────────────────────
function send(cmd) {
  cmd = (cmd || '').trim();
  if (!cmd || !rconOk) return;
  ws.send(JSON.stringify({type:'command', command:cmd}));
  log('> ' + cmd, 'sent');
  if (hist[0] !== cmd) hist.unshift(cmd);
  if (hist.length > 100) hist.pop();
  histIdx = -1;
  ci.value = '';
}
function sc(cmd) { send(cmd); }

// Silent background send — no console echo, no history entry
function sendBg(cmd) {
  if (!cmd || !rconOk) return;
  ws.send(JSON.stringify({type:'command', command:cmd}));
}

ci.addEventListener('keydown', e => {
  if (e.key==='Enter') { send(ci.value); return; }
  if (e.key==='ArrowUp')   { histIdx=Math.min(histIdx+1,hist.length-1); ci.value=hist[histIdx]||''; e.preventDefault(); }
  if (e.key==='ArrowDown') { histIdx=Math.max(histIdx-1,-1); ci.value=histIdx>=0?hist[histIdx]:''; e.preventDefault(); }
});
cb.onclick = () => send(ci.value);

// ── Chat ───────────────────────────────────────────────────────────────────
chatL.addEventListener('scroll', () => { chatAutoScroll = chatL.scrollTop + chatL.clientHeight >= chatL.scrollHeight - 24; });

function addChat(who, cls, text) {
  const d = document.createElement('div');
  d.className = 'cm';
  d.innerHTML = '<span class="cm-t">'+ts()+'</span>'
    +'<span class="cm-who '+cls+'">'+esc(who)+'</span>'
    +'<span class="cm-sep">:</span>'
    +'<span class="cm-text">'+esc(text)+'</span>';
  chatL.appendChild(d);
  if (chatAutoScroll) chatL.scrollTop = chatL.scrollHeight;
  if (activeTab !== 'chat') {
    chatUnread++;
    const b = $('chat-badge');
    b.textContent = chatUnread; b.className = 'tbadge show';
  }
}

function parseChat(msg) {
  try {
    const obj = JSON.parse(msg);
    if (obj && obj.Username !== undefined) {
      const isServer = obj.UserId === '0' || obj.UserId === 0;
      const chan = obj.Channel === 1 ? ' [Team]' : '';
      addChat((obj.Username||'?') + chan, isServer ? 'server' : 'player', obj.Message || '');
      return;
    }
  } catch(e) {}
  const sep = msg.indexOf(' : ');
  if (sep !== -1) {
    const who = msg.substring(0, sep).trim();
    addChat(who, who === 'SERVER' ? 'server' : 'player', msg.substring(sep+3).trim());
  } else {
    addChat('?', 'player', msg);
  }
}

ci2.addEventListener('keydown', e => { if (e.key==='Enter') sayMsg(); });
cb2.onclick = sayMsg;
function sayMsg() {
  const msg = ci2.value.trim();
  if (!msg || !rconOk) return;
  send('say ' + msg);
  ci2.value = '';
}

// ── Server info / player list ──────────────────────────────────────────────
function parseStatus(msg) {
  const set = (id, v) => { if (v != null) $(id).textContent = v; };
  const hn  = msg.match(/hostname\s*:\s*(.+)/i);                  if (hn)  hsvr.textContent = hn[1].trim();
  const pl  = msg.match(/players\s*:\s*(\d+)\s*\((\d+)\s*max/i); if (pl)  set('si-pl', pl[1]+' / '+pl[2]);
  const jn  = msg.match(/\((\d+)\s*joining\)/i);                  if (jn)  set('si-joining', jn[1]);
  const slp = msg.match(/\((\d+)\s*sleeping\)/i);                 if (slp) set('si-sleeping', slp[1]);
  const map = msg.match(/map\s*:\s*(.+)/i);                       if (map) set('si-map', map[1].trim().replace(/^"|"$/g,''));
  const fps = msg.match(/fps(?:\s+avg)?\s*[:\|]\s*([\d.]+)/i);   if (fps) set('si-fps', parseFloat(fps[1]).toFixed(1));
  const mem = msg.match(/(\d+)\s*mb/i);                           if (mem) set('si-mem', mem[1]+' MB');
}

function parsePlayers(msg) {
  const players = [];
  for (const line of msg.split('\n')) {
    const t = line.trim();
    const m = t.match(/^(\d{17})\s+"?([^"]+?)"?\s+(\d+)\s+/);
    if (m) { players.push({id:m[1],name:m[2].trim(),ping:parseInt(m[3])}); continue; }
    const m2 = t.match(/^(\d{17})\s+(\S+)/);
    if (m2) players.push({id:m2[1],name:m2[2],ping:null});
  }
  if (players.length > 0 || /SteamID/i.test(msg)) renderPlayers(players);
}

function renderPlayers(players) {
  $('p-count').textContent = players.length;
  if ($('si-pl').textContent === '--') $('si-pl').textContent = players.length;
  livePlayers = {};
  for (const p of players) livePlayers[p.id] = p;
  // Recalculate sleeping every playerlist update: location entries not in live list
  $('si-sleeping').textContent = Object.keys(mapPlayers).filter(id => !livePlayers[id]).length;
  // Keep Players tab badge current without requiring a tab visit
  const badge = $('players-badge');
  if (players.length > 0) { badge.textContent = players.length; badge.className = 'tbadge show'; }
  else { badge.textContent = ''; badge.className = 'tbadge'; }
  if (activeTab === 'players' && playersData) renderPlayersTable();
  const list = $('player-list');
  list.innerHTML = '';
  for (const p of players) {
    const div = document.createElement('div');
    div.className = 'player';
    let pc = '', ps = '?ms';
    if (p.ping !== null) { ps = p.ping+'ms'; pc = p.ping<80?'g':p.ping<150?'m':'b'; }
    div.innerHTML = '<span class="p-name" title="'+esc(p.id)+'">'+esc(p.name)+'</span><span class="p-ping '+pc+'">'+ps+'</span>';
    div.onclick = e => { e.stopPropagation(); showPlayerMenu(e, p); };
    list.appendChild(div);
  }
}

// ── Player menu ────────────────────────────────────────────────────────────
function closeMenu() { const m = $('pmenu'); if (m) m.remove(); }

function showPlayerMenu(e, p) {
  closeMenu();
  const menu = document.createElement('div');
  menu.id = 'pmenu';
  const items = [
    { ico:'⚡', label:'Kick',           action:()=>openModal('kick',p) },
    { ico:'🔨', label:'Ban...',          action:()=>openModal('ban',p), cls:'danger' },
    { ico:'🎁', label:'Give Item...',    action:()=>openGiveModal(p), sep:true },
    { ico:'🔇', label:'Mute',           action:()=>send('mute '+p.id), sep:true },
    { ico:'🔈', label:'Unmute',         action:()=>send('unmute '+p.id) },
    { ico:'✈',  label:'Teleport to me', action:()=>send('teleport2me '+p.id), sep:true },
    { ico:'📋', label:'Copy Steam ID', action:()=>{navigator.clipboard.writeText(p.id);log('Copied: '+p.id,'sys');}, sep:true },
    { ico:'🔗', label:'Steam Profile', action:()=>window.open('https://steamcommunity.com/profiles/'+p.id,'_blank') },
  ];
  for (const it of items) {
    const d = document.createElement('div');
    d.className = 'pmi'+(it.cls?' '+it.cls:'')+(it.sep?' sep':'');
    d.innerHTML = '<span class="pmi-ico">'+it.ico+'</span>'+esc(it.label);
    d.onclick = ev => { ev.stopPropagation(); it.action(); closeMenu(); };
    menu.appendChild(d);
  }
  document.body.appendChild(menu);
  const rect = menu.getBoundingClientRect();
  let x = e.clientX, y = e.clientY;
  if (x+rect.width  > window.innerWidth)  x = window.innerWidth  - rect.width  - 6;
  if (y+rect.height > window.innerHeight) y = window.innerHeight - rect.height - 6;
  menu.style.left = x+'px'; menu.style.top = y+'px';
  setTimeout(() => document.addEventListener('click', closeMenu, {once:true}), 0);
}

function openModal(action, p) {
  const overlay = document.createElement('div');
  overlay.id = 'modal-overlay';
  const isBan = action === 'ban';
  overlay.innerHTML = `<div id="modal-box">
    <h3>${isBan?'Ban':'Kick'} ${esc(p.name)}</h3>
    <div class="modal-field">
      <label>Reason</label>
      <input id="modal-reason" class="modal-input" placeholder="${isBan?'Cheating, toxicity...':'Rule violation...'}" autocomplete="off">
    </div>
    <div class="modal-btns">
      <button class="modal-btn primary" id="modal-ok">${isBan?'Ban':'Kick'}</button>
      <button class="modal-btn secondary" id="modal-cancel">Cancel</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  const rEl = $('modal-reason');
  rEl.focus();
  $('modal-cancel').onclick = () => overlay.remove();
  overlay.onclick = e => { if (e.target===overlay) overlay.remove(); };
  $('modal-ok').onclick = () => {
    const r = rEl.value.trim() || (isBan?'Banned by admin':'Kicked by admin');
    send(isBan ? `ban ${p.id} "${r}"` : `kick ${p.id} "${r}"`);
    overlay.remove();
  };
  rEl.addEventListener('keydown', e => {
    if (e.key==='Enter')  $('modal-ok').click();
    if (e.key==='Escape') overlay.remove();
  });
}

// ── Give Item ──────────────────────────────────────────────────────────────
const RUST_ITEMS = [
  // Resources
  {c:'Resources', n:'Wood',                  id:'wood'},
  {c:'Resources', n:'Stones',                id:'stones'},
  {c:'Resources', n:'Metal Fragments',       id:'metal.fragments'},
  {c:'Resources', n:'High Quality Metal',    id:'metal.refined'},
  {c:'Resources', n:'Sulfur',                id:'sulfur'},
  {c:'Resources', n:'Charcoal',              id:'charcoal'},
  {c:'Resources', n:'Low Grade Fuel',        id:'lowgradefuel'},
  {c:'Resources', n:'Crude Oil',             id:'crude.oil'},
  {c:'Resources', n:'Cloth',                 id:'cloth'},
  {c:'Resources', n:'Leather',               id:'leather'},
  {c:'Resources', n:'Animal Fat',            id:'fat.animal'},
  {c:'Resources', n:'Bone Fragments',        id:'bone.fragments'},
  {c:'Resources', n:'Scrap',                 id:'scrap'},
  {c:'Resources', n:'Metal Ore',             id:'metal.ore'},
  {c:'Resources', n:'Sulfur Ore',            id:'sulfur.ore'},
  // Weapons
  {c:'Weapons', n:'AK-47',                   id:'rifle.ak'},
  {c:'Weapons', n:'Bolt Action Rifle',       id:'rifle.bolt'},
  {c:'Weapons', n:'LR-300',                  id:'rifle.lr300'},
  {c:'Weapons', n:'M39 Rifle',               id:'rifle.m39'},
  {c:'Weapons', n:'Semi-Auto Rifle',         id:'rifle.semiauto'},
  {c:'Weapons', n:'MP5A4',                   id:'smg.mp5'},
  {c:'Weapons', n:'Thompson',                id:'smg.thompson'},
  {c:'Weapons', n:'Custom SMG',              id:'smg.2'},
  {c:'Weapons', n:'M92 Pistol',              id:'pistol.m92'},
  {c:'Weapons', n:'Python Revolver',         id:'pistol.python'},
  {c:'Weapons', n:'Revolver',                id:'pistol.revolver'},
  {c:'Weapons', n:'Eoka Pistol',             id:'pistol.eoka'},
  {c:'Weapons', n:'Nailgun',                 id:'pistol.nailgun'},
  {c:'Weapons', n:'Pump Shotgun',            id:'shotgun.pump'},
  {c:'Weapons', n:'SPAS-12',                 id:'shotgun.spas12'},
  {c:'Weapons', n:'Waterpipe Shotgun',       id:'shotgun.waterpipe'},
  {c:'Weapons', n:'Double Barrel Shotgun',   id:'shotgun.double'},
  {c:'Weapons', n:'M249',                    id:'lmg.m249'},
  {c:'Weapons', n:'Rocket Launcher',         id:'rocket.launcher'},
  {c:'Weapons', n:'Compound Bow',            id:'compound.bow'},
  {c:'Weapons', n:'Hunting Bow',             id:'bow.hunting'},
  {c:'Weapons', n:'Crossbow',                id:'crossbow'},
  {c:'Weapons', n:'Combat Knife',            id:'knife.combat'},
  {c:'Weapons', n:'Bone Knife',              id:'knife.bone'},
  {c:'Weapons', n:'Machete',                 id:'machete'},
  {c:'Weapons', n:'Salvaged Sword',          id:'salvaged.sword'},
  {c:'Weapons', n:'Longsword',               id:'longsword'},
  {c:'Weapons', n:'Mace',                    id:'mace'},
  {c:'Weapons', n:'Flamethrower',            id:'flamethrower'},
  {c:'Weapons', n:'Wooden Spear',            id:'spear.wooden'},
  {c:'Weapons', n:'Metal Spear',             id:'spear.metal'},
  // Ammo
  {c:'Ammo', n:'5.56 Rifle Ammo',            id:'ammo.rifle'},
  {c:'Ammo', n:'Explosive 5.56',             id:'ammo.rifle.explosive'},
  {c:'Ammo', n:'Incendiary 5.56',            id:'ammo.rifle.incendiary'},
  {c:'Ammo', n:'HV 5.56 Ammo',              id:'ammo.rifle.hv'},
  {c:'Ammo', n:'Pistol Ammo',                id:'ammo.pistol'},
  {c:'Ammo', n:'HV Pistol Ammo',             id:'ammo.pistol.hv'},
  {c:'Ammo', n:'Incendiary Pistol Ammo',     id:'ammo.pistol.fire'},
  {c:'Ammo', n:'12 Gauge Buckshot',          id:'ammo.shotgun'},
  {c:'Ammo', n:'12 Gauge Slug',              id:'ammo.shotgun.slug'},
  {c:'Ammo', n:'Handmade Shell',             id:'ammo.handmade.shell'},
  {c:'Ammo', n:'Rocket',                     id:'rocket.basic'},
  {c:'Ammo', n:'HV Rocket',                  id:'rocket.hv'},
  {c:'Ammo', n:'Incendiary Rocket',          id:'rocket.fire'},
  {c:'Ammo', n:'Smoke Rocket',               id:'rocket.smoke'},
  {c:'Ammo', n:'40mm HE Grenade',            id:'ammo.grenadelauncher'},
  {c:'Ammo', n:'40mm Smoke Grenade',         id:'ammo.grenadelauncher.smoke'},
  {c:'Ammo', n:'Wooden Arrow',               id:'arrow.wooden'},
  {c:'Ammo', n:'HV Arrow',                   id:'arrow.hv'},
  {c:'Ammo', n:'Fire Arrow',                 id:'arrow.fire'},
  // Explosives
  {c:'Explosives', n:'Timed Explosive (C4)',  id:'explosive.timed'},
  {c:'Explosives', n:'Satchel Charge',        id:'explosive.satchel'},
  {c:'Explosives', n:'F1 Grenade',            id:'grenade.f1'},
  {c:'Explosives', n:'Beancan Grenade',       id:'grenade.beancan'},
  {c:'Explosives', n:'Molotov Cocktail',      id:'grenade.molotov'},
  {c:'Explosives', n:'Survey Charge',         id:'surveycharge'},
  {c:'Explosives', n:'Explosives',            id:'explosives'},
  {c:'Explosives', n:'Land Mine',             id:'trap.landmine'},
  // Medical
  {c:'Medical', n:'Medical Syringe',          id:'syringe.medical'},
  {c:'Medical', n:'Bandage',                  id:'bandage'},
  {c:'Medical', n:'Large Medkit',             id:'largemedkit'},
  {c:'Medical', n:'Anti-Radiation Pills',     id:'antiradpills'},
  // Food
  {c:'Food', n:'Apple',                       id:'apple'},
  {c:'Food', n:'Blueberries',                 id:'blueberries'},
  {c:'Food', n:'Mushroom',                    id:'mushroom'},
  {c:'Food', n:'Corn',                        id:'corn'},
  {c:'Food', n:'Potato',                      id:'potato'},
  {c:'Food', n:'Pumpkin',                     id:'pumpkin'},
  {c:'Food', n:'Black Raspberries',           id:'black.raspberries'},
  {c:'Food', n:'Cooked Chicken',              id:'chicken.cooked'},
  {c:'Food', n:'Cooked Wolf Meat',            id:'wolfmeat.cooked'},
  {c:'Food', n:'Cooked Bear Meat',            id:'bearmeat.cooked'},
  {c:'Food', n:'Can of Tuna',                 id:'can.tuna'},
  {c:'Food', n:'Can of Beans',                id:'can.beans'},
  // Armor
  {c:'Armor', n:'Metal Facemask',             id:'metal.facemask'},
  {c:'Armor', n:'Metal Chest Plate',          id:'metal.plate.torso'},
  {c:'Armor', n:'Heavy Plate Helmet',         id:'heavy.plate.helmet'},
  {c:'Armor', n:'Heavy Plate Jacket',         id:'heavy.plate.jacket'},
  {c:'Armor', n:'Heavy Plate Pants',          id:'heavy.plate.pants'},
  {c:'Armor', n:'Riot Helmet',                id:'riot.helmet'},
  {c:'Armor', n:'Road Sign Helmet',           id:'roadsign.helmet'},
  {c:'Armor', n:'Road Sign Jacket',           id:'roadsign.jacket'},
  {c:'Armor', n:'Road Sign Kilt',             id:'roadsign.kilt'},
  {c:'Armor', n:'Wood Armor Helmet',          id:'wood.armor.helmet'},
  {c:'Armor', n:'Wood Armor Jacket',          id:'wood.armor.jacket'},
  {c:'Armor', n:'Wood Armor Pants',           id:'wood.armor.pants'},
  {c:'Armor', n:'Hazmat Suit',                id:'hazmatsuit'},
  // Clothing
  {c:'Clothing', n:'Hoodie',                  id:'hoodie'},
  {c:'Clothing', n:'Pants',                   id:'pants'},
  {c:'Clothing', n:'T-Shirt',                 id:'tshirt'},
  {c:'Clothing', n:'Jacket',                  id:'jacket'},
  {c:'Clothing', n:'Boots',                   id:'shoes.boots'},
  {c:'Clothing', n:'Burlap Shirt',            id:'burlap.shirt'},
  {c:'Clothing', n:'Burlap Trousers',         id:'burlap.trousers'},
  {c:'Clothing', n:'Burlap Headwrap',         id:'burlap.headwrap'},
  {c:'Clothing', n:'Burlap Shoes',            id:'burlap.shoes'},
  {c:'Clothing', n:'Hide Shirt',              id:'hide.shirt'},
  {c:'Clothing', n:'Hide Pants',              id:'hide.pants'},
  {c:'Clothing', n:'Hide Shoes',              id:'hide.shoes'},
  {c:'Clothing', n:'Hide Poncho',             id:'hide.poncho'},
  // Tools
  {c:'Tools', n:'Hammer',                     id:'hammer'},
  {c:'Tools', n:'Building Plan',              id:'building.planner'},
  {c:'Tools', n:'Chainsaw',                   id:'chainsaw'},
  {c:'Tools', n:'Salvaged Icepick',           id:'icepick.salvaged'},
  {c:'Tools', n:'Hatchet',                    id:'hatchet'},
  {c:'Tools', n:'Pickaxe',                    id:'pickaxe'},
  {c:'Tools', n:'Stone Hatchet',              id:'stonehatchet'},
  {c:'Tools', n:'Stone Pickaxe',              id:'stone.pickaxe'},
  {c:'Tools', n:'Jackhammer',                 id:'jackhammer'},
  {c:'Tools', n:'Torch',                      id:'torch'},
  // Components
  {c:'Components', n:'Gears',                 id:'gears'},
  {c:'Components', n:'Road Signs',            id:'roadsigns'},
  {c:'Components', n:'Metal Blade',           id:'metalblade'},
  {c:'Components', n:'Metal Spring',          id:'metalspring'},
  {c:'Components', n:'SMG Body',              id:'smgbody'},
  {c:'Components', n:'Rifle Body',            id:'riflebody'},
  {c:'Components', n:'Semi Automatic Body',   id:'semibody'},
  {c:'Components', n:'Tech Trash',            id:'techparts'},
  {c:'Components', n:'Tarp',                  id:'tarp'},
  {c:'Components', n:'Rope',                  id:'rope'},
  {c:'Components', n:'Sewing Kit',            id:'sewingkit'},
  {c:'Components', n:'Sheet Metal',           id:'sheetmetal'},
  {c:'Components', n:'CCTV Camera',           id:'cctv.camera'},
  {c:'Components', n:'Targeting Computer',    id:'targeting.computer'},
  // Misc
  {c:'Misc', n:'Supply Signal',               id:'supply.signal'},
  {c:'Misc', n:'Research Paper',              id:'researchpaper'},
  {c:'Misc', n:'Bear Trap',                   id:'trap.bear'},
  {c:'Misc', n:'Snap Trap',                   id:'trap.bear.trap'},
  {c:'Misc', n:'Flashlight',                  id:'flashlight.held'},
  {c:'Misc', n:'Small Stash',                 id:'stash.small'},
];

function openGiveModal(p) {
  const overlay = document.createElement('div');
  overlay.id = 'modal-overlay';
  overlay.innerHTML = `<div id="modal-box" style="width:320px">
    <h3>Give Item — ${esc(p.name)}</h3>
    <div class="modal-field">
      <label>Search</label>
      <input id="give-search" class="modal-input" placeholder="Filter items..." autocomplete="off">
    </div>
    <div class="modal-field" style="margin-top:8px">
      <label>Item</label>
      <select id="give-select" size="8"></select>
    </div>
    <div class="modal-field" style="margin-top:8px">
      <label>Amount</label>
      <input id="give-amount" class="modal-input" type="number" value="1" min="1" max="100000">
    </div>
    <div class="modal-btns">
      <button class="modal-btn ok" id="give-ok">Give</button>
      <button class="modal-btn secondary" id="give-cancel">Cancel</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);

  const sel = document.getElementById('give-select');
  const srch = document.getElementById('give-search');

  function populate(filter) {
    sel.innerHTML = '';
    const f = (filter || '').toLowerCase();
    let lastCat = null, grp = null;
    for (const item of RUST_ITEMS) {
      if (f && !item.n.toLowerCase().includes(f) && !item.id.includes(f)) continue;
      if (item.c !== lastCat) {
        grp = document.createElement('optgroup');
        grp.label = item.c;
        sel.appendChild(grp);
        lastCat = item.c;
      }
      const opt = document.createElement('option');
      opt.value = item.id;
      opt.textContent = item.n;
      grp.appendChild(opt);
    }
    if (sel.options.length) sel.selectedIndex = 0;
  }

  populate('');
  srch.addEventListener('input', () => populate(srch.value));

  document.getElementById('give-cancel').onclick = () => overlay.remove();
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
  srch.addEventListener('keydown', e => { if (e.key === 'Escape') overlay.remove(); });

  document.getElementById('give-ok').onclick = () => {
    const item = sel.value;
    const amt  = Math.max(1, parseInt(document.getElementById('give-amount').value) || 1);
    if (!item) return;
    send('inventory.give ' + p.id + ' ' + item + ' ' + amt);
    overlay.remove();
  };

  srch.focus();
}

// ── Map ────────────────────────────────────────────────────────────────────
let mapPlayers  = {};   // { steamid: {name, grid, x, z} }
let mapMonuments = [];  // [{name, x, z}, ...]
let mapImg = null;
let WORLD_SIZE = 4500;
let MAP_SEED = 0;
let MAP_IMG_CONFIGURED = false;
const MAP_BORDER = 500;  // ocean border around terrain (must match plugin BORDER)
let mapNeedsInit = true;
let mapImgRetries = 0;

// Pan/zoom state
let view = { scale: 1, ox: 0, oy: 0 };
let _drag = { active: false, sx: 0, sy: 0 };

// Players tab state
let livePlayers = {};   // { steamid: {name, ping} } — updated by playerlist poll
let playersData = null; // cached /api/players response
let plSortKey = 'last_seen', plSortAsc = false, _plLastFetch = 0;
let plSubtab = 'online';
let bansData = null, _bansLastFetch = 0;

function resetView() {
  view.scale = 1; view.ox = 0; view.oy = 0;
  drawMap();
}

// Monument tier visibility filters
const monFilters = { safe:true, '3':true, '2':true, '1':true, water:true, cave:true, other:true };
document.querySelectorAll('#map-filters input[type=checkbox]').forEach(cb => {
  cb.addEventListener('change', () => {
    monFilters[cb.dataset.tier] = cb.checked;
    drawMap();
  });
});

// ── Server clock ───────────────────────────────────────────────────────────

fetch('/api/cfg').then(r=>r.json()).then(c => {
  WORLD_SIZE = c.world_size || 4500;
  MAP_SEED = c.seed || 0;
  MAP_IMG_CONFIGURED = c.map_img_configured || false;
  if (MAP_SEED) $('map-rmlink').href = 'https://rustmaps.com/?seed='+MAP_SEED+'&size='+WORLD_SIZE;
  updateMapInfoBar();
  drawMap();
}).catch(()=>{});

function fetchWorldCfg() {
  fetch('/api/worldcfg').then(r => r.ok ? r.json() : null).then(c => {
    if (!c || c.error) return;
    if (c.seed != null)       { MAP_SEED   = c.seed; }
    if (c.world_size != null) { WORLD_SIZE = c.world_size; }
    if (MAP_SEED) $('map-rmlink').href = 'https://rustmaps.com/?seed='+MAP_SEED+'&size='+WORLD_SIZE;
    updateMapInfoBar();
    drawMap();
  }).catch(() => {});
}

function updateMapInfoBar() {
  // Bottom-left infobar on canvas
  const bar = $('map-infobar');
  if (bar) bar.innerHTML = (WORLD_SIZE ? 'Size: <b>' + WORLD_SIZE + 'm</b>' : '') +
    (MAP_SEED ? ' &nbsp;· Seed: <b>' + MAP_SEED + '</b>' : '');

  // Sidebar map info
  const setSI = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  setSI('msi-size',  WORLD_SIZE ? WORLD_SIZE + 'm' : '--');
  setSI('msi-seed',  MAP_SEED   ? MAP_SEED          : '--');
  setSI('msi-total', mapMonuments.length || '--');

  // Per-tier counts in filter rows
  const TIERS = ['safe','3','2','1','water','cave','other'];
  for (const t of TIERS) {
    const cnt = mapMonuments.filter(m => m.tier === t).length;
    const el  = $('mfc-' + t);
    if (el) el.textContent = cnt || '';
  }
}

// ResizeObserver keeps canvas pixel dimensions in sync with its container
new ResizeObserver(entries => {
  const r = entries[0].contentRect;
  const canvas = $('map-canvas');
  canvas.width  = Math.floor(r.width);
  canvas.height = Math.floor(r.height);
  drawMap();
}).observe($('map-canvas-wrap'));

// Returns the largest centered square within the canvas (keeps map 1:1 aspect ratio)
function mapRect() {
  const canvas = $('map-canvas');
  const size = Math.min(canvas.width, canvas.height);
  return { x: (canvas.width - size) / 2, y: (canvas.height - size) / 2, size };
}

function worldToCanvas(x, z) {
  const { x: mx, y: my, size } = mapRect();
  const extent = WORLD_SIZE + 2 * MAP_BORDER;
  return [
    mx + (x + extent / 2) / extent * size,
    my + (extent / 2 - z) / extent * size,
  ];
}

function loadMapImg() {
  const img = new Image();
  img.onload = () => { mapImg = img; mapImgRetries = 0; drawMap(); };
  img.onerror = () => {
    mapImg = null; drawMap();
    if (mapImgRetries < 4) { mapImgRetries++; setTimeout(loadMapImg, 4000); }
  };
  img.src = '/mapimg?' + Date.now();
}

function initMapIfNeeded() {
  if (!mapNeedsInit) return;
  mapNeedsInit = false;
  loadMapImg();
  fetch('/api/monuments').then(r=>r.json()).then(data => {
    mapMonuments = data || [];
    updateMapInfoBar();
    drawMap();
  }).catch(()=>{});
}

function drawMap() {
  const canvas = $('map-canvas');
  if (!canvas || canvas.width === 0) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;

  // Clear and apply pan/zoom transform
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, W, H);
  ctx.setTransform(view.scale, 0, 0, view.scale, view.ox, view.oy);

  // Largest centered square — keeps the world map 1:1 regardless of window shape
  const { x: mx0, y: my0, size } = mapRect();

  // Background / map image
  if (mapImg) {
    ctx.drawImage(mapImg, mx0, my0, size, size);
  } else {
    ctx.fillStyle = '#0a120a';
    ctx.fillRect(mx0, my0, size, size);
    ctx.font = '12px Consolas,monospace';
    ctx.fillStyle = 'rgba(255,255,255,0.22)';
    ctx.textAlign = 'center';
    if (!MAP_IMG_CONFIGURED) {
      ctx.fillText('No map image — click "rustmaps.com ↗" above to get one', mx0 + size/2, my0 + 26);
      ctx.font = '10px Consolas,monospace';
      ctx.fillStyle = 'rgba(255,255,255,0.12)';
      ctx.fillText('Copy the image URL and set it as map.image_url in config.json', mx0 + size/2, my0 + 42);
    } else {
      ctx.fillText('Waiting for MapRenderer to generate the map…', mx0 + size/2, my0 + 26);
      ctx.font = '10px Consolas,monospace';
      ctx.fillStyle = 'rgba(255,255,255,0.12)';
      ctx.fillText('Run  maprender.generate  in the console to trigger it now', mx0 + size/2, my0 + 42);
    }
    ctx.textAlign = 'left';
  }

  // Terrain region within the square (excludes ocean border)
  const extent   = WORLD_SIZE + 2 * MAP_BORDER;
  const bordFrac = MAP_BORDER / extent;
  const terrFrac = WORLD_SIZE / extent;
  const tx = mx0 + bordFrac * size;   // terrain left edge
  const ty = my0 + bordFrac * size;   // terrain top edge
  const ts = terrFrac * size;         // terrain side length (square)

  // Grid (within terrain only)
  const GRID_CELLS = Math.ceil(WORLD_SIZE / 150);
  const cs = ts / GRID_CELLS;         // cell size (same for x and y — square cells)
  ctx.strokeStyle = mapImg ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.07)';
  ctx.lineWidth = 0.5;
  for (let i = 0; i <= GRID_CELLS; i++) {
    ctx.beginPath(); ctx.moveTo(tx + i*cs, ty);    ctx.lineTo(tx + i*cs, ty+ts); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(tx, ty + i*cs);    ctx.lineTo(tx+ts,     ty + i*cs); ctx.stroke();
  }

  // Grid labels
  ctx.font = '9px Consolas,monospace';
  ctx.fillStyle = mapImg ? 'rgba(255,255,255,0.35)' : 'rgba(255,255,255,0.18)';
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  for (let i = 0; i < GRID_CELLS; i++) {
    const lbl = i < 26 ? ALPHA[i] : ALPHA[Math.floor(i/26)-1]+ALPHA[i%26];
    ctx.fillText(lbl,        tx + i*cs + 3, ty + 10);
    ctx.fillText(String(i+1), tx + 2,       ty + i*cs + 10);
  }

  // Compass (at terrain edges)
  ctx.font = 'bold 11px Consolas,monospace';
  ctx.fillStyle = 'rgba(255,255,255,0.45)';
  ctx.textAlign = 'center';
  ctx.fillText('N', tx + ts/2, ty + 14);
  ctx.fillText('S', tx + ts/2, ty + ts - 4);
  ctx.fillText('W', tx + 10,   ty + ts/2 + 4);
  ctx.fillText('E', tx + ts - 10, ty + ts/2 + 4);
  ctx.textAlign = 'left';

  // Monument markers — tier-coded icons
  const TIER_STYLE = {
    safe:  { color:'#4caf50', stroke:'rgba(0,0,0,0.6)', shape:'circle', r:5, lbl:'rgba(150,255,150,0.95)' },
    '3':   { color:'#ef4444', stroke:'rgba(0,0,0,0.6)', shape:'triangle', r:5, lbl:'rgba(255,140,140,0.95)' },
    '2':   { color:'#f97316', stroke:'rgba(0,0,0,0.6)', shape:'diamond', r:5, lbl:'rgba(255,190,130,0.95)' },
    '1':   { color:'#facc15', stroke:'rgba(0,0,0,0.5)', shape:'diamond', r:4, lbl:'rgba(255,230,100,0.95)' },
    water: { color:'#60a5fa', stroke:'rgba(0,0,0,0.5)', shape:'circle',  r:4, lbl:'rgba(140,200,255,0.95)' },
    cave:  { color:'#a78bfa', stroke:'rgba(0,0,0,0.5)', shape:'circle',  r:3, lbl:'rgba(200,180,255,0.85)' },
    other: { color:'rgba(200,200,200,0.7)', stroke:'rgba(0,0,0,0.4)', shape:'dot', r:3, lbl:'rgba(200,200,200,0.7)' },
  };
  for (const m of mapMonuments) {
    if (!monFilters[m.tier]) continue;
    const st = TIER_STYLE[m.tier] || TIER_STYLE.other;
    const [mx, my] = worldToCanvas(m.x, m.z);
    ctx.save();
    ctx.fillStyle   = st.color;
    ctx.strokeStyle = st.stroke;
    ctx.lineWidth   = 1.2;
    if (st.shape === 'circle' || st.shape === 'dot') {
      ctx.beginPath(); ctx.arc(mx, my, st.r, 0, Math.PI*2); ctx.fill(); ctx.stroke();
    } else if (st.shape === 'diamond') {
      const r = st.r;
      ctx.beginPath();
      ctx.moveTo(mx, my-r); ctx.lineTo(mx+r, my);
      ctx.lineTo(mx, my+r); ctx.lineTo(mx-r, my);
      ctx.closePath(); ctx.fill(); ctx.stroke();
    } else if (st.shape === 'triangle') {
      const r = st.r;
      ctx.beginPath();
      ctx.moveTo(mx, my-r); ctx.lineTo(mx+r, my+r); ctx.lineTo(mx-r, my+r);
      ctx.closePath(); ctx.fill(); ctx.stroke();
    }
    ctx.restore();
    // Label — always show; flip to left when near right/bottom edge of map square
    const font = st.shape === 'dot' ? '8px Consolas,monospace' : '9px Consolas,monospace';
    ctx.font = font;
    const tw = ctx.measureText(m.name).width;
    const lx = mx > mx0 + size * 0.65 ? mx - st.r - 3 - tw : mx + st.r + 3;
    const ly = my > my0 + size * 0.92 ? my - st.r - 3 : my + 3;
    ctx.lineWidth = 2.5;
    ctx.strokeStyle = 'rgba(0,0,0,0.75)';
    ctx.fillStyle   = st.lbl;
    ctx.strokeText(m.name, lx, ly);
    ctx.fillText(m.name,   lx, ly);
  }

  // Player dots
  const players = Object.values(mapPlayers);
  $('map-player-count').textContent = players.length + ' player' + (players.length !== 1 ? 's' : '');

  if (players.length === 0) {
    ctx.font = '13px Consolas,monospace';
    ctx.fillStyle = 'rgba(255,255,255,0.18)';
    ctx.textAlign = 'center';
    ctx.fillText('No players online', mx0 + size/2, my0 + size/2 - 10);
    ctx.font = '11px Consolas,monospace';
    ctx.fillText('Click Refresh when players are online', mx0 + size/2, my0 + size/2 + 12);
    ctx.textAlign = 'left';
  }

  for (const p of players) {
    const [cx, cy] = worldToCanvas(p.x, p.z);

    // Glow
    ctx.save();
    ctx.shadowColor = '#cd4214';
    ctx.shadowBlur = 10;
    ctx.fillStyle = '#cd4214';
    ctx.beginPath();
    ctx.arc(cx, cy, 5, 0, Math.PI*2);
    ctx.fill();
    ctx.restore();

    // Name label
    ctx.font = 'bold 11px Consolas,monospace';
    ctx.strokeStyle = 'rgba(0,0,0,0.75)';
    ctx.lineWidth = 2.5;
    ctx.strokeText(p.name, cx+9, cy+4);
    ctx.fillStyle = '#ffffff';
    ctx.fillText(p.name, cx+9, cy+4);
  }
  ctx.setTransform(1, 0, 0, 1, 0, 0);
}

// Parse location command response: "76561198... Name: G5, 123.4, -678.9"
function parseLocations(msg) {
  let updated = false;
  for (const line of msg.split('\n')) {
    const m = line.trim().match(/^(\d{17})\s+(.+?):\s+([A-Z]{1,2}\d+),\s*(-?[\d.]+),\s*(-?[\d.]+)/);
    if (m) {
      mapPlayers[m[1]] = { name:m[2].trim(), grid:m[3], x:parseFloat(m[4]), z:parseFloat(m[5]) };
      updated = true;
    }
  }
  if (updated) {
    const now = new Date().toLocaleTimeString('en-US', {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
    $('map-updated').textContent = 'Updated ' + now;
    if (activeTab === 'map') drawMap();
    // location covers all players (online + sleeping); subtract live ones to get sleeping count
    const sleeping = Object.keys(mapPlayers).filter(id => !livePlayers[id]).length;
    $('si-sleeping').textContent = sleeping;
  }
  return updated;
}

function refreshMap() {
  if (!rconOk) return;
  sendBg('location');
  if (!mapImg && MAP_IMG_CONFIGURED) { mapImgRetries = 0; loadMapImg(); }
}

function rerenderMap() {
  if (!rconOk) return;
  const btn = $('map-rerender');
  btn.disabled = true;
  btn.textContent = '⏳ Rendering...';
  send('maprender.generate');
  // Poll for updated image — plugin takes ~5-15s to render + save
  let polls = 0;
  const poll = setInterval(() => {
    polls++;
    mapImgRetries = 0;
    loadMapImg();
    if (mapImg || polls >= 12) {
      clearInterval(poll);
      btn.disabled = false;
      btn.textContent = '📷 Re-render';
    }
  }, 5000);
}

// Map interactions (pan, zoom, tooltip, coords)
const mapCanvas = $('map-canvas');
const tooltip   = $('map-tooltip');

// Convert a screen position to view-space coordinates (same space as worldToCanvas output)
function canvasToMap(clientX, clientY) {
  const rect = mapCanvas.getBoundingClientRect();
  const cx = (clientX - rect.left) * mapCanvas.width  / rect.width;
  const cy = (clientY - rect.top)  * mapCanvas.height / rect.height;
  return [(cx - view.ox) / view.scale, (cy - view.oy) / view.scale];
}

mapCanvas.addEventListener('wheel', e => {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
  const rect = mapCanvas.getBoundingClientRect();
  const cx = (e.clientX - rect.left) * mapCanvas.width  / rect.width;
  const cy = (e.clientY - rect.top)  * mapCanvas.height / rect.height;
  // Zoom toward cursor
  view.ox = cx - (cx - view.ox) * factor;
  view.oy = cy - (cy - view.oy) * factor;
  view.scale = Math.max(0.25, Math.min(12, view.scale * factor));
  drawMap();
}, { passive: false });

mapCanvas.addEventListener('mousedown', e => {
  if (e.button !== 0) return;
  _drag.active = true;
  _drag.sx = e.clientX - view.ox;
  _drag.sy = e.clientY - view.oy;
  mapCanvas.style.cursor = 'grabbing';
});

mapCanvas.addEventListener('mousemove', e => {
  if (_drag.active) {
    view.ox = e.clientX - _drag.sx;
    view.oy = e.clientY - _drag.sy;
    drawMap();
    return;
  }

  const [mx, my] = canvasToMap(e.clientX, e.clientY);
  const { x: mx0, y: my0, size } = mapRect();

  // World coordinates from view-space position within the map square
  const extent   = WORLD_SIZE + 2 * MAP_BORDER;
  const relX = (mx - mx0) / size;   // 0..1 within map square
  const relY = (my - my0) / size;
  const wx = Math.round(relX * extent - extent / 2);
  const wz = Math.round(extent / 2 - relY * extent);

  // Grid reference — only within terrain boundary
  const halfW    = WORLD_SIZE / 2;
  const bordFrac = MAP_BORDER / extent;
  const terrFrac = WORLD_SIZE / extent;
  const GRID_CELLS = Math.ceil(WORLD_SIZE / 150);
  let coords = wx + ', ' + wz;
  if (Math.abs(wx) <= halfW && Math.abs(wz) <= halfW) {
    const col = Math.floor((relX - bordFrac) / terrFrac * GRID_CELLS);
    const row = Math.floor((relY - bordFrac) / terrFrac * GRID_CELLS);
    if (col >= 0 && row >= 0 && col < GRID_CELLS && row < GRID_CELLS) {
      let colStr = '', ci = col;
      do { colStr = String.fromCharCode(65 + (ci % 26)) + colStr; ci = Math.floor(ci / 26) - 1; } while (ci >= 0);
      coords = colStr + (row + 1) + '  ' + coords;
    }
  }
  $('map-coords').textContent = coords;

  // Player tooltip
  let found = null;
  for (const p of Object.values(mapPlayers)) {
    const [pcx, pcy] = worldToCanvas(p.x, p.z);
    if (Math.hypot(mx - pcx, my - pcy) < 10) { found = p; break; }
  }
  const rect = mapCanvas.getBoundingClientRect();
  if (found) {
    tooltip.style.display = 'block';
    tooltip.style.left = (e.clientX - rect.left + 14) + 'px';
    tooltip.style.top  = (e.clientY - rect.top  - 10) + 'px';
    tooltip.querySelector('.tt-name').textContent = found.name;
    tooltip.querySelector('.tt-grid').textContent = found.grid;
    tooltip.querySelector('.tt-id').textContent   = found.id;
  } else {
    tooltip.style.display = 'none';
  }
});

mapCanvas.addEventListener('mouseup',    () => { _drag.active = false; mapCanvas.style.cursor = 'crosshair'; });
mapCanvas.addEventListener('mouseleave', () => {
  _drag.active = false;
  mapCanvas.style.cursor = 'crosshair';
  $('map-coords').textContent = '';
  tooltip.style.display = 'none';
});
mapCanvas.addEventListener('dblclick', resetView);

// window resize is handled by ResizeObserver above

// Auto-refresh map every 30s when visible
setInterval(() => { if (activeTab === 'map' && rconOk) refreshMap(); }, 30000);

// ── Players tab ────────────────────────────────────────────────────────────
function fmtDuration(secs) {
  if (!secs || secs < 0) return '—';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}

function fmtDate(ts) {
  if (!ts) return '—';
  const diff = Date.now() / 1000 - ts;
  if (diff < 60)        return 'now';
  if (diff < 3600)      return Math.floor(diff/60) + 'm ago';
  if (diff < 86400)     return Math.floor(diff/3600) + 'h ago';
  if (diff < 86400*7)   return Math.floor(diff/86400) + 'd ago';
  return new Date(ts*1000).toLocaleDateString('en-US', {month:'short', day:'numeric', year:'2-digit'});
}

function switchPlSubtab(name) {
  plSubtab = name;
  ['online','history','banned'].forEach(t => {
    $('pst-' + t).classList.toggle('active', t === name);
  });
  const isBanned = name === 'banned';
  $('pl-scroll').style.display      = isBanned ? 'none' : '';
  $('pl-toolbar').style.display     = isBanned ? 'none' : '';
  $('pl-banned-wrap').style.display = isBanned ? ''     : 'none';
  if (isBanned) loadBannedTab();
  else renderPlayersTable();
}

function plRefresh() {
  if (plSubtab === 'banned') loadBannedTab(true);
  else loadPlayersTab(true);
}

async function loadPlayersTab(force) {
  const now = Date.now();
  if (!force && playersData && (now - _plLastFetch) < 30000) { renderPlayersTable(); return; }
  try {
    const r = await fetch('/api/players');
    if (r.status === 401) { window.location.href = '/login'; return; }
    playersData = await r.json();
    _plLastFetch = Date.now();
    renderPlayersTable();
  } catch(e) {}
}

function plSort(key) {
  if (plSortKey === key) { plSortAsc = !plSortAsc; }
  else { plSortKey = key; plSortAsc = key === 'name'; }
  renderPlayersTable();
}

function renderPlayersTable() {
  if (plSubtab === 'banned') return;
  if (!playersData) { loadPlayersTab(true); return; }
  const search = ($('pl-search').value || '').toLowerCase();
  let rows = playersData.filter(p =>
    (plSubtab === 'online' ? p.online : true) &&
    (!search || p.name.toLowerCase().includes(search) || p.id.includes(search))
  );

  rows.sort((a, b) => {
    if (a.online !== b.online) return a.online ? -1 : 1;
    let av = a[plSortKey] ?? 0, bv = b[plSortKey] ?? 0;
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return plSortAsc ? cmp : -cmp;
  });

  document.querySelectorAll('#pl-table th[onclick]').forEach(th => {
    const m = th.getAttribute('onclick').match(/plSort\('(.+?)'\)/);
    th.className = (m && m[1] === plSortKey) ? (plSortAsc ? 'sort-asc' : 'sort-desc') : '';
  });

  const online = playersData.filter(p => p.online).length;
  const badge = $('players-badge');
  if (online > 0) { badge.textContent = online; badge.className = 'tbadge show'; }
  else { badge.textContent = ''; badge.className = 'tbadge'; }
  $('pl-count').textContent = rows.length + ' player' + (rows.length !== 1 ? 's' : '') +
    (plSubtab === 'online' ? ' online' : '');

  const tbody = $('pl-tbody');
  tbody.innerHTML = '';

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="pl-empty">No players found.</td></tr>';
    return;
  }

  for (const p of rows) {
    const live = livePlayers[p.id];
    const ping = live ? live.ping : null;
    const pc   = ping !== null ? (ping < 80 ? 'g' : ping < 150 ? 'm' : 'b') : '';
    const pingCell = ping !== null
      ? '<td class="pl-ping '+pc+'">'+ping+'ms</td>'
      : '<td></td>';

    let totalSecs = p.total_seconds || 0;
    if (p.online && p.session_start) totalSecs += Date.now()/1000 - p.session_start;

    const tr = document.createElement('tr');
    tr.className = 'pl-row' + (p.online ? ' online' : '');
    tr.dataset.id = p.id;
    tr.innerHTML =
      '<td><span class="pl-dot'+(p.online?' on':'')+'"></span></td>' +
      '<td class="pl-name">'+esc(p.name)+'</td>' +
      '<td><span class="pl-sid" title="Click to copy" onclick="event.stopPropagation();navigator.clipboard.writeText(\''+p.id+'\')">'+esc(p.id)+'</span></td>' +
      '<td>'+fmtDuration(totalSecs)+'</td>' +
      '<td>'+p.session_count+'</td>' +
      '<td>'+fmtDate(p.first_seen)+'</td>' +
      '<td>'+fmtDate(p.last_seen)+'</td>' +
      pingCell;
    tr.onclick = () => togglePlayerSessions(tr, p);
    tbody.appendChild(tr);
  }
}

function togglePlayerSessions(tr, p) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('pl-sessions-row')) {
    next.remove(); tr.classList.remove('expanded'); return;
  }
  tr.classList.add('expanded');
  const sess = (p.sessions || []).slice().reverse();
  let html = '<div class="pl-sessions-hdr">Session history (last ' + sess.length + ')</div><div class="pl-sess-list">';
  for (let i = 0; i < sess.length; i++) {
    const s = sess[i];
    const dur = s.l ? fmtDuration(s.l - s.j) : fmtDuration(Date.now()/1000 - s.j) + ' (online)';
    html += '<div class="pl-sess">'
      + '<span class="pl-sess-n">#' + (sess.length - i) + '</span>'
      + '<span class="pl-sess-date">' + fmtDate(s.j) + '</span>'
      + '<span class="pl-sess-dur">' + dur + '</span></div>';
  }
  if (!sess.length) html += '<div class="pl-sess">No sessions recorded yet</div>';
  html += '</div>';
  const sessRow = document.createElement('tr');
  sessRow.className = 'pl-sessions-row';
  sessRow.innerHTML = '<td colspan="8"><div class="pl-sessions-inner">' + html + '</div></td>';
  sessRow.onclick = e => e.stopPropagation();
  tr.insertAdjacentElement('afterend', sessRow);
}

async function loadBannedTab(force) {
  const now = Date.now();
  if (!force && bansData && (now - _bansLastFetch) < 30000) { renderBannedTab(); return; }
  const tbody = $('pl-banned-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="pl-empty">Loading...</td></tr>';
  try {
    const r = await fetch('/api/bans');
    if (r.status === 401) { window.location.href = '/login'; return; }
    if (!r.ok) {
      const d = await r.json();
      tbody.innerHTML = '<tr><td colspan="4" class="pl-empty" style="color:var(--red)">' + esc(d.error || 'Error') + '</td></tr>';
      return;
    }
    bansData = await r.json();
    _bansLastFetch = Date.now();
    renderBannedTab();
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="4" class="pl-empty" style="color:var(--red)">Request failed</td></tr>';
  }
}

function renderBannedTab() {
  const tbody = $('pl-banned-tbody');
  if (!bansData || !bansData.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="pl-empty">No banned players.</td></tr>';
    return;
  }
  tbody.innerHTML = '';
  for (const b of bansData) {
    const knownName = (playersData || []).find(p => p.id === b.steamid)?.name || b.name || '';
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td><span class="pl-sid" title="Click to copy" onclick="navigator.clipboard.writeText(\''+b.steamid+'\')" style="cursor:pointer">'+esc(b.steamid)+'</span></td>' +
      '<td class="pl-name">'+(knownName ? esc(knownName) : '<span style="color:var(--dim)">Unknown</span>')+'</td>' +
      '<td class="col-reason" style="color:var(--dim)">'+(b.reason ? esc(b.reason) : '')+'</td>' +
      '<td><button class="ban-unban" onclick="unbanPlayer(\''+b.steamid+'\',this)">Unban</button></td>';
    tbody.appendChild(tr);
  }
}

async function unbanPlayer(steamid, btn) {
  if (!confirm('Unban ' + steamid + '?')) return;
  btn.disabled = true;
  btn.textContent = '...';
  try {
    const r = await fetch('/api/unban', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({steamid})
    });
    const d = await r.json();
    if (d.ok) {
      bansData = bansData.filter(b => b.steamid !== steamid);
      renderBannedTab();
      log('Unbanned ' + steamid, 'ok');
    } else {
      btn.disabled = false; btn.textContent = 'Unban';
      log('Unban failed: ' + (d.error || '?'), 'err');
    }
  } catch(e) { btn.disabled = false; btn.textContent = 'Unban'; }
}

// Auto-refresh players tab every 60s when visible
setInterval(() => {
  if (activeTab !== 'players') return;
  if (plSubtab === 'banned') loadBannedTab(true);
  else loadPlayersTab(true);
}, 60000);

// ── WebSocket message handler ──────────────────────────────────────────────
function onMsg(e) {
  const d = JSON.parse(e.data);

  if (d.type === 'connected') {
    _hasProfile = true;
    hideLoginOverlay();
    document.getElementById('login-connect-btn').disabled = false;
    setOk(true);
    log('RCON connected', 'ok');
    setTimeout(() => sendBg('status'),      300);
    setTimeout(() => sendBg('serverinfo'),  600);
    setTimeout(() => sendBg('playerlist'),  900);
    setTimeout(() => sendBg('env.time'),   1200);
    setTimeout(() => sendBg('location'),   1500);
    fetchWorldCfg();
  } else if (d.type === 'disconnected') {
    setOk(false);
    log('RCON disconnected, retrying…', 'sys');
  } else if (d.type === 'status') {
    _hasProfile = d.has_profile;
    setOk(d.connected);
    if (!d.has_profile) {
      showLoginOverlay();
    } else if (d.connected) {
      hideLoginOverlay();
      setTimeout(()=>sendBg('status'),300); setTimeout(()=>sendBg('serverinfo'),600); setTimeout(()=>sendBg('playerlist'),900); setTimeout(()=>sendBg('env.time'),1200); setTimeout(()=>sendBg('location'),1500);
      fetchWorldCfg();
    }
  } else if (d.type === 'rcon') {
    const msg  = (d.data && d.data.Message) || '';
    const type = (d.data && d.data.Type)    || '';
    const msgT = msg.trim();
    if (!msgT) return;

    // Chat messages
    if (type === 'Chat') {
      parseChat(msgT);
      log('[Chat] ' + msgT, 'info');
      return;
    }

    // Suppress automated poll noise (never useful in console)
    if (msgT === 'No players found.') return;

    // Playerlist JSON response — parse silently, never log raw JSON
    if (msgT.startsWith('[') && msgT.endsWith(']')) {
      try {
        const pl = JSON.parse(msgT);
        if (Array.isArray(pl)) {
          renderPlayers(pl.map(p => ({id: p.SteamID, name: p.DisplayName || p.Username || '', ping: p.Ping})));
          return;
        }
      } catch(e) {}
    }

    // serverinfo JSON response — update FPS + memory silently
    if (msgT.startsWith('{') && msgT.endsWith('}')) {
      try {
        const si = JSON.parse(msgT);
        if ('Framerate' in si) {
          $('si-fps').textContent = parseFloat(si.Framerate).toFixed(1);
          $('si-mem').textContent = si.Memory + ' MB';
          if (si.Hostname) hsvr.textContent = si.Hostname;
          if (si.Players  != null && si.MaxPlayers != null) $('si-pl').textContent = si.Players + ' / ' + si.MaxPlayers;
          if (si.Joining  != null) $('si-joining').textContent = si.Joining + (si.Queued ? ' (+' + si.Queued + ' queued)' : '');
          return;
        }
      } catch(e) {}
    }

    // Location data — parse silently if matched, otherwise fall through to console
    if (parseLocations(msg)) return;

    // env.time ConVar response — format float 0-24 as HH:MM in-game time
    const etm = msgT.match(/^env\.time\s*:\s*"?([\d.]+)"?/i);
    if (etm) {
      const t = parseFloat(etm[1]), h = Math.floor(t), m = Math.floor((t - h) * 60);
      $('si-gametime').textContent = String(h).padStart(2,'0') + ':' + String(m).padStart(2,'0');
      return;
    }

    // Status response — parse into sidebar, suppress raw output from console
    if (/hostname\s*:/i.test(msg)) { parseStatus(msg); return; }
    if (/fps\s*[:\|]/i.test(msg))  { parseStatus(msg); return; }
    if (/\d{17}/.test(msg))          parsePlayers(msg);

    msgT.split('\n').forEach(l => { if (l.trim()) log(l); });
  }
}

// ── Login / Server profiles ───────────────────────────────────────────────
let _loginProfiles = [];
let _loginSelId = null;
let _hasProfile = false;

function showLoginOverlay() {
  document.getElementById('login-overlay').classList.remove('hidden');
  loadLoginProfiles();
}

function hideLoginOverlay() {
  document.getElementById('login-overlay').classList.add('hidden');
}

function loginClose() {
  if (_hasProfile) hideLoginOverlay();
}

async function loadLoginProfiles() {
  try {
    const r = await fetch('/api/profiles');
    const d = await r.json();
    _loginProfiles = d.profiles || [];
    const lastId   = d.last_id  || '';
    renderLoginProfiles();
    if (!_loginProfiles.length) {
      loginNewProfile();                            // no profiles → show blank form directly
    } else if (!_loginSelId) {
      const pref = _loginProfiles.find(p => p.id === lastId) || _loginProfiles[0];
      loginSelectProfile(pref);                     // pre-select last-used (or first)
    }
  } catch(e) {}
}

function renderLoginProfiles() {
  const list = document.getElementById('login-profiles-list');
  list.innerHTML = '';
  for (const p of _loginProfiles) {
    const div = document.createElement('div');
    div.className = 'lp-item' + (p.id === _loginSelId ? ' active' : '');
    div.innerHTML =
      '<div class="lp-info"><div class="lp-name">' + esc(p.name || p.host) + '</div>' +
      '<div class="lp-host">' + esc(p.host) + ':' + p.port + '</div></div>' +
      '<button class="lp-del" title="Delete" onclick="event.stopPropagation();loginDeleteProfile(\'' + p.id + '\')">✕</button>';
    div.onclick = () => loginSelectProfile(p);
    list.appendChild(div);
  }
}

function loginSelectProfile(p) {
  _loginSelId = p.id;
  document.getElementById('lf-name').value = p.name || '';
  document.getElementById('lf-host').value = p.host || '';
  document.getElementById('lf-port').value = p.port || 28016;
  document.getElementById('lf-pass').value = p.password || '';
  renderLoginProfiles();
}

function loginNewProfile() {
  _loginSelId = null;
  document.getElementById('lf-name').value = '';
  document.getElementById('lf-host').value = '';
  document.getElementById('lf-port').value = '28016';
  document.getElementById('lf-pass').value = '';
  loginSetStatus('');
  renderLoginProfiles();
  document.getElementById('lf-host').focus();
}

async function loginConnect() {
  const host = document.getElementById('lf-host').value.trim();
  const port = parseInt(document.getElementById('lf-port').value) || 28016;
  const pass = document.getElementById('lf-pass').value;
  const name = document.getElementById('lf-name').value.trim();
  if (!host) { loginSetStatus('Enter a host / IP address', 'err'); return; }
  if (!pass)  { loginSetStatus('Enter the RCON password', 'err'); return; }
  const btn = document.getElementById('login-connect-btn');
  btn.disabled = true;
  loginSetStatus('Connecting…');
  try {
    // Auto-save as a profile if this is a new connection (no profile selected yet)
    if (!_loginSelId) {
      const sr = await fetch('/api/profiles', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: name || host, host, port, password: pass})
      });
      const sd = await sr.json();
      if (sd.ok) { _loginSelId = sd.id; await loadLoginProfiles(); }
    }
    const r = await fetch('/api/connect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: _loginSelId, host, port, password: pass, name})
    });
    const d = await r.json();
    if (!d.ok) { loginSetStatus(d.error || 'Connection request failed', 'err'); btn.disabled = false; }
    // Success: overlay closes when WS sends 'connected'
  } catch(e) {
    loginSetStatus('Request failed', 'err');
    btn.disabled = false;
  }
}

async function loginSaveProfile() {
  const host = document.getElementById('lf-host').value.trim();
  const port = parseInt(document.getElementById('lf-port').value) || 28016;
  const pass = document.getElementById('lf-pass').value;
  const name = document.getElementById('lf-name').value.trim();
  if (!host) { loginSetStatus('Enter a host / IP address first', 'err'); return; }
  const body = {name: name || host, host, port, password: pass};
  if (_loginSelId) body.id = _loginSelId;
  try {
    const r = await fetch('/api/profiles', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if (d.ok) {
      _loginSelId = d.id;
      await loadLoginProfiles();
      loginSetStatus('Profile saved', 'ok');
    } else {
      loginSetStatus(d.error || 'Save failed', 'err');
    }
  } catch(e) { loginSetStatus('Request failed', 'err'); }
}

async function loginDeleteProfile(id) {
  if (!confirm('Delete this profile?')) return;
  try {
    await fetch('/api/profiles/' + id, {method: 'DELETE'});
    if (_loginSelId === id) { _loginSelId = null; loginNewProfile(); }
    await loadLoginProfiles();
  } catch(e) {}
}

function loginSetStatus(msg, type) {
  const el = document.getElementById('login-status');
  el.textContent = msg;
  el.style.color = type === 'err' ? 'var(--red)' : type === 'ok' ? 'var(--green)' : 'var(--dim)';
}

// ── Settings ───────────────────────────────────────────────────────────────
function showSettings() {
  document.getElementById('settings-overlay').classList.remove('hidden');
  document.getElementById('set-pwd-cur').value = '';
  document.getElementById('set-pwd-new').value = '';
  document.getElementById('set-pwd-confirm').value = '';
  settingsMsg('');
  document.getElementById('set-pwd-cur').focus();
}

function hideSettings() {
  document.getElementById('settings-overlay').classList.add('hidden');
}

document.getElementById('settings-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('settings-overlay')) hideSettings();
});

function showAbout() {
  document.getElementById('about-overlay').classList.remove('hidden');
  fetch('/api/about').then(r => r.json()).then(d => {
    document.getElementById('ab-version').textContent  = d.version  || '—';
    document.getElementById('ab-python').textContent   = d.python   || '—';
    document.getElementById('ab-aiohttp').textContent  = d.aiohttp  || '—';
    document.getElementById('ab-platform').textContent = d.platform || '—';
    if (d.github) document.getElementById('ab-github').href = d.github;
  }).catch(() => {});
}

function hideAbout() {
  document.getElementById('about-overlay').classList.add('hidden');
}

document.getElementById('about-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('about-overlay')) hideAbout();
});

async function settingsSavePassword() {
  const cur     = document.getElementById('set-pwd-cur').value;
  const newPwd  = document.getElementById('set-pwd-new').value;
  const confirm = document.getElementById('set-pwd-confirm').value;
  if (!cur)    { settingsMsg('Enter your current password', 'err'); return; }
  if (!newPwd) { settingsMsg('Enter a new password', 'err'); return; }
  if (newPwd !== confirm) { settingsMsg('Passwords do not match', 'err'); return; }
  try {
    const r = await fetch('/api/settings/password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({current: cur, new: newPwd, confirm})
    });
    const d = await r.json();
    if (d.ok) {
      settingsMsg('Password changed — you will be signed out', 'ok');
      setTimeout(() => { window.location.href = '/logout'; }, 1500);
    } else {
      settingsMsg(d.error || 'Failed', 'err');
    }
  } catch(e) { settingsMsg('Request failed', 'err'); }
}

function settingsMsg(msg, type) {
  const el = document.getElementById('settings-msg');
  el.textContent = msg;
  el.style.color = type === 'err' ? 'var(--red)' : type === 'ok' ? 'var(--green)' : 'var(--dim)';
}

// ── Oxide tab ──────────────────────────────────────────────────────────────
let oxideData = null, oxideCache = 0, oxideUpdates = {};

async function loadOxideTab(force) {
  const now = Date.now();
  if (!force && oxideData && now - oxideCache < 30000) { renderOxideTab(); return; }
  $('oxide-status-msg').textContent = 'Loading…';
  $('oxide-version').textContent = '';
  try {
    const r = await fetch('/api/oxide');
    if (r.status === 401) { window.location.href = '/login'; return; }
    if (!r.ok) { $('oxide-status-msg').textContent = 'Error ' + r.status; return; }
    oxideData = await r.json();
    oxideCache = now;
    renderOxideTab();
  } catch(e) { $('oxide-status-msg').textContent = 'Request failed'; }
}

function renderOxideTab() {
  if (!oxideData) return;
  $('oxide-version').textContent = oxideData.oxide_version || '';
  const n = (oxideData.plugins || []).length;
  $('oxide-status-msg').textContent = n + ' plugin' + (n === 1 ? '' : 's');
  const tb = $('oxide-tbody');
  tb.innerHTML = '';
  for (const p of (oxideData.plugins || [])) {
    const upd = oxideUpdates[p.slug || p.name];
    const tr = document.createElement('tr');
    const slugSafe = (p.slug || p.name).replace(/'/g, "\\'");

    let verHtml = esc(p.version);
    if (upd) {
      if (upd.found && upd.latest && upd.latest !== p.version) {
        verHtml += `<span class="ox-upd-badge" title="Update available: ${esc(upd.latest)}">&#8593;${esc(upd.latest)}</span>`;
      } else if (upd.found) {
        verHtml += '<span class="ox-up-to-date" title="Up to date">&#10003;</span>';
      }
    }
    let actHtml =
      `<button class="ox-act" onclick="oxideReload('${slugSafe}')">Reload</button>` +
      `<button class="ox-act unload" style="margin-left:4px" onclick="oxideUnload('${slugSafe}')">Unload</button>`;
    if (upd && upd.found && upd.latest && upd.latest !== p.version) {
      if (upd.download_url) {
        const dlSafe = (upd.download_url||'').replace(/'/g,"\\'");
        actHtml += `<button class="ox-act update" style="margin-left:4px" onclick="oxideUpdate('${slugSafe}','${dlSafe}')">&#8593; Update</button>`;
      } else if (upd.url) {
        actHtml += `<a class="ox-act ext-link" href="${esc(upd.url)}" target="_blank" style="margin-left:4px" title="${esc(upd.marketplace||'Marketplace')}">&#8599; ${esc(upd.marketplace||'Update')}</a>`;
      }
    }
    tr.innerHTML =
      `<td><span class="ox-dot"></span></td>` +
      `<td>${esc(p.name)}</td>` +
      `<td>${verHtml}</td>` +
      `<td>${esc(p.author)}</td>` +
      `<td style="color:var(--dim);font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.description)}</td>` +
      `<td style="white-space:nowrap">${actHtml}</td>`;
    tb.appendChild(tr);
  }
}

async function _oxidePost(body) {
  const r = await fetch('/api/oxide/action', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return r.json();
}

async function oxideReload(name) {
  $('oxide-status-msg').textContent = 'Reloading ' + name + '…';
  try {
    const d = await _oxidePost({action: 'reload', plugin: name});
    $('oxide-status-msg').textContent = d.result || (d.ok ? 'Reloaded' : (d.error || 'Failed'));
    setTimeout(() => loadOxideTab(true), 1500);
  } catch(e) { $('oxide-status-msg').textContent = 'Request failed'; }
}

async function oxideUnload(name) {
  $('oxide-status-msg').textContent = 'Unloading ' + name + '…';
  try {
    const d = await _oxidePost({action: 'unload', plugin: name});
    $('oxide-status-msg').textContent = d.result || (d.ok ? 'Unloaded' : (d.error || 'Failed'));
    if (oxideData) oxideData.plugins = oxideData.plugins.filter(p => p.slug !== name && p.name !== name);
    renderOxideTab();
  } catch(e) { $('oxide-status-msg').textContent = 'Request failed'; }
}

async function oxideReloadAll() {
  $('oxide-status-msg').textContent = 'Reloading all plugins…';
  const btn = $('oxide-reload-all-btn');
  btn.disabled = true;
  try {
    const d = await _oxidePost({action: 'reload', plugin: '*'});
    $('oxide-status-msg').textContent = d.result || (d.ok ? 'All reloaded' : (d.error || 'Failed'));
    setTimeout(() => loadOxideTab(true), 2500);
  } catch(e) { $('oxide-status-msg').textContent = 'Request failed'; }
  finally { btn.disabled = false; }
}

async function oxideCheckUpdates() {
  if (!oxideData || !oxideData.plugins.length) return;
  const btn = $('oxide-updates-btn');
  btn.disabled = true;
  oxideUpdates = {};
  $('oxide-status-msg').textContent = 'Checking updates…';
  try {
    const slugs = oxideData.plugins.map(p => p.slug || p.name.replace(/\s+/g, '')).filter(Boolean).join(',');
    const r = await fetch('/api/oxide/updates?plugins=' + encodeURIComponent(slugs));
    if (!r.ok) { $('oxide-status-msg').textContent = 'Update check failed'; return; }
    oxideUpdates = await r.json();
    const outdated = oxideData.plugins.filter(p => {
      const u = oxideUpdates[p.slug || p.name];
      return u && u.found && u.latest && u.latest !== p.version;
    }).length;
    renderOxideTab();
    $('oxide-status-msg').textContent = outdated
      ? outdated + ' update' + (outdated > 1 ? 's' : '') + ' available'
      : 'All plugins up to date';
  } catch(e) { $('oxide-status-msg').textContent = 'Update check failed'; }
  finally { btn.disabled = false; }
}

async function oxideUpdate(name, downloadUrl) {
  $('oxide-status-msg').textContent = 'Downloading ' + name + '…';
  try {
    const r = await fetch('/api/oxide/update', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name, download_url: downloadUrl})
    });
    const d = await r.json();
    $('oxide-status-msg').textContent = d.result || (d.ok ? 'Updated!' : (d.error || 'Failed'));
    if (d.ok) setTimeout(() => loadOxideTab(true), 2000);
  } catch(e) { $('oxide-status-msg').textContent = 'Request failed'; }
}

// ── WebSocket connection ───────────────────────────────────────────────────
async function checkAuthAndRedirect() {
  try {
    const r = await fetch('/api/ping');
    if (r.status === 401) { window.location.href = '/login'; return true; }
  } catch(e) {}
  return false;
}

function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen    = () => log('Panel connected', 'sys');
  ws.onmessage = onMsg;
  ws.onerror   = async () => { if (!await checkAuthAndRedirect()) log('Panel WebSocket error', 'err'); };
  ws.onclose   = async () => { setOk(false); if (await checkAuthAndRedirect()) return; log('Panel disconnected -- reconnecting in 3s...', 'sys'); setTimeout(connect, 3000); };
}

setInterval(() => { if (rconOk) { sendBg('playerlist'); sendBg('serverinfo'); sendBg('status'); sendBg('env.time'); sendBg('location'); } }, 60000);
connect();
</script>
</body>
</html>"""

_browsers: set = set()
_rcon_q: asyncio.Queue = None
_rcon_ok: bool = False
_msg_id: int = 0
_mapimg_cache: bytes = None
_mapimg_cache_ct: str = 'image/jpeg'
_mapimg_path_cache: bytes = None
_mapimg_path_cache_ct: str = 'image/png'
_mapimg_path_mtime: float = 0.0
_favicon_cache: str = ''
_http_session: aiohttp.ClientSession = None


@web.middleware
async def _auth(request, handler):
    pwd = CONFIG.get('web', {}).get('password', '')
    if not pwd:
        return await handler(request)
    if request.path in ('/login', '/favicon.svg', '/mapimg', '/monuments'):
        return await handler(request)
    # CSRF: reject state-changing requests from foreign origins
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        host = request.headers.get('Host', '')
        origin = request.headers.get('Origin', '')
        referer = request.headers.get('Referer', '')
        allowed = False
        if origin:
            origin_host = origin.split('://', 1)[-1].rstrip('/')
            allowed = (origin_host == host)
        elif referer:
            referer_host = referer.split('://', 1)[-1].split('/', 1)[0]
            allowed = (referer_host == host)
        else:
            allowed = True  # no origin/referer (e.g. curl, mobile app)
        if not allowed:
            return web.Response(status=403, body=b'Forbidden')
    token = request.cookies.get('rcon_session', '')
    if token and _valid_session(token):
        return await handler(request)
    is_ws = request.headers.get('Upgrade', '').lower() == 'websocket'
    is_api = request.path.startswith('/api/')
    if is_ws or is_api or request.method != 'GET':
        return web.Response(status=401, body=b'Unauthorized')
    raise web.HTTPFound('/login')


def _login_servers_html() -> str:
    if not _profiles:
        return '<div class="servers"><div class="no-srv">No servers configured</div></div>'
    last_id = CONFIG.get('web', {}).get('last_profile_id', '') or _profiles[0]['id']
    rows = ''
    for p in _profiles:
        name = _he(p.get('name') or p['host'])
        host = _he(p['host'])
        port = _he(str(p['port']))
        pid  = _he(p['id'])
        sel  = ' sel' if p['id'] == last_id else ''
        rows += (
            f'<div class="srv-row{sel}" data-id="{pid}">'
            '<div class="srv-dot"></div>'
            '<div><div class="srv-name">' + name + '</div>'
            '<div class="srv-addr">' + host + ':' + port + '</div></div>'
            '</div>'
        )
    return '<div class="servers"><div class="servers-hdr">Servers</div>' + rows + '</div>'


async def _handle_login_get(req):
    return web.Response(
        text=LOGIN_HTML.format(servers_html=_login_servers_html(), error_msg=''),
        content_type='text/html', charset='utf-8',
    )


async def _handle_login_post(req):
    ip = req.headers.get('X-Forwarded-For', req.remote or '').split(',')[0].strip()
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < 600]
    if len(attempts) >= 10:
        return web.Response(
            text=LOGIN_HTML.format(servers_html=_login_servers_html(),
                                   error_msg='Too many attempts — try again later.'),
            content_type='text/html', charset='utf-8', status=429,
        )
    data = await req.post()
    given = data.get('password', '')
    expected = CONFIG.get('web', {}).get('password', '')
    if expected and _verify_web_pwd(given, expected):
        global _rcon_cfg, _active_profile_id
        _login_attempts.pop(ip, None)
        profile_id = data.get('profile_id', '').strip()
        if profile_id and profile_id != _active_profile_id:
            p = next((x for x in _profiles if x['id'] == profile_id), None)
            if p:
                _rcon_cfg = {'host': p['host'], 'port': p['port'], 'password': _decrypt_pwd(p['password'])}
                _active_profile_id = profile_id
                CONFIG.setdefault('web', {})['last_profile_id'] = profile_id
                cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
                with open(cfg_path, 'w') as f:
                    json.dump(CONFIG, f, indent=2)
                if _rcon_restart:
                    _rcon_restart.set()
        token = _new_session()
        resp = web.HTTPFound('/')
        resp.set_cookie('rcon_session', token, httponly=True, samesite='Lax', max_age=86400, path='/')
        raise resp
    attempts.append(now)
    _login_attempts[ip] = attempts
    return web.Response(
        text=LOGIN_HTML.format(servers_html=_login_servers_html(), error_msg='Invalid password — try again.'),
        content_type='text/html', charset='utf-8', status=401,
    )


async def _handle_settings_password(req):
    try:
        d = await req.json()
    except Exception:
        return web.json_response({'ok': False, 'error': 'Invalid JSON'}, status=400)
    current = d.get('current', '')
    new_pwd = d.get('new', '')
    confirm = d.get('confirm', '')
    stored = CONFIG.get('web', {}).get('password', '')
    if not _verify_web_pwd(current, stored):
        return web.json_response({'ok': False, 'error': 'Current password is incorrect'})
    if not new_pwd:
        return web.json_response({'ok': False, 'error': 'New password cannot be empty'})
    if new_pwd != confirm:
        return web.json_response({'ok': False, 'error': 'Passwords do not match'})
    CONFIG['web']['password'] = _hash_web_pwd(new_pwd)
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(cfg_path, 'w') as f:
        json.dump(CONFIG, f, indent=2)
    return web.json_response({'ok': True})


async def _handle_ping(req):
    return web.json_response({'ok': True})


async def _handle_logout(req):
    _delete_session(req.cookies.get('rcon_session', ''))
    resp = web.HTTPFound('/login')
    resp.del_cookie('rcon_session', path='/')
    raise resp


async def _broadcast(data: dict):
    dead = set()
    for ws in _browsers:
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    _browsers.difference_update(dead)


async def _recv(ws):
    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            try:
                d = json.loads(msg.data)
                ident = d.get('Identifier', 0)
                if ident and ident in _rcon_pending:
                    fut = _rcon_pending.pop(ident)
                    if not fut.done():
                        fut.set_result(d.get('Message', ''))
                    continue
                await _broadcast({'type': 'rcon', 'data': d})
                txt = d.get('Message', '')
                if txt and _process_join_leave(txt):
                    asyncio.create_task(asyncio.to_thread(_save_player_db))
            except Exception:
                pass
        elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
            break


async def _send(ws, stop: asyncio.Event):
    while not stop.is_set():
        try:
            cmd = await asyncio.wait_for(_rcon_q.get(), timeout=1.0)
            if not ws.closed:
                await ws.send_json(cmd)
        except asyncio.TimeoutError:
            continue
        except Exception:
            break


async def _rcon_loop():
    global _rcon_ok
    while True:
        if not _rcon_cfg:
            await _rcon_restart.wait()
            _rcon_restart.clear()
            continue

        cfg = dict(_rcon_cfg)
        url = cfg.get('url') or f"ws://{cfg['host']}:{cfg['port']}/{cfg['password']}"

        try:
            to = aiohttp.ClientTimeout(total=None, connect=10, sock_connect=10)
            async with aiohttp.ClientSession(timeout=to) as sess:
                async with sess.ws_connect(url) as ws:
                    _rcon_ok = True
                    await _broadcast({'type': 'connected'})
                    stop = asyncio.Event()
                    recv_t = asyncio.create_task(_recv(ws))
                    send_t = asyncio.create_task(_send(ws, stop))
                    restart_t = asyncio.create_task(_rcon_restart.wait())
                    await asyncio.wait([recv_t, send_t, restart_t], return_when=asyncio.FIRST_COMPLETED)
                    stop.set()
                    for t in [recv_t, send_t, restart_t]:
                        t.cancel()
                    await asyncio.gather(recv_t, send_t, restart_t, return_exceptions=True)
        except Exception as e:
            print(f'RCON connect error: {e}', flush=True)

        _rcon_ok = False
        await _broadcast({'type': 'disconnected'})

        if _rcon_restart.is_set():
            _rcon_restart.clear()
        else:
            try:
                await asyncio.wait_for(_rcon_restart.wait(), timeout=5.0)
                _rcon_restart.clear()
            except asyncio.TimeoutError:
                pass


async def _handle_players_api(req):
    now = int(time.time())
    result = []
    for sid, p in _player_db.items():
        sessions = p.get('sessions', [])
        total = 0
        for s in sessions:
            total += s.get('l', now) - s['j']
        current = next((s for s in reversed(sessions) if 'l' not in s), None)
        result.append({
            'id':            sid,
            'name':          p.get('name', '?'),
            'online':        current is not None,
            'session_start': current['j'] if current else None,
            'total_seconds': total,
            'session_count': len(sessions),
            'first_seen':    sessions[0]['j']  if sessions else None,
            'last_seen':     (current['j'] if current else sessions[-1].get('l')) if sessions else None,
            'sessions':      sessions[-50:],
        })
    result.sort(key=lambda x: (not x['online'], -(x['last_seen'] or 0)))
    return web.json_response(result)


async def _handle_index(req):
    auth_enabled = 'true' if CONFIG.get('web', {}).get('password', '') else 'false'
    html = HTML.replace('/*__AUTH_ENABLED__*/', f'const AUTH_ENABLED={auth_enabled};')
    return web.Response(text=html, content_type='text/html', charset='utf-8')


async def _fetch_map_url(url: str):
    global _mapimg_cache, _mapimg_cache_ct
    delays = [5, 15, 30, 60, 120, 300]
    attempt = 0
    while True:
        try:
            async with _http_session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    ct = resp.content_type or ''
                    _mapimg_cache = data
                    _mapimg_cache_ct = 'image/png' if ('png' in ct or url.lower().endswith('.png')) else 'image/jpeg'
                    print(f'Map image cached from URL ({len(data)//1024} KB)', flush=True)
                    return
                else:
                    print(f'Map image fetch: HTTP {resp.status}, retrying…', flush=True)
        except Exception as e:
            print(f'Map image fetch failed: {e}, retrying…', flush=True)
        delay = delays[min(attempt, len(delays) - 1)]
        attempt += 1
        await asyncio.sleep(delay)


async def _handle_api_cfg(req):
    map_cfg = CONFIG.get('map', {})
    has_img = bool(map_cfg.get('image_path') or map_cfg.get('image_url'))
    return web.json_response({
        'world_size': map_cfg.get('world_size', 4500),
        'seed':       map_cfg.get('seed', 0),
        'map_img_configured': has_img,
    })


async def _handle_api_worldcfg(req):
    if not _rcon_ok:
        return web.json_response({'error': 'not connected'}, status=503)
    def _parse_cv(raw: str):
        m = _RE_WORLDCFG_VAL.search(raw)
        return int(m.group(1)) if m else None
    try:
        seed_raw, size_raw = await asyncio.gather(
            _rcon_query('server.seed'),
            _rcon_query('server.worldsize'),
        )
        return web.json_response({'seed': _parse_cv(seed_raw.strip()), 'world_size': _parse_cv(size_raw.strip())})
    except Exception as e:
        return web.json_response({'error': str(e)}, status=503)


async def _handle_about(req):
    return web.json_response({
        'version':    _APP_VERSION,
        'python':     sys.version.split()[0],
        'aiohttp':    aiohttp.__version__,
        'platform':   platform.system() + ' ' + platform.release(),
        'github':     'https://github.com/username-mendoza/rust-rcon-panel',
    })



async def _handle_favicon(req):
    global _favicon_cache
    if not _favicon_cache:
        path = os.path.join(os.path.dirname(__file__), 'static', 'favicon.svg')
        with open(path) as f:
            _favicon_cache = f.read()
    return web.Response(text=_favicon_cache, content_type='image/svg+xml',
                        headers={'Cache-Control': 'max-age=86400'})


async def _handle_mapimg(req):
    global _mapimg_path_cache, _mapimg_path_cache_ct, _mapimg_path_mtime
    path = CONFIG.get('map', {}).get('image_path', '')
    if path and os.path.exists(path):
        mtime = os.path.getmtime(path)
        if _mapimg_path_cache is None or mtime != _mapimg_path_mtime:
            ct = 'image/png' if path.lower().endswith('.png') else 'image/jpeg'
            _mapimg_path_cache    = await asyncio.to_thread(Path(path).read_bytes)
            _mapimg_path_cache_ct = ct
            _mapimg_path_mtime    = mtime
        return web.Response(body=_mapimg_path_cache, content_type=_mapimg_path_cache_ct)
    if _mapimg_cache:
        return web.Response(body=_mapimg_cache, content_type=_mapimg_cache_ct)
    return web.Response(status=404)


async def _read_local_monuments() -> str | None:
    path = CONFIG.get('map', {}).get('image_path', '')
    if path:
        mpath = Path(path).resolve().parent / 'monuments.json'
        if mpath.exists():
            return await asyncio.to_thread(mpath.read_text)
    return None


async def _handle_monuments_public(req):
    """Public /monuments endpoint — served to remote panels that use this panel as image_url source."""
    text = await _read_local_monuments()
    return web.Response(text=text or '[]', content_type='application/json')


async def _handle_monuments(req):
    text = await _read_local_monuments()
    if text is not None:
        return web.Response(text=text, content_type='application/json')
    # No local file — try fetching from the image_url source panel
    image_url = CONFIG.get('map', {}).get('image_url', '')
    if image_url:
        # Derive monuments URL from image URL (replace /mapimg path with /monuments)
        parsed = urlparse(image_url)
        mon_url = urlunparse(parsed._replace(path='/monuments', query='', fragment=''))
        try:
            async with _http_session.get(mon_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    return web.Response(text=body, content_type='application/json')
        except Exception:
            pass
    return web.Response(text='[]', content_type='application/json')


async def _handle_mapimg_refresh(req):
    url = CONFIG.get('map', {}).get('image_url', '')
    if not url:
        return web.json_response({'ok': False, 'error': 'No image_url in config'})
    asyncio.create_task(_fetch_map_url(url))
    return web.json_response({'ok': True})


async def _handle_ws(req):
    global _msg_id
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(req)
    _browsers.add(ws)
    await ws.send_json({'type': 'status', 'connected': _rcon_ok, 'has_profile': bool(_rcon_cfg)})
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    d = json.loads(msg.data)
                    if d.get('type') == 'command':
                        _msg_id += 1
                        _rcon_q.put_nowait({
                            'Identifier': _msg_id,
                            'Message': str(d.get('command', '')),
                            'Name': 'WebPanel',
                        })
                except Exception:
                    pass
            elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        _browsers.discard(ws)
    return ws


async def _rcon_query(cmd: str, timeout: float = 8.0) -> str:
    global _msg_id
    if not _rcon_ok:
        raise Exception('RCON not connected')
    _msg_id += 1
    ident = _msg_id
    fut = asyncio.get_running_loop().create_future()
    _rcon_pending[ident] = fut
    _rcon_q.put_nowait({'Identifier': ident, 'Message': cmd, 'Name': 'WebPanel'})
    try:
        return await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        _rcon_pending.pop(ident, None)
        raise Exception('RCON command timed out')


async def _handle_bans(req):
    try:
        raw = await _rcon_query('banlistex')
    except Exception as e:
        return web.json_response({'error': str(e)}, status=503)
    bans = []
    raw = raw.strip()
    if not raw or raw.lower() in ('', 'no bans', 'banlist is empty'):
        return web.json_response([])
    # Try JSON first (some server versions return JSON)
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                bans.append({
                    'steamid':  str(item.get('SteamID', item.get('steamid', ''))),
                    'name':     item.get('Username', item.get('name', '')),
                    'reason':   item.get('Notes',    item.get('reason', '')),
                    'expiry':   item.get('Expiry',   item.get('expiry', '')),
                })
            return web.json_response(bans)
    except Exception:
        pass
    # Text format — handle variants:
    #   76561198xxx "Name" "Reason"
    #   76561198xxx 0 0 "Name" "Notes"      (banlistex with extra fields)
    #   1. 76561198xxx "Name"               (numbered entries)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        line = _RE_BAN_IDX.sub('', line).strip()
        m = _RE_BAN_SID.search(line)
        if not m:
            continue
        steamid = m.group(1)
        rest = line[m.end():].strip()
        # Extract all quoted tokens from rest
        name = ''
        reason = ''
        quoted = re.findall(r'"([^"]*)"', rest)
        if quoted:
            name   = quoted[0]
            reason = quoted[1] if len(quoted) > 1 else ''
        elif rest:
            # unquoted remainder — skip leading bare numbers (extra banlistex fields)
            tokens = rest.split()
            non_num = [t for t in tokens if not t.isdigit()]
            name = non_num[0] if non_num else ''
        bans.append({'steamid': steamid, 'name': name, 'reason': reason, 'expiry': ''})
    return web.json_response(bans)


async def _handle_unban(req):
    try:
        d = await req.json()
    except Exception:
        return web.json_response({'ok': False, 'error': 'Invalid JSON'}, status=400)
    steamid = (d.get('steamid') or '').strip()
    if not steamid:
        return web.json_response({'ok': False, 'error': 'steamid required'}, status=400)
    if not _valid_steamid(steamid):
        return web.json_response({'ok': False, 'error': 'invalid steamid'}, status=400)
    try:
        result = await _rcon_query(f'unban {steamid}')
        return web.json_response({'ok': True, 'result': result})
    except Exception as e:
        return web.json_response({'ok': False, 'error': str(e)}, status=503)


async def _handle_profiles_get(req):
    last_id = CONFIG.get('web', {}).get('last_profile_id', '')
    return web.json_response({
        'profiles': [_profile_for_api(p) for p in _profiles],
        'last_id':  last_id,
    })


async def _handle_profiles_post(req):
    global _profiles
    try:
        d = await req.json()
    except Exception:
        return web.json_response({'ok': False, 'error': 'Invalid JSON'}, status=400)
    host = (d.get('host') or '').strip()
    port = d.get('port') or 28016
    password = d.get('password', '')
    name = (d.get('name') or host).strip()
    pid = (d.get('id') or '').strip()
    if not host:
        return web.json_response({'ok': False, 'error': 'host required'}, status=400)
    if not _valid_port(port):
        return web.json_response({'ok': False, 'error': 'port must be 1-65535'}, status=400)
    port = int(port)
    enc_pwd = _encrypt_pwd(password)
    async with _profiles_lock:
        if pid:
            for p in _profiles:
                if p['id'] == pid:
                    p.update({'name': name, 'host': host, 'port': port, 'password': enc_pwd})
                    _save_profiles()
                    return web.json_response({'ok': True, 'id': pid})
            return web.json_response({'ok': False, 'error': 'Profile not found'}, status=404)
        new_id = os.urandom(6).hex()
        _profiles.append({'id': new_id, 'name': name, 'host': host, 'port': port, 'password': enc_pwd})
        _save_profiles()
    return web.json_response({'ok': True, 'id': new_id})


async def _handle_profiles_delete(req):
    global _profiles, _active_profile_id
    pid = req.match_info['id']
    async with _profiles_lock:
        before = len(_profiles)
        _profiles = [p for p in _profiles if p['id'] != pid]
        if len(_profiles) < before:
            _save_profiles()
            if _active_profile_id == pid:
                _active_profile_id = ''
            return web.json_response({'ok': True})
    return web.json_response({'ok': False, 'error': 'Not found'}, status=404)


async def _handle_connect(req):
    global _rcon_cfg, _active_profile_id
    try:
        d = await req.json()
    except Exception:
        return web.json_response({'ok': False, 'error': 'Invalid JSON'}, status=400)
    pid = (d.get('id') or '').strip()
    if pid:
        p = next((p for p in _profiles if p['id'] == pid), None)
        if not p:
            return web.json_response({'ok': False, 'error': 'Profile not found'}, status=404)
        host, port, password = p['host'], p['port'], _decrypt_pwd(p['password'])
    else:
        host = (d.get('host') or '').strip()
        port = d.get('port') or 28016
        password = d.get('password', '')
        if not _valid_port(port):
            return web.json_response({'ok': False, 'error': 'port must be 1-65535'}, status=400)
        port = int(port)
    if not host:
        return web.json_response({'ok': False, 'error': 'host required'}, status=400)
    _rcon_cfg = {'host': host, 'port': port, 'password': password}
    _active_profile_id = pid
    _rcon_restart.set()
    if pid:
        CONFIG.setdefault('web', {})['last_profile_id'] = pid
        cfg_path = os.path.join(os.path.dirname(_profiles_path), 'config.json')
        with open(cfg_path, 'w') as f:
            json.dump(CONFIG, f, indent=2)
    return web.json_response({'ok': True})


async def _handle_oxide(req):
    if not _rcon_ok:
        return web.json_response({'error': 'RCON not connected'}, status=503)
    try:
        ver_raw, plugins_raw = await asyncio.gather(
            _rcon_query('oxide.version', timeout=8.0),
            _rcon_query('oxide.plugins', timeout=8.0),
        )
    except Exception as e:
        return web.json_response({'error': str(e)}, status=503)
    return web.json_response({
        'oxide_version': _parse_oxide_version(ver_raw),
        'plugins':       _parse_oxide_plugins(plugins_raw),
    })


async def _handle_oxide_action(req):
    try:
        d = await req.json()
    except Exception:
        return web.json_response({'ok': False, 'error': 'Invalid JSON'}, status=400)
    action = (d.get('action') or '').strip().lower()
    plugin = (d.get('plugin') or '').strip()
    if action not in ('reload', 'unload', 'load'):
        return web.json_response({'ok': False, 'error': 'action must be reload/unload/load'}, status=400)
    if not plugin:
        return web.json_response({'ok': False, 'error': 'plugin required'}, status=400)
    # Allow '*' only for reload
    if plugin == '*' and action != 'reload':
        return web.json_response({'ok': False, 'error': 'wildcard only allowed for reload'}, status=400)
    cmd = f'oxide.{action} {plugin}'
    try:
        result = await _rcon_query(cmd, timeout=15.0)
        return web.json_response({'ok': True, 'result': result.strip()})
    except Exception as e:
        return web.json_response({'ok': False, 'error': str(e)}, status=503)


_UC_CONFIG_PATH = '/home/steam/rustserver/oxide/config/UpdateChecker.json'

def _load_uc_map() -> dict:
    """Return {slugKey: {marketplace, url}} from UpdateChecker.json."""
    try:
        with open(_UC_CONFIG_PATH) as f:
            data = json.load(f)
        result = {}
        for p in data.get('List of plugins', []):
            key = re.sub(r'\s+', '', p.get('Name', ''))
            result[key] = {
                'marketplace': p.get('Marketplace', ''),
                'url':         p.get('Link to plugin', ''),
            }
        return result
    except Exception:
        return {}


async def _handle_oxide_updates(req):
    names_param = req.rel_url.query.get('plugins', '')
    if not names_param:
        return web.json_response({})
    slugs = [n.strip() for n in names_param.split(',') if n.strip()][:50]

    uc_map = await asyncio.to_thread(_load_uc_map)
    sem = asyncio.Semaphore(6)
    hdrs = {'User-Agent': f'RconPanel/{_APP_VERSION}'}

    async def _check_one(slug):
        async with sem:
            info     = uc_map.get(slug, {})
            page_url = info.get('url', '')
            # Query ServerArmour: use known page URL when available (exact match),
            # otherwise search by slug name — same strategy as UpdateChecker plugin.
            query    = page_url if page_url else slug
            sa_url   = f'https://serverarmour.com/api/v3/marketplace/search?plugin={query}'
            try:
                async with _http_session.get(sa_url, timeout=aiohttp.ClientTimeout(total=12), headers=hdrs) as resp:
                    if resp.status != 200:
                        return slug, {'found': False, 'latest': '', 'marketplace': '', 'url': page_url, 'download_url': ''}
                    d = await resp.json(content_type=None)
                if d.get('status') != 200 or not d.get('data'):
                    return slug, {'found': False, 'latest': '', 'marketplace': '', 'url': page_url, 'download_url': ''}
                items = d['data']
                # When querying by URL the first result is always the right plugin.
                # When querying by name, find exact slug/name match.
                if page_url:
                    best = items[0]
                else:
                    sl = slug.lower()
                    best = next(
                        (x for x in items
                         if (x.get('slug') or '').lower().replace('-','') == sl
                         or (x.get('name') or '').lower().replace(' ','') == sl),
                        None
                    )
                if not best:
                    return slug, {'found': False, 'latest': '', 'marketplace': '', 'url': page_url, 'download_url': ''}
                mp  = best.get('marketplace', '')
                url = best.get('url', '') or page_url
                # For uMod plugins the download URL is simply {slug}.cs
                dl  = f'https://umod.org/plugins/{slug}.cs' if mp == 'uMod' else ''
                return slug, {'found': True, 'latest': best.get('latestVersion', ''),
                               'marketplace': mp, 'url': url, 'download_url': dl}
            except Exception:
                return slug, {'found': False, 'latest': '', 'marketplace': '', 'url': page_url, 'download_url': ''}

    results = await asyncio.gather(*[_check_one(s) for s in slugs])
    return web.json_response(dict(results))


async def _handle_oxide_update(req):
    """Download a uMod plugin .cs file and reload it via RCON."""
    try:
        d = await req.json()
    except Exception:
        return web.json_response({'ok': False, 'error': 'Invalid JSON'}, status=400)
    name         = (d.get('name') or '').strip()
    download_url = (d.get('download_url') or '').strip()
    if not name or not download_url:
        return web.json_response({'ok': False, 'error': 'name and download_url required'}, status=400)
    if not re.match(r'^\w+$', name):
        return web.json_response({'ok': False, 'error': 'invalid plugin name'}, status=400)
    if not download_url.startswith('https://umod.org/'):
        return web.json_response({'ok': False, 'error': 'only uMod downloads supported'}, status=400)
    plugin_path = f'/home/steam/rustserver/oxide/plugins/{name}.cs'
    tmp_path    = plugin_path + '.tmp'
    try:
        async with _http_session.get(download_url, timeout=aiohttp.ClientTimeout(total=30),
                                      headers={'User-Agent': f'RconPanel/{_APP_VERSION}'}) as resp:
            if resp.status != 200:
                return web.json_response({'ok': False, 'error': f'Download failed: HTTP {resp.status}'}, status=502)
            content = await resp.read()
    except Exception as e:
        return web.json_response({'ok': False, 'error': f'Download error: {e}'}, status=502)
    if len(content) < 50 or (b'class ' not in content and b'namespace' not in content):
        return web.json_response({'ok': False, 'error': 'Downloaded content does not look like a plugin'}, status=502)
    try:
        def _write():
            with open(tmp_path, 'wb') as f:
                f.write(content)
            os.replace(tmp_path, plugin_path)
        await asyncio.to_thread(_write)
    except Exception as e:
        return web.json_response({'ok': False, 'error': f'Write failed: {e}'}, status=500)
    try:
        result = await _rcon_query(f'oxide.reload {name}', timeout=15.0)
        return web.json_response({'ok': True, 'result': result.strip()})
    except Exception as e:
        return web.json_response({'ok': True, 'result': f'Downloaded OK — reload: {e}'})


async def _cleanup_loop():
    while True:
        await asyncio.sleep(300)
        now = time.time()
        expired = [k for k, v in list(_sessions.items()) if now > v]
        for k in expired:
            _sessions.pop(k, None)
        stale = [k for k, v in list(_login_attempts.items())
                 if not any(now - t < 600 for t in v)]
        for k in stale:
            _login_attempts.pop(k, None)


async def _startup(app):
    global _rcon_restart, _profiles_lock, _http_session
    _rcon_restart = asyncio.Event()
    _profiles_lock = asyncio.Lock()
    _http_session = aiohttp.ClientSession()
    if _rcon_cfg:
        _rcon_restart.set()
    app['rcon']    = asyncio.create_task(_rcon_loop())
    app['cleanup'] = asyncio.create_task(_cleanup_loop())
    url = CONFIG.get('map', {}).get('image_url', '')
    if url:
        asyncio.create_task(_fetch_map_url(url))


async def _cleanup(app):
    for key in ('rcon', 'cleanup'):
        app[key].cancel()
    await asyncio.gather(app['rcon'], app['cleanup'], return_exceptions=True)
    await _http_session.close()


def _build_ssl_ctx(ssl_cfg: dict):
    mode = (ssl_cfg.get('mode') or 'none').lower()
    if mode == 'none':
        return None
    cert = ssl_cfg.get('cert', '')
    key  = ssl_cfg.get('key', '')
    if not cert or not key:
        print(f'SSL mode "{mode}" configured but cert/key missing — running HTTP')
        return None
    for p, label in ((cert, 'cert'), (key, 'key')):
        if not os.path.exists(p):
            print(f'SSL {label} not found: {p} — running HTTP')
            return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def main():
    global CONFIG, _rcon_q, _player_db_path, _profiles_path, _active_profile_id, _rcon_cfg, _secret_key_path
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    if not os.path.exists(cfg_path):
        raise SystemExit(f'Config not found: {cfg_path}')
    with open(cfg_path) as f:
        CONFIG = json.load(f)

    _player_db_path = os.path.join(os.path.dirname(cfg_path), 'players.json')
    _load_player_db()

    _secret_key_path = os.path.join(os.path.dirname(cfg_path), '.secret_key')
    _init_fernet()

    _profiles_path = os.path.join(os.path.dirname(cfg_path), 'profiles.json')
    _load_profiles()
    _migrate_profile_passwords()

    # Hash plaintext web password on first start
    web_pwd = CONFIG.get('web', {}).get('password', '')
    if web_pwd and not web_pwd.startswith('pbkdf2:'):
        CONFIG['web']['password'] = _hash_web_pwd(web_pwd)
        with open(cfg_path, 'w') as f:
            json.dump(CONFIG, f, indent=2)

    # Bootstrap a default profile from config.json rcon section if none saved yet,
    # then remove the plaintext rcon section so credentials only live in profiles.json
    rcon_cfg = CONFIG.pop('rcon', {})
    if not _profiles and rcon_cfg.get('host'):
        default_id = os.urandom(6).hex()
        _profiles.append({
            'id': default_id,
            'name': rcon_cfg.get('host', 'Default Server'),
            'host': rcon_cfg['host'],
            'port': int(rcon_cfg.get('port', 28016)),
            'password': rcon_cfg.get('password', ''),
        })
        _save_profiles()
    if rcon_cfg:  # was present — rewrite config.json without it
        with open(cfg_path, 'w') as f:
            json.dump(CONFIG, f, indent=2)

    # Auto-connect to last-used profile on startup
    last_id = CONFIG.get('web', {}).get('last_profile_id', '')
    if _profiles:
        p = next((x for x in _profiles if x['id'] == last_id), _profiles[0])
        _active_profile_id = p['id']
        _rcon_cfg = {'host': p['host'], 'port': p['port'], 'password': _decrypt_pwd(p['password'])}

    _rcon_q = asyncio.Queue()

    app = web.Application(middlewares=[_auth])
    app.router.add_get('/',                       _handle_index)
    app.router.add_get('/favicon.svg',            _handle_favicon)
    app.router.add_get('/ws',                     _handle_ws)
    app.router.add_get('/api/cfg',                _handle_api_cfg)
    app.router.add_get('/api/worldcfg',           _handle_api_worldcfg)
    app.router.add_get('/api/about',              _handle_about)
    app.router.add_get('/api/monuments',          _handle_monuments)
    app.router.add_get('/monuments',              _handle_monuments_public)
    app.router.add_get('/api/players',            _handle_players_api)
    app.router.add_get('/mapimg',                 _handle_mapimg)
    app.router.add_get('/api/mapimg/refresh',     _handle_mapimg_refresh)
    app.router.add_get('/api/profiles',           _handle_profiles_get)
    app.router.add_post('/api/profiles',          _handle_profiles_post)
    app.router.add_delete('/api/profiles/{id}',   _handle_profiles_delete)
    app.router.add_post('/api/connect',           _handle_connect)
    app.router.add_get('/api/ping',               _handle_ping)
    app.router.add_get('/api/bans',               _handle_bans)
    app.router.add_post('/api/unban',             _handle_unban)
    app.router.add_get('/api/oxide',              _handle_oxide)
    app.router.add_post('/api/oxide/action',      _handle_oxide_action)
    app.router.add_get('/api/oxide/updates',      _handle_oxide_updates)
    app.router.add_post('/api/oxide/update',      _handle_oxide_update)
    app.router.add_get('/login',                  _handle_login_get)
    app.router.add_post('/login',                 _handle_login_post)
    app.router.add_get('/logout',                 _handle_logout)
    app.router.add_post('/api/settings/password', _handle_settings_password)
    app.on_startup.append(_startup)
    app.on_cleanup.append(_cleanup)

    host      = CONFIG['web'].get('host', '0.0.0.0')
    port      = int(CONFIG['web'].get('port', 8080))
    http_port = int(CONFIG['web'].get('http_port', 80))
    ssl_cfg   = CONFIG.get('web', {}).get('ssl') or {}
    ssl_ctx   = _build_ssl_ctx(ssl_cfg)

    if ssl_ctx:
        async def _http_redir(req):
            h    = req.headers.get('Host', '').split(':')[0]
            dest = f'https://{h}' + (f':{port}' if port != 443 else '') + req.path_qs
            raise web.HTTPMovedPermanently(dest)

        async def _run_https():
            redir_app = web.Application()
            redir_app.router.add_route('*', '/{path:.*}', _http_redir)
            runner       = web.AppRunner(app,       access_log=None)
            redir_runner = web.AppRunner(redir_app, access_log=None)
            await runner.setup()
            await redir_runner.setup()
            await web.TCPSite(runner,       host, port,      ssl_context=ssl_ctx).start()
            await web.TCPSite(redir_runner, host, http_port).start()
            print(f'Rust RCON Panel  →  https://{host}:{port}')
            print(f'HTTP redirect    →  :{http_port} → https:{port}')
            print('======== Running on https ========')
            try:
                await asyncio.Event().wait()
            finally:
                await runner.cleanup()
                await redir_runner.cleanup()

        asyncio.run(_run_https())
    else:
        print(f'Rust RCON Panel  →  http://{host}:{port}')
        web.run_app(app, host=host, port=port, access_log=None)


if __name__ == '__main__':
    main()
