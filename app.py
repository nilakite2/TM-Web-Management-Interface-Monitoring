import os
os.environ.setdefault("SIMPLE_WEBSOCKET_ASYNC_MODE", "eventlet")

import eventlet
eventlet.monkey_patch()

import io
import json
import re
import subprocess
import time
import socket
import struct
from collections import deque, defaultdict
from eventlet.semaphore import Semaphore
_PM2_LOCKS = defaultdict(Semaphore)
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

import psutil
import requests
import yaml

# Load .env
try:
    from dotenv import load_dotenv
    import os
    DOTENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
    load_dotenv(DOTENV_PATH)
except Exception:
    pass

# Flask stack
from flask import (
    Flask, request, session, jsonify, redirect, send_file
)
from werkzeug.exceptions import HTTPException
from authlib.integrations.flask_client import OAuth
from flask_sock import Sock

# Optional: wexpect for interactive pm2 attach on Windows
try:
    import wexpect as pexpect  # type: ignore
    HAVE_WEXPECT = True
except Exception:
    pexpect = None  # type: ignore
    HAVE_WEXPECT = False


# =============================================================================
# Configuration
# =============================================================================

CFG_PATH = os.environ.get("SERVERS_YAML", "servers.yaml")
with open(CFG_PATH, "r", encoding="utf-8") as f:
    CFG = yaml.safe_load(f)

SET = CFG.get("settings", {})
SESSION_SECRET = (
    os.environ.get("SESSION_SECRET")
    or SET.get("session_secret")
    or "dev_session_secret_change_me"
)
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID") or SET.get("discord_client_id")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET") or SET.get("discord_client_secret")
OAUTH_REDIRECT_URL = (
    os.environ.get("OAUTH_REDIRECT_URL")
    or SET.get("oauth_redirect_url")
    or "http://localhost:8000/auth/callback"
)

ADMIN_IDS = set(SET.get("admin_discord_ids", []))
WEBHOOK = os.environ.get("DISCORD_WEBHOOK") or SET.get("discord_webhook", "")

# Default to empty (no mentions) unless explicitly provided
MENTION_TEXT = (SET.get("mention_text") or os.environ.get("MENTION_TEXT") or "").strip()

STATE_FILE = SET.get("state_file", os.path.join(os.getcwd(), "tm-monitor-state.txt"))
LOG_FILE = SET.get("monitor_log", os.path.join(os.getcwd(), "AutoLogs.txt"))
ALWAYS_POST_ON_FIRST_RUN = True

PHP56_DEFAULT = SET.get("php56") or CFG.get("php56") or r"C:\xampp\php56\php.exe"

# Defaults for direct XML-RPC if instance doesn’t override
DEFAULT_RPC_USER = SET.get("default_rpc_user") or SET.get("rpc_user") or "SuperAdmin"
DEFAULT_RPC_PASS = SET.get("default_rpc_pass") or SET.get("rpc_pass") or ""

# Trakman / PM2
INSTANCES = CFG.get("instances", [])
INSTANCE_NAME = os.environ.get("COMPUTERNAME", "WIN")
CREATE_NEW_CONSOLE = 0x00000010 if os.name == "nt" else 0

# =============================================================================
# Group-based auth helpers
# =============================================================================

USER_GROUPS = SET.get("user_groups", {})

# Normalize group_admins to: { "amp": {"id1","id2"}, "nila": {"id3"} }
GROUP_ADMINS = {
    (g or "").strip().lower(): set(map(str, ids or []))
    for g, ids in (SET.get("group_admins", {}) or {}).items()
}

def is_superadmin(user: Optional[dict]) -> bool:
    return bool(user and user.get("id") in ADMIN_IDS)

def is_group_admin_for_inst(user: Optional[dict], inst: dict) -> bool:
    if not user:
        return False
    if is_superadmin(user):
        return True
    group = (inst.get("group") or "").strip().lower()
    if not group:
        return False
    return user.get("id") in GROUP_ADMINS.get(group, set())

def current_user() -> Optional[dict]:
    return session.get("user")

def require_inst_admin(inst: dict) -> dict:
    u = current_user()
    if not u:
        abort_json(401, "Login required")
    if is_group_admin_for_inst(u, inst):
        return u
    abort_json(403, "Insufficient permissions for this instance")

def require_admin() -> dict:
    u = current_user()
    if not u:
        abort_json(401, "Login required")
    if u.get("id") not in ADMIN_IDS:
        abort_json(403, "Admin only")
    return u


# =============================================================================
# Utilities
# =============================================================================

def abort_json(code: int, message: str):
    resp = jsonify({"error": message})
    resp.status_code = code
    # Immediately stop request
    raise HTTPException(response=resp)

def log_line(msg: str) -> None:
    ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def _norm(p: Optional[str]) -> Optional[str]:
    return os.path.normcase(os.path.normpath(p)) if p else p

def _server_dir_from_bat(bat_path: Optional[str]) -> Optional[str]:
    return _norm(os.path.dirname(bat_path)) if bat_path else None

def is_tm_server_alive(server_dir: Optional[str]) -> bool:
    if not server_dir:
        return False
    target = _norm(server_dir)
    for p in psutil.process_iter(["pid", "name", "cwd", "exe"]):
        try:
            cwd = p.info.get("cwd")
            if cwd and _norm(cwd) == target:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


# =============================================================================
# PM2 helpers (Trakman)
# =============================================================================

def pm2_jlist() -> list:
    try:
        out = subprocess.check_output("pm2 jlist", shell=True, encoding="utf-8", errors="ignore")
        return json.loads(out)
    except Exception:
        return []

def get_pm2_id_by_name(name: str) -> Optional[int]:
    try:
        for proc in pm2_jlist():
            if proc.get("name") == name:
                return proc.get("pm_id")
    except Exception as e:
        log_line(f"[PM2] jlist error: {e}")
    return None

def pm2_is_online(name: str) -> bool:
    for proc in pm2_jlist():
        if proc.get("name") == name and proc.get("pm2_env", {}).get("status") == "online":
            return True
    return False

def pm2_attach_send_capture(
    pm2_name: str,
    commands: List[str],
    *,
    wait_between: float = 0.8,        # delay after each send/Enter
    settle_after: float = 1.8,        # fallback settle if we didn’t detach earlier
    attach_timeout: float = 6.0,      # timeout for the attach spawn
    extra_enter_on_last: bool = False,# keep FALSE so last cmd (e.g. //kc) doesn’t reopen CLI
    detach_after_last: bool = True,   # TRUE = Ctrl+C right after the last cmd settles
    settle_after_last: float = 0.5    # small settle after last cmd before Ctrl+C
) -> dict:
    """
    Attach to a PM2 process, open Trakman CLI, execute commands.
    - Sends an extra Enter BETWEEN commands so the CLI reopens.
    - By default does NOT send an extra Enter after the last command,
      and detaches (Ctrl+C) shortly after it (good for //kc).
    """
    if not HAVE_WEXPECT:
        raise RuntimeError("wexpect is not available on this host")

    lock = _PM2_LOCKS[pm2_name]
    with lock:
        pm2_id = get_pm2_id_by_name(pm2_name)
        if pm2_id is None:
            raise RuntimeError(f"PM2 process '{pm2_name}' not found")

        buf = io.StringIO()
        detached = False
        try:
            child = pexpect.spawn(f"pm2 attach {pm2_id}", encoding="utf-8", timeout=attach_timeout)  # type: ignore
            child.logfile = buf

            # Open Trakman CLI
            try:
                child.sendline("")               # press Enter to open CLI
                time.sleep(wait_between)
                try:
                    child.expect(r"Run command as server:.*", timeout=2)
                except Exception:
                    pass
            except Exception:
                pass

            for i, cmd in enumerate(commands or []):
                last = (i == len(commands) - 1)

                # 1) send the command
                child.sendline(cmd)
                time.sleep(wait_between)

                # 2) send extra Enter ONLY between commands (or if explicitly requested on last)
                if (not last) or (last and extra_enter_on_last):
                    child.sendline("")
                    time.sleep(wait_between)

                # 3) detach immediately after the last command if requested
                if last and detach_after_last:
                    time.sleep(settle_after_last)
                    try:
                        child.sendcontrol("c")   # detach
                        time.sleep(0.4)
                    except Exception:
                        pass
                    detached = True
                    break

            # If we didn’t detach inside the loop (e.g., custom params)
            if not detached:
                time.sleep(settle_after)
                try:
                    child.sendcontrol("c")
                    time.sleep(0.4)
                except Exception:
                    pass

            try:
                child.terminate(force=True)
            except Exception:
                pass

            return {"pm2_id": pm2_id, "output": buf.getvalue()}

        finally:
            try:
                buf.close()
            except Exception:
                pass

def trakman_send(inst: dict, message: str) -> bool:
    """
    For Trakman instances:
      - If message looks like a command ('/' or '//'), run it in the Trakman console via PM2 attach.
      - Otherwise, broadcast it using the dedicated server's XML-RPC ChatSend.
    Returns True on success, False on failure.
    """
    t = (inst.get("type") or "").lower()
    if t != "trakman":
        raise RuntimeError("trakman_send called on non-trakman instance")

    msg = (message or "").strip()
    if not msg:
        return False

    # 1) Commands → run in Trakman console so ChatService handles them
    if msg.startswith("/") or msg.startswith("//"):
        pm2_name = inst.get("pm2_name") or inst["name"]
        # Optionally mirror ChatService.serverCommand behavior (prepend //sm if no slash),
        # but since we already require leading slash(es), just send as-is:
        pm2_attach_send_capture(pm2_name, [msg])
        return True

    # 2) Plain chat → broadcast via dedicated XML-RPC
    login = inst.get("xmlrpc_login") or DEFAULT_RPC_USER
    pw    = inst.get("xmlrpc_password") if inst.get("xmlrpc_password") is not None else DEFAULT_RPC_PASS
    if not login or pw is None:
        raise RuntimeError("xmlrpc_login/xmlrpc_password not configured for the instance")

    res = gbx_call_sequence(inst, [
        ("Authenticate", [login, pw]),
        ("ChatSend", [msg]),
    ], timeout=5.0)
    if not res or not res[0]:
        raise RuntimeError("Authenticate returned falsy")
    if not res[1]:
        raise RuntimeError("ChatSend returned falsy")
    return True

# =============================================================================
# Dedicated server XML-RPC (direct)
# =============================================================================

class DediRPCError(Exception):
    pass

def _pick(inst: dict, *keys: str, default=None):
    for k in keys:
        if k in inst and inst[k] not in (None, ""):
            return inst[k]
    return default

def get_dedi_conn_info(inst: dict) -> Tuple[str, int, str, str]:
    host = _pick(inst, "rpc_host", "xmlrpc_host", "host", default="127.0.0.1")
    port = _pick(inst, "rpc_port", "xmlrpc_port", "xmlrpc", "port", default=None)
    if port is None:
        raise DediRPCError("Instance is missing XML-RPC port (rpc_port/xmlrpc_port)")
    try:
        port = int(port)
    except Exception:
        raise DediRPCError("Invalid XML-RPC port for instance")
    user = _pick(inst, "rpc_user", "xmlrpc_user", "server_login", default=DEFAULT_RPC_USER)
    pw   = _pick(inst, "rpc_pass", "xmlrpc_pass", "server_password", default=DEFAULT_RPC_PASS)
    if not user:
        raise DediRPCError("Missing XML-RPC user (rpc_user / server_login)")
    return str(host), int(port), str(user), str(pw)

_GBX_REQ_ID = 0x80000000

def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))

def _xml_val(v):
    if v is None:
        return "<nil/>"
    if isinstance(v, bool):
        return f"<boolean>{1 if v else 0}</boolean>"
    if isinstance(v, int):
        return f"<int>{v}</int>"
    if isinstance(v, float):
        return f"<double>{v}</double>"
    if isinstance(v, (list, tuple)):
        inner = "".join(f"<value>{_xml_val(x)}</value>" for x in v)
        return f"<array><data>{inner}</data></array>"
    if isinstance(v, dict):
        items = "".join(f"<member><name>{k}</name><value>{_xml_val(val)}</value></member>" for k, val in v.items())
        return f"<struct>{items}</struct>"
    s = _xml_escape(str(v))
    return f"<string>{s}</string>"

def _xml_build_call(method: str, params: list) -> bytes:
    params_xml = "".join(f"<param><value>{_xml_val(p)}</value></param>" for p in (params or []))
    xml = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>{method}</methodName>
  <params>{params_xml}</params>
</methodCall>"""
    return xml.encode("utf-8")

def _xml_parse_value(val_el: ET.Element):
    if len(list(val_el)) == 0 and val_el.text is not None:
        return val_el.text
    child = next(iter(val_el), None)
    if child is None:
        return None
    tag = child.tag.lower()
    tx = (child.text or "")
    if tag.endswith("i4") or tag.endswith("int"):
        return int(tx or "0")
    if tag.endswith("boolean"):
        return tx.strip() in ("1", "true", "True")
    if tag.endswith("double"):
        return float(tx or "0")
    if tag.endswith("string"):
        return tx
    if tag.endswith("array"):
        data = child.find(".//data")
        out = []
        if data is not None:
            for v in data.findall("value"):
                out.append(_xml_parse_value(v))
        return out
    if tag.endswith("struct"):
        out = {}
        for m in child.findall("member"):
            name_el = m.find("name")
            ve = m.find("value")
            if name_el is not None and ve is not None:
                out[name_el.text or ""] = _xml_parse_value(ve)
        return out
    return tx

def _xml_parse_response(body: bytes):
    root = ET.fromstring(body)
    fault = root.find(".//fault")
    if fault is not None:
        val = fault.find("value")
        data = _xml_parse_value(val) if val is not None else None
        if isinstance(data, dict):
            code = data.get("faultCode", -1)
            string = data.get("faultString", "Fault")
        else:
            code = -1
            string = str(data)
        raise RuntimeError(f"XML-RPC fault [{code}]: {string}")
    val = root.find(".//params/param/value")
    return _xml_parse_value(val) if val is not None else None

def _gbx_recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("Socket closed while reading")
        buf += chunk
    return buf

def _gbx_expect_handshake(sock: socket.socket, *, timeout: float = 3.0) -> None:
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(32)
            if not chunk:
                break
            buf += chunk
            if b"GBXRemote 2" in buf:
                return
            if len(buf) > 64:
                return
    except socket.timeout:
        return

def gbx_call_sequence(inst: dict, calls: list[tuple[str, list]], timeout: float = 5.0) -> list:
    host = inst.get("xmlrpc_host") or "127.0.0.1"
    port = int(inst.get("xmlrpc_port"))
    if not port:
        raise RuntimeError("xmlrpc_port missing for instance")
    global _GBX_REQ_ID
    results: list = []
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        try:
            _gbx_expect_handshake(s)
        except Exception:
            pass
        for method, params in calls:
            xml_bytes = _xml_build_call(method, params or [])
            _GBX_REQ_ID = (_GBX_REQ_ID + 1) & 0xFFFFFFFF
            header = struct.pack("<II", len(xml_bytes), _GBX_REQ_ID)
            s.sendall(header + xml_bytes)
            hdr = _gbx_recvn(s, 8)
            resp_len, _resp_id = struct.unpack("<II", hdr)
            body = _gbx_recvn(s, resp_len)
            results.append(_xml_parse_response(body))
    return results

def _xmlrpc_call(inst: dict, method: str, params: list | None = None, timeout: float = 10.0):
    host = inst.get("xmlrpc_host") or "127.0.0.1"
    port = int(inst.get("xmlrpc_port"))
    paths = [inst.get("xmlrpc_path"), "/RPC2", "/"]
    paths = [p for p in paths if p]
    req = _xml_build_call(method, params or [])
    last_err = None
    for p in paths:
        if not p.startswith("/"): p = "/" + p
        url = f"http://{host}:{port}{p}"
        try:
            r = requests.post(url, data=req, headers={"Content-Type":"text/xml","Connection":"keep-alive"}, timeout=timeout)
            r.raise_for_status()
            return _xml_parse_response(r.content)
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("No XML-RPC path attempted")

def _ensure_authenticated(inst: dict, force: bool = False):
    # Simplified: per-call auth is usually done inline, but keep helper in case you reuse.
    login = inst.get("xmlrpc_login")
    pw = inst.get("xmlrpc_password")
    if not login or not pw:
        raise RuntimeError("xmlrpc_login/xmlrpc_password not configured for instance")
    host = inst.get("xmlrpc_host") or "127.0.0.1"
    port = int(inst.get("xmlrpc_port"))
    log_line(f"[DediRPC/{inst['name']}] Authenticate → {host}:{port} as {login}")
    ok = _xmlrpc_call(inst, "Authenticate", [login, pw])
    if not ok:
        raise RuntimeError("Authenticate failed (server returned falsy)")


# =============================================================================
# Instance control (server & controller)
# =============================================================================

def start_server(inst: dict) -> None:
    if inst.get("server_bat") and os.path.exists(inst["server_bat"]):
        subprocess.Popen(f'start "" "{inst["server_bat"]}"', shell=True, cwd=os.path.dirname(inst["server_bat"]))

def stop_server(inst: dict) -> None:
    sdir = _server_dir_from_bat(inst.get("server_bat")) if inst.get("server_bat") else None
    if not sdir:
        return
    target = _norm(sdir)
    for p in psutil.process_iter(["pid", "name", "cwd", "exe"]):
        try:
            cwd = p.info.get("cwd")
            if cwd and _norm(cwd) == target:
                p.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def restart_server(inst: dict) -> None:
    stop_server(inst)
    time.sleep(1)
    start_server(inst)

def start_controller(inst: dict) -> None:
    t = (inst.get("type") or "").lower()
    if t == "trakman":
        name = inst.get("pm2_name") or inst["name"]
        tdir = inst["trakman_dir"]
        subprocess.Popen(f'pm2 start ./built/src/Main.js --name {name} --cwd "{tdir}"', shell=True)
        return
    xdir = inst.get("xaseco_dir") or (os.path.dirname(inst.get("xaseco_bat", "")) if inst.get("xaseco_bat") else "")
    if not xdir or not os.path.isdir(xdir):
        log_line(f"[{inst['name']}] XAseco start: xaseco_dir missing")
        return
    php56 = inst.get("php56") or PHP56_DEFAULT
    try:
        subprocess.Popen([php56, "aseco.php", f"--name={inst.get('xaseco_name') or inst['name']}"], cwd=xdir, creationflags=CREATE_NEW_CONSOLE)
        log_line(f"[{inst['name']}] XAseco started via PHP.")
    except Exception as e:
        log_line(f"[{inst['name']}] XAseco PHP start failed: {e}")

def stop_controller(inst: dict) -> None:
    t = (inst.get("type") or "").lower()
    if t == "trakman":
        name = inst.get("pm2_name") or inst["name"]
        subprocess.Popen(f'pm2 delete {name}', shell=True)
        return
    xdir = _norm(inst.get("xaseco_dir") or (os.path.dirname(inst.get("xaseco_bat", "")) if inst.get("xaseco_bat") else ""))
    if not xdir:
        return
    for p in psutil.process_iter(["pid", "name", "cwd", "cmdline"]):
        try:
            if p.info.get("name", "").lower() == "php.exe":
                cwd = p.info.get("cwd")
                if cwd and _norm(cwd) == xdir:
                    p.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def restart_controller(inst: dict) -> None:
    t = (inst.get("type") or "").lower()
    if t == "trakman":
        name = inst.get("pm2_name") or inst["name"]
        if pm2_is_online(name):
            subprocess.Popen(f'pm2 restart {name}', shell=True)
        else:
            stop_controller(inst)
            time.sleep(1)
            start_controller(inst)
    else:
        stop_controller(inst)
        time.sleep(1)
        start_controller(inst)

def start_instance(inst: dict) -> None:
    start_server(inst)
    start_controller(inst)

def stop_instance(inst: dict) -> None:
    stop_controller(inst)
    time.sleep(1)
    stop_server(inst)

def restart_instance(inst: dict) -> None:
    stop_instance(inst)
    time.sleep(1)
    start_instance(inst)


# =============================================================================
# Discord notifications
# =============================================================================

def _build_allowed_mentions(mention_enabled: bool) -> dict:
    if not mention_enabled or not MENTION_TEXT:
        return {"parse": []}
    if MENTION_TEXT.startswith("<@&") and MENTION_TEXT.endswith(">"):
        rid = MENTION_TEXT.strip("<@&>").strip(">")
        return {"parse": [], "roles": [rid]}
    if MENTION_TEXT.startswith("<@") and MENTION_TEXT.endswith(">"):
        uid = MENTION_TEXT.strip("<@!>").strip(">")
        return {"parse": [], "users": [uid]}
    return {"parse": []}

def monitor_post_discord(title: str, desc: str, mention: bool = False) -> None:
    if not WEBHOOK:
        return
    prefix = (MENTION_TEXT + " ") if (mention and MENTION_TEXT) else ""
    allowed = _build_allowed_mentions(mention)
    payload = {
        "content": f"{prefix}{title}",
        "embeds": [{
            "title": title,
            "description": desc,
            "footer": {"text": "tm-discord-monitor • " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
        }],
        "allowed_mentions": allowed,
    }
    try:
        requests.post(WEBHOOK, json=payload, timeout=10)
        log_line("[Discord] Monitor message sent.")
    except Exception as e:
        log_line(f"[Discord] Monitor post error: {e}")


# =============================================================================
# Monitoring (background thread runs asyncio coroutines)
# =============================================================================

REFRESH_SECONDS = int(SET.get("monitor_refresh_seconds", 600))  # default 10 min
MONITOR_FLAGS_FILE = SET.get(
    "monitor_state_file",
    os.path.join(os.getcwd(), "monitor-flags.json")
)
TRAKMAN_RESTART_HOURS = float(SET.get("trakman_restart_hours", 27))
TRAKMAN_PLAYER_CHECK_MINUTES = float(SET.get("trakman_player_check_minutes", 15))

# name -> {"enabled": bool, "start_time": datetime, "last_player_check": datetime}
_MON: dict[str, dict] = {}
_NEXT_RUN_AT: Optional[datetime] = None

def _load_monitor_flags() -> dict[str, bool]:
    try:
        if os.path.exists(MONITOR_FLAGS_FILE):
            with open(MONITOR_FLAGS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f) or {}
                return {str(k): bool(v) for k, v in raw.items()}
    except Exception as e:
        log_line(f"[MonitorFlags] load failed: {e}")
    # default: disabled unless explicitly turned on
    return {}

_MONITOR_FLAGS = _load_monitor_flags()

def _set_mon_defaults(name: str) -> None:
    if name not in _MON:
        _MON[name] = {
            "start_time": datetime.now(),
            "last_player_check": datetime.min.replace(tzinfo=None)
        }

def _read_state() -> tuple[str, bool]:
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return f.read(), True
    except Exception as e:
        log_line(f"[State] Read failed: {e}")
    return "", False

def _write_state(s: str) -> None:
    try:
        folder = os.path.dirname(STATE_FILE)
        if folder and not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(s)
    except Exception as e:
        log_line(f"[State] Write failed: {e}")

def _save_monitor_flags(flags: dict[str, bool]) -> None:
    try:
        tmp = MONITOR_FLAGS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(flags, f, indent=2)
        os.replace(tmp, MONITOR_FLAGS_FILE)
    except Exception as e:
        log_line(f"[MonitorFlags] save failed: {e}")

def find_running_servers() -> Set[str]:
    expected_dirs = {
        _norm(_server_dir_from_bat(i.get("server_bat")))
        for i in INSTANCES if i.get("server_bat")
    }
    running: Set[str] = set()
    for p in psutil.process_iter(["name", "cwd"]):
        try:
            cwd = p.info.get("cwd")
            if cwd:
                n = _norm(cwd)
                if n in expected_dirs:
                    running.add(n)  # type: ignore[arg-type]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return running

def _tail_last_lines(filepath: str, n: int = 6) -> List[str]:
    lines: deque[str] = deque(maxlen=n)
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                lines.append(line.strip())
    except Exception as e:
        log_line(f"[Log] Could not read {filepath}: {e}")
    return list(lines)

def graceful_restart_trakman_server(inst: dict) -> None:
    """
    Performs a graceful restart for a Trakman server, using per-instance
    overrides from servers.yaml when present.

    Supported per-instance keys (all optional):
      restart_pre_commands:  list[str]   # sent to PM2 console BEFORE starting server again
      restart_wait_before_start: float   # seconds to wait after pre-commands
      restart_wait_after_start: float    # seconds to wait after starting server
      restart_post_commands: list[str]   # sent to PM2 console AFTER starting server
    """
    name = inst["name"]
    pm2_name = inst.get("pm2_name") or name

    # Defaults match your current behavior
    pre_cmds  = inst.get("restart_pre_commands")  or ["//svms", "//s", "//sd"]
    wait_pre  = float(inst.get("restart_wait_before_start", 5.0))
    wait_post = float(inst.get("restart_wait_after_start", 30.0))
    post_cmds = inst.get("restart_post_commands") or ["//kc"]

    log_line(f"[{name}] Restarting server (graceful)…")
    try:
        # Send pre-commands (e.g., save, stop, shutdown)
        if pre_cmds:
            pm2_attach_send_capture(pm2_name, pre_cmds)

        # Give controller time to process shutdown
        if wait_pre > 0:
            time.sleep(wait_pre)

        # Start dedicated server again
        start_server(inst)

        # Let the server come up
        if wait_post > 0:
            time.sleep(wait_post)

        # Send post-commands (e.g., //kc to reconnect) and detach immediately after last
        if post_cmds:
            pm2_attach_send_capture(
                pm2_name,
                post_cmds,
                extra_enter_on_last=False,   # don’t reopen CLI after //kc
                detach_after_last=True,      # Ctrl+C after //kc
                settle_after_last=0.5        # tiny pause to let output flush
            )

    except Exception as e:
        log_line(f"[{name}] graceful restart exception: {e}")
    log_line(f"[{name}] Restart complete.")

def graceful_restart_xaseco(inst: dict) -> None:
    name  = inst["name"]
    login = inst.get("xmlrpc_login")
    pw    = inst.get("xmlrpc_password")
    if not login or pw is None:
        log_line(f"[{name}] Missing XML-RPC creds; aborting XAseco restart.")
        return

    # Pull per-instance, else global defaults from settings:
    pre_chat = inst.get("restart_chat_pre") or SET.get("xaseco_restart_pre_chat", [
        "/admin writetracklist", "/admin writeabilities", "/admin skip"
    ])
    wait_before_shutdown = float(inst.get("restart_wait_before_shutdown",
                                SET.get("xaseco_restart_wait_before_shutdown", 60)))
    shutdown_cmd = inst.get("shutdown_command",
                            SET.get("xaseco_shutdown_command", "/admin shutdownall"))
    wait_after_start = float(inst.get("restart_wait_after_start",
                              SET.get("xaseco_restart_wait_after_start", 30)))

    log_line(f"[{name}] XAseco graceful restart…")

    def _send(cmd: str, delay: float = 0.5):
        try:
            gbx_call_sequence(inst, [("Authenticate", [login, pw]), ("ChatSend", [cmd])], timeout=5.0)
            time.sleep(delay)
        except Exception as e:
            log_line(f"[{name}] ChatSend '{cmd}' failed: {e}")

    # 1) pre-commands
    for cmd in pre_chat:
        _send(cmd)

    # 2) wait before shutdown (let writes/skip settle)
    time.sleep(wait_before_shutdown)

    # 3) shutdown both
    _send(shutdown_cmd, delay=1.0)

    # 4) start server & controller again
    start_server(inst)
    time.sleep(wait_after_start)
    start_controller(inst)

    log_line(f"[{name}] XAseco graceful restart complete.")

def assess_and_notify(force: bool = False) -> None:
    """Checks basic up/down, but only for instances with monitor enabled."""
    enabled_names = {n for n, on in _MONITOR_FLAGS.items() if on}
    down: List[str] = []

    for inst in INSTANCES:
        name = inst["name"]
        if name not in enabled_names:
            continue  # monitoring disabled → ignore in outage reports

        # --- Server status (exe-name aware, falls back to CWD)
        if not is_server_process_alive(inst):
            down.append(f"{name} server")

        # --- Controller status
        if (inst.get("type") or "").lower() == "trakman":
            if not pm2_is_online(inst.get("pm2_name") or name):
                down.append(f"{name} controller")
        else:
            xdir = inst.get("xaseco_dir") or (
                os.path.dirname(inst.get("xaseco_bat", "")) if inst.get("xaseco_bat") else ""
            )
            if xdir and not is_xaseco_alive(xdir, inst.get("xaseco_name") or name):
                down.append(f"{name} controller")

    new_state = ";".join(sorted(down))
    old_state, existed = _read_state()
    _write_state(new_state)
    host = INSTANCE_NAME

    if force:
        if not down:
            monitor_post_discord(f"✅ All services up on {host}", "All monitored services are **UP**.", mention=False)
        else:
            monitor_post_discord(
                f"❌ Outage on {host}",
                "The following components are **DOWN**:\n- " + "\n- ".join(down),
                mention=bool(MENTION_TEXT)
            )
        return

    if new_state == old_state and existed:
        return

    if not down:
        title = f"✅ All services up on {host}" if not existed and ALWAYS_POST_ON_FIRST_RUN else f"✅ All services recovered on {host}"
        monitor_post_discord(title, "All monitored services are **UP**.", mention=False)
        return

    monitor_post_discord(
        f"❌ Outage on {host}",
        "The following components are **DOWN**:\n- " + "\n- ".join(down),
        mention=bool(MENTION_TEXT)
    )

def _initial_bootstrap_sync():
    log_line("=== Monitoring bootstrap ===")
    for inst in INSTANCES:
        _set_mon_defaults(inst["name"])

    # Start only monitored & missing components
    self_heal_enabled_instances()

    assess_and_notify(force=True)
    log_line("=== Bootstrap complete; entering monitor loop soon ===")

def monitor_loop_sync():
    global _NEXT_RUN_AT
    while True:
        try:
            start = datetime.now(timezone.utc)
            _NEXT_RUN_AT = start + timedelta(seconds=REFRESH_SECONDS)

            log_line("=== Monitoring sweep ===")

            # Start missing pieces only for monitored instances
            self_heal_enabled_instances()

            # Build outage snapshot after self-heal
            assess_and_notify()

            enabled_names = {n for n, on in _MONITOR_FLAGS.items() if on}

            for inst in INSTANCES:
                name = inst["name"]
                t = (inst.get("type") or "").lower()

                # Show "disabled" for everyone (Trakman + XAseco)
                if name not in enabled_names:
                    log_line(f"[{name}] monitoring disabled → skip.")
                    continue

                # ----- XAseco (AMP_*): scheduled empty-check + graceful restart -----
                if t != "trakman":
                    # Heartbeat log
                    s_ok = is_server_process_alive(inst)
                    xdir = inst.get("xaseco_dir") or (os.path.dirname(inst.get("xaseco_bat", "")) if inst.get("xaseco_bat") else "")
                    c_ok = bool(xdir and is_xaseco_alive(xdir, inst.get("xaseco_name") or name))
                    log_line(f"[{name}] XAseco heartbeat — Server: {'UP' if s_ok else 'DOWN'}, Controller: {'UP' if c_ok else 'DOWN'}")
                
                    # Use the same timers as Trakman unless you add XAseco-specific settings
                    _set_mon_defaults(name)
                    info = _MON[name]
                    uptime = datetime.now() - info["start_time"]
                    since_chk = datetime.now() - info["last_player_check"]
                
                    restart_hours = float(inst.get("restart_after_hours",
                        SET.get("xaseco_restart_hours", TRAKMAN_RESTART_HOURS)))
                    check_minutes = float(inst.get("player_check_minutes",
                        SET.get("xaseco_player_check_minutes", TRAKMAN_PLAYER_CHECK_MINUTES)))
                
                    if uptime < timedelta(hours=restart_hours):
                        log_line(f"[{name}] Uptime <{restart_hours}h → skip.")
                        continue
                    if since_chk < timedelta(minutes=check_minutes):
                        log_line(f"[{name}] Player check <{check_minutes}min ago → skip.")
                        continue
                
                    # Time to check players
                    info["last_player_check"] = datetime.now()
                    try:
                        empty = xaseco_is_empty(inst)
                    except Exception as e:
                        log_line(f"[{name}] GetPlayerList failed: {e}")
                        empty = False
                
                    if empty:
                        graceful_restart_xaseco(inst)
                        _MON[name]["start_time"] = datetime.now()
                        _MON[name]["last_player_check"] = datetime.min
                        assess_and_notify()
                    else:
                        log_line(f"[{name}] Players detected → no restart.")
                    continue

                # ----- Trakman: keep your 27h + player check + graceful restart -----
                _set_mon_defaults(name)
                info = _MON[name]
                uptime = datetime.now() - info["start_time"]
                since_chk = datetime.now() - info["last_player_check"]
                log_line(f"[{name}] Uptime: {uptime}, Last player check: {since_chk}")

                restart_hours = float(inst.get("restart_after_hours", TRAKMAN_RESTART_HOURS))
                if uptime < timedelta(hours=restart_hours):
                    log_line(f"[{name}] Uptime <{restart_hours}h → skip.")
                    continue
                check_minutes = float(inst.get("player_check_minutes", TRAKMAN_PLAYER_CHECK_MINUTES))
                if since_chk < timedelta(minutes=check_minutes):
                    log_line(f"[{name}] Player check <{check_minutes}min ago → skip.")
                    continue

                info["last_player_check"] = datetime.now()
                try:
                    empty = trakman_is_empty(inst)
                except Exception as e:
                    log_line(f"[{name}] GetPlayerList failed: {e}")
                    empty = None
                
                if empty is True:
                    graceful_restart_trakman_server(inst)
                    _MON[name]["start_time"] = datetime.now()
                    _MON[name]["last_player_check"] = datetime.min
                    assess_and_notify()
                elif empty is False:
                    log_line(f"[{name}] Players detected → no restart.")
                else:
                    log_line(f"[{name}] Occupancy unknown → no action.")

            log_line(f"Sleeping {REFRESH_SECONDS} seconds…\n")
            eventlet.sleep(REFRESH_SECONDS)
        except Exception as e:
            log_line(f"[Monitor] Loop error: {e}")
            eventlet.sleep(30)

# =============================================================================
# Process detection helpers (XAseco — status only)
# =============================================================================

def get_server_proc_name(inst: dict) -> Optional[str]:
    """
    Optional per-instance process name for the dedicated server,
    e.g. 'NilaRPG.exe' or 'AMPRPG.exe'. If missing, returns None.
    """
    pn = (inst.get("server_proc_name") or inst.get("server_proc") or "").strip()
    return pn or None


def is_server_process_alive(inst: dict) -> bool:
    """
    Prefer exact EXE name match if 'server_proc_name' is provided.
    Fallback to your existing working-directory (CWD) detection.
    """
    proc_name = (get_server_proc_name(inst) or "").lower()
    sdir = _server_dir_from_bat(inst.get("server_bat")) if inst.get("server_bat") else None
    sdir_n = _norm(sdir) if sdir else None

    for p in psutil.process_iter(["name", "cwd"]):
        try:
            pname = (p.info.get("name") or "").lower()
            cwd = p.info.get("cwd")

            if proc_name:
                # Match exact exe name, and if we know expected CWD, require it too.
                if pname == proc_name and (not sdir_n or (cwd and _norm(cwd) == sdir_n)):
                    return True
            else:
                # No proc name configured → use the old CWD-based check.
                if sdir_n and cwd and _norm(cwd) == sdir_n:
                    return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return False


def is_xaseco_alive(xaseco_dir: str, expect_name: Optional[str] = None) -> bool:
    xdir = _norm(xaseco_dir)
    for p in psutil.process_iter(["name", "cwd", "cmdline"]):
        try:
            if p.info.get("name", "").lower() == "php.exe":
                cwd = p.info.get("cwd")
                if cwd and _norm(cwd) == xdir:
                    cmd = " ".join(p.info.get("cmdline") or [])
                    if "aseco.php" in cmd.lower():
                        return True if not expect_name else (f"--name={expect_name}".lower() in cmd.lower())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def self_heal_enabled_instances():
    """
    Start ONLY monitored components that are not running.
    - Server: by server_proc_name (if provided) else CWD.
    - Controller: Trakman via PM2; XAseco via php.exe --name=...
    """
    enabled_names = {n for n, on in _MONITOR_FLAGS.items() if on}
    if not enabled_names:
        return

    for inst in INSTANCES:
        name = inst["name"]
        if name not in enabled_names:
            continue

        # ---- Server
        if not is_server_process_alive(inst):
            log_line(f"[{name}] Server is NOT running and is monitored → starting.")
            start_server(inst)
            _set_mon_defaults(name)
            _MON[name]["start_time"] = datetime.now()
            _MON[name]["last_player_check"] = datetime.min

        # ---- Controller
        t = (inst.get("type") or "").lower()
        if t == "trakman":
            ctrl_alive = pm2_is_online(inst.get("pm2_name") or name)
        else:
            xdir = inst.get("xaseco_dir") or (os.path.dirname(inst.get("xaseco_bat", "")) if inst.get("xaseco_bat") else "")
            ctrl_alive = bool(xdir and is_xaseco_alive(xdir, inst.get("xaseco_name") or name))

        if not ctrl_alive:
            log_line(f"[{name}] Controller is NOT running and is monitored → starting.")
            start_controller(inst)

# =============================================================================
# Flask app setup
# =============================================================================

app = Flask(__name__)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(PREFERRED_URL_SCHEME=os.environ.get("PREFERRED_URL_SCHEME", "https"))

# Session / cookie settings
COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN") or SET.get("cookie_domain")
_cookie_conf = {
    "SECRET_KEY": SESSION_SECRET,
    "SESSION_COOKIE_NAME": "tmwebui_session",
    "SESSION_COOKIE_SAMESITE": "Lax",
    "SESSION_COOKIE_SECURE": True,
    "PERMANENT_SESSION_LIFETIME": 60 * 60 * 24,  # seconds
}
if COOKIE_DOMAIN:
    _cookie_conf["SESSION_COOKIE_DOMAIN"] = COOKIE_DOMAIN
app.config.update(**_cookie_conf)

# JSON error shape
@app.errorhandler(HTTPException)
def _http_error(e: HTTPException):
    if e.response:  # created by abort_json
        return e.response
    return jsonify(error=e.description or "HTTP error"), e.code or 500

# OAuth (Discord)
oauth = OAuth(app)
oauth.register(
    name="discord",
    client_id=DISCORD_CLIENT_ID,
    client_secret=DISCORD_CLIENT_SECRET,
    access_token_url="https://discord.com/api/oauth2/token",
    authorize_url="https://discord.com/api/oauth2/authorize",
    api_base_url="https://discord.com/api/",
    client_kwargs={"token_endpoint_auth_method": "client_secret_post", "scope": "identify"},
)

# WebSocket
sock = Sock(app)


# =============================================================================
# Routes: HTML + Auth + Helpers
# =============================================================================

@app.get("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.get("/login")
def login():
    # You can also use url_for('auth_callback', _external=True)
    redirect_uri = OAUTH_REDIRECT_URL
    return oauth.discord.authorize_redirect(redirect_uri)

@app.get("/auth/callback")
def auth_callback():
    token = oauth.discord.authorize_access_token()
    resp = oauth.discord.get("users/@me", token=token)
    user = resp.json()
    session["user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "discriminator": user.get("discriminator"),
    }
    return redirect("/")

@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.after_request
def _nocache(r):
    r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

# =============================================================================
# App-facing API: status, control, logs
# =============================================================================

def _collect_proc_snapshot() -> list[dict]:
    snap = []
    for p in psutil.process_iter(["name", "cwd", "cmdline"]):
        try:
            snap.append({
                "name": (p.info.get("name") or "").lower(),
                "cwd": _norm(p.info.get("cwd")),
                "cmdline": " ".join(p.info.get("cmdline") or []).lower(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snap

def _pm2_online_set() -> set[str]:
    online = set()
    try:
        for pr in pm2_jlist():
            if pr.get("pm2_env", {}).get("status") == "online":
                n = pr.get("name")
                if n:
                    online.add(n)
    except Exception:
        pass
    return online

def status_instance(inst: dict, user: Optional[dict] = None, *,
                    proc_snapshot: Optional[list[dict]] = None,
                    pm2_online: Optional[set[str]] = None) -> dict:
    t = (inst.get("type") or "").lower()

    # ---- Server alive (use single proc snapshot if given)
    if proc_snapshot is not None:
        proc_name = (inst.get("server_proc_name") or inst.get("server_proc") or "").strip().lower()
        sdir = _server_dir_from_bat(inst.get("server_bat")) if inst.get("server_bat") else None
        sdir_n = _norm(sdir) if sdir else None
        server_alive = False
        for p in proc_snapshot:
            if proc_name:
                if p["name"] == proc_name and (not sdir_n or p["cwd"] == sdir_n):
                    server_alive = True
                    break
            else:
                if sdir_n and p["cwd"] == sdir_n:
                    server_alive = True
                    break
    else:
        server_alive = is_server_process_alive(inst)

    # ---- Controller alive (reuse pm2/process snapshot if given)
    if t == "trakman":
        if pm2_online is not None:
            controller_alive = (inst.get("pm2_name") or inst["name"]) in pm2_online
        else:
            controller_alive = pm2_is_online(inst.get("pm2_name") or inst["name"])
    else:
        if proc_snapshot is not None:
            xdir = inst.get("xaseco_dir") or (os.path.dirname(inst.get("xaseco_bat", "")) if inst.get("xaseco_bat") else "")
            xdir_n = _norm(xdir) if xdir else None
            expect = (inst.get("xaseco_name") or inst["name"]).lower()
            controller_alive = False
            if xdir_n:
                for p in proc_snapshot:
                    if p["name"] == "php.exe" and p["cwd"] == xdir_n and "aseco.php" in p["cmdline"]:
                        # If a name is passed, make sure it matches
                        if expect and f"--name={expect}" not in p["cmdline"]:
                            continue
                        controller_alive = True
                        break
        else:
            controller_alive = False
            if inst.get("xaseco_dir"):
                controller_alive = is_xaseco_alive(inst["xaseco_dir"], inst.get("xaseco_name") or inst["name"])
            elif inst.get("xaseco_bat"):
                controller_alive = is_xaseco_alive(os.path.dirname(inst["xaseco_bat"]), inst.get("xaseco_name") or inst["name"])

    return {
        "name": inst["name"],
        "type": t,
        "group": (inst.get("group") or ""),
        "may_admin": is_group_admin_for_inst(user, inst) if user else False,
        "server_alive": server_alive,
        "controller_alive": controller_alive,
        "server_log": inst.get("server_log"),
        "controller_log": inst.get("controller_log"),
    }

@app.get("/api/me")
def api_me():
    u = current_user()
    if not u:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "user": u, "is_admin": u.get("id") in ADMIN_IDS})

@app.get("/api/status")
def api_status():
    u = current_user()
    procs = _collect_proc_snapshot()
    pm2_ok = _pm2_online_set()
    return jsonify([status_instance(inst, u, proc_snapshot=procs, pm2_online=pm2_ok)
                    for inst in INSTANCES])

@app.post("/api/start")
def api_start():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst: abort_json(404, "Unknown instance")
    require_inst_admin(inst)
    start_instance(inst)
    monitor_post_discord("Start", f"{name} started")
    return jsonify({"ok": True})

@app.post("/api/stop")
def api_stop():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst: abort_json(404, "Unknown instance")
    require_inst_admin(inst)
    stop_instance(inst)
    monitor_post_discord("Stop", f"{name} stopped")
    return jsonify({"ok": True})

@app.post("/api/restart")
def api_restart():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst: abort_json(404, "Unknown instance")
    require_inst_admin(inst)
    restart_instance(inst)
    monitor_post_discord("Restart", f"{name} restarted")
    return jsonify({"ok": True})

@app.post("/api/control")
def api_control():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name")
    action = (data.get("action") or "").lower()
    target = (data.get("target") or "both").lower()
    if action not in ("start", "stop", "restart"):
        abort_json(400, "action must be start|stop|restart")
    if target not in ("server", "controller", "both"):
        abort_json(400, "target must be server|controller|both")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst: abort_json(404, "Unknown instance")
    require_inst_admin(inst)
    if target in ("server", "both"):
        if action == "start": start_server(inst)
        if action == "stop": stop_server(inst)
        if action == "restart": restart_server(inst)
    if target in ("controller", "both"):
        if action == "start": start_controller(inst)
        if action == "stop": stop_controller(inst)
        if action == "restart": restart_controller(inst)
    monitor_post_discord(action.capitalize(), f"{name} ({target}) {action}ed")
    return jsonify({"ok": True})

# =============================================================================
# Monitoring API
# =============================================================================

@app.get("/api/monitor")
def api_monitor_get():
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    next_run = (
        _NEXT_RUN_AT.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if _NEXT_RUN_AT else None
    )
    return jsonify({
        "refresh_seconds": REFRESH_SECONDS,
        "now": now,
        "next_run_at": next_run,
        "instances": [
            {"name": i["name"], "enabled": bool(_MONITOR_FLAGS.get(i["name"], False))}
            for i in INSTANCES
        ]
    })

@app.post("/api/monitor/toggle")
def api_monitor_toggle():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    enabled = bool(data.get("enabled"))
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")
    # Must be admin of this instance
    require_inst_admin(inst)

    _MONITOR_FLAGS[name] = enabled
    _save_monitor_flags(_MONITOR_FLAGS)
    # initialize timers so uptime logic won’t trip on first run
    _set_mon_defaults(name)
    return jsonify({"ok": True, "name": name, "enabled": enabled})

@app.post("/api/monitor/force")
def api_monitor_force():
    require_admin()
    assess_and_notify(force=True)
    return jsonify({"ok": True})


# =============================================================================
# Public playercount
# =============================================================================

@app.post("/api/public/playercount")
def api_public_playercount():
    return api_playercount()

PLAYERCOUNT_CACHE: dict[str, dict] = {}   # { name: {"count": int, "ts": float} }
PLAYERCOUNT_TTL = float(SET.get("playercount_cache_ttl", 30))  # seconds

def _get_player_count(inst: dict, *, timeout: float = 5.0) -> int:
    """Count real players (exclude server pseudo-player)."""
    login = inst.get("xmlrpc_login")
    pw    = inst.get("xmlrpc_password")
    if not login or pw is None:
        raise RuntimeError("xmlrpc_login/xmlrpc_password not configured for instance")

    res = gbx_call_sequence(inst, [
        ("Authenticate", [login, pw]),
        ("GetPlayerList", [255, 0, 2]),  # include server row
    ], timeout=timeout)

    if not res or not res[0]:
        raise RuntimeError("Authenticate returned falsy")

    players = res[1] or []
    cnt = 0
    for p in players:
        try:
            if int(p.get("PlayerId", -1)) != 0:  # exclude server pseudo-player
                cnt += 1
        except Exception:
            # be conservative; treat as 0 increment
            pass
    return cnt

@app.post("/api/playercount")
def api_playercount():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort_json(400, "Missing 'name'")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")

    # tiny in-memory TTL cache to de-burst
    now = time.time()
    entry = PLAYERCOUNT_CACHE.get(name)
    if entry and (now - entry["ts"] < PLAYERCOUNT_TTL):
        return jsonify({"ok": True, "count": entry["count"], "cached": True, "age_sec": int(now - entry["ts"])})

    try:
        cnt = _get_player_count(inst)
    except Exception:
        abort_json(502, "Player count temporarily unavailable")

    PLAYERCOUNT_CACHE[name] = {"count": cnt, "ts": now}
    return jsonify({"ok": True, "count": cnt, "cached": False, "age_sec": 0})

# =============================================================================
# Dedicated server API (direct XML-RPC)
# =============================================================================

@app.post("/api/dedi/authenticate")
def api_dedi_authenticate():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort_json(400, "Missing 'name'")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")

    require_inst_admin(inst)

    login = data.get("login") or inst.get("xmlrpc_login")
    password = data.get("password") or inst.get("xmlrpc_password")
    if not login or not password:
        abort_json(400, "Missing credentials (login/password or xmlrpc_login/xmlrpc_password)")

    # Use GBXRemote (binary) instead of HTTP here
    try:
        res = gbx_call_sequence(inst, [("Authenticate", [login, password])], timeout=5.0)
    except RuntimeError as e:
        abort_json(400, f"XML-RPC fault: {e}")
    except Exception as e:
        abort_json(502, f"Authenticate failed: {e}")

    ok = bool(res and res[0])
    return jsonify({"ok": True, "authenticated": ok})

def authenticate_any(inst: dict, login: str, password: str, timeout: float = 5.0) -> bool:
    # Try HTTP first
    try:
        return bool(_xmlrpc_call(inst, "Authenticate", [login, password], timeout=timeout))
    except Exception as e:
        msg = str(e)
        # If the peer spoke GBXRemote (or any HTTP-level parse error), fall back
        if "GBXRemote 2" in msg or "BadStatusLine" in msg or "Connection aborted" in msg:
            res = gbx_call_sequence(inst, [("Authenticate", [login, password])], timeout=timeout)
            return bool(res and res[0])
        # Otherwise bubble up
        raise

@app.post("/api/dedi/chatsend")
def api_dedi_chatsend():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    message = (data.get("message") or "").strip()
    if not name or not message:
        abort_json(400, "Missing 'name' or 'message'")

    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")

    require_inst_admin(inst)   # enforce auth

    inst_type = (inst.get("type") or "").lower()
    try:
        if inst_type == "trakman":
            # Route intelligently for Trakman
            ok = trakman_send(inst, message)
            if not ok:
                abort_json(400, "Failed to send Trakman message/command")
            return jsonify({"ok": True})

        # --- default (XAseco etc.): keep your existing Authenticate + ChatSend flow ---
        login = inst.get("xmlrpc_login") or DEFAULT_RPC_USER
        pw    = inst.get("xmlrpc_password") if inst.get("xmlrpc_password") is not None else DEFAULT_RPC_PASS
        if not login or pw is None:
            abort_json(400, "xmlrpc_login/xmlrpc_password not configured for the instance")

        try:
            host = inst.get("xmlrpc_host") or "127.0.0.1"
            port = int(inst.get("xmlrpc_port"))
            log_line(f"[GBXRPC/{name}] seq → {host}:{port} "
                     f'[{{"method":"Authenticate","params":["{login}","****"]}},{{"method":"ChatSend","params":["<msg>"]}}]')
        except Exception:
            pass

        res = gbx_call_sequence(inst, [
            ("Authenticate", [login, pw]),
            ("ChatSend", [message]),
        ], timeout=5.0)

        if not isinstance(res, list) or len(res) < 2:
            abort_json(502, "Malformed GBX response")
        auth_res, chat_res = res[0], res[1]
        if not auth_res:
            abort_json(401, "Authenticate returned falsy")
        if not chat_res:
            abort_json(400, "ChatSend returned falsy")
        return jsonify({"ok": True})

    except RuntimeError as e:
        abort_json(400, f"XML-RPC/Trakman error: {e}")
    except Exception as e:
        abort_json(502, f"ChatSend failed: {e}")


# ---- Log beautifiers ----
_TM_CODES = re.compile(r"\$[0-9a-fA-F]{3}|\$.")
_ANSI_ESC = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

def strip_tm_colors(s: str) -> str:
    return _TM_CODES.sub("", s or "")

def strip_ansi(s: str) -> str:
    return _ANSI_ESC.sub("", s or "")

def clean_log_line(s: str) -> str:
    if not s:
        return ""
    s = s.replace("$$", "$")
    s = strip_ansi(s)
    s = strip_tm_colors(s)
    return s.replace("\r", "").rstrip()

def _read_last_lines(path: str, n: int = 200) -> List[str]:
    try:
        lines: List[bytes] = []
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0 and len(lines) <= n:
                step = block if size - block > 0 else size
                f.seek(size - step)
                data = f.read(step) + data
                size -= step
                lines = data.splitlines()
        tail = lines[-n:] if len(lines) > n else lines
        return [l.decode("utf-8", errors="ignore") for l in tail]
    except Exception:
        return []

@app.get("/api/log/<name>/<kind>")
def api_log(name: str, kind: str):
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")
    require_inst_admin(inst)
    kind_l = kind.lower()
    if kind_l not in ("server", "controller"):
        abort_json(400, 'kind must be "server" or "controller"')
    path = inst.get("server_log") if kind_l == "server" else inst.get("controller_log")
    if not path or not os.path.exists(path):
        abort_json(404, "Log not found")
    # stream/plain text
    return send_file(path, mimetype="text/plain", as_attachment=False, download_name=os.path.basename(path))

# --- XAseco helpers: player list & empty check (use version=1 to exclude server row)

def xaseco_players(inst: dict, *, max_count: int = 255, start: int = 0, version: int = 1, timeout: float = 5.0) -> list:
    """
    Returns list of players using GetPlayerList. With version=1 the server
    pseudo-player is NOT included, so empty array really means empty.
    """
    login = inst.get("xmlrpc_login")
    pw    = inst.get("xmlrpc_password")
    if not login or pw is None:
        raise RuntimeError("xmlrpc_login/xmlrpc_password not configured for instance")
    res = gbx_call_sequence(inst, [
        ("Authenticate", [login, pw]),
        ("GetPlayerList", [int(max_count), int(start), int(version)]),
    ], timeout=timeout)
    ok = bool(res and res[0])
    if not ok:
        raise RuntimeError("Authenticate failed")
    return res[1] or []

def xaseco_is_empty(inst: dict) -> bool:
    """
    XAseco emptiness check:
      - Call GetPlayerList(255, 0, 2) so the server pseudo-player is included.
      - If any row has PlayerId != 0 (i.e., any real player/spectator), it's NOT empty.
      - If the only row(s) are PlayerId == 0 (server pseudo-player), it's empty.
    Optionally you can set inst["server_login"] in servers.yaml; otherwise we infer
    it from the row with PlayerId == 0.
    """
    login = inst.get("xmlrpc_login")
    pw    = inst.get("xmlrpc_password")
    if not login or pw is None:
        raise RuntimeError("xmlrpc_login/xmlrpc_password not configured for instance")

    # Always use (255, 0, 2) for this check
    res = gbx_call_sequence(inst, [
        ("Authenticate", [login, pw]),
        ("GetPlayerList", [255, 0, 2]),
    ], timeout=5.0)

    if not res or not res[0]:
        # auth failed → be conservative, don't trigger restart
        return False

    players = res[1] or []
    if not isinstance(players, list):
        return False

    # Try to identify server login from PlayerId == 0 (fallback to optional config)
    server_login = inst.get("server_login")
    if not server_login:
        for p in players:
            try:
                if int(p.get("PlayerId", -1)) == 0:
                    server_login = str(p.get("Login") or "").strip()
                    break
            except Exception:
                pass

    # If ANY entry is a real player (PlayerId != 0), it's not empty.
    for p in players:
        try:
            if int(p.get("PlayerId", -1)) != 0:
                return False
        except Exception:
            # Unknown row shape → play safe
            return False

    # Only the server pseudo-player remains → empty
    return True

def trakman_is_empty(inst: dict) -> bool:
    """
    Trakman emptiness check:
      - Call GetPlayerList(255, 0, 2) so the server pseudo-player is included.
      - If ANY row has PlayerId != 0 (a real player/spectator), it's NOT empty.
      - If the only row(s) have PlayerId == 0 (server pseudo-player), it's empty.
    """
    login = inst.get("xmlrpc_login")
    pw    = inst.get("xmlrpc_password")
    if not login or pw is None:
        raise RuntimeError("xmlrpc_login/xmlrpc_password not configured for instance")

    res = gbx_call_sequence(inst, [
        ("Authenticate", [login, pw]),
        ("GetPlayerList", [255, 0, 2]),
    ], timeout=5.0)

    if not res or not res[0]:
        # auth failed or malformed → be conservative, do NOT restart
        return False

    players = res[1] or []
    if not isinstance(players, list) or len(players) == 0:
        # unexpected; DS normally returns at least the server row
        return False

    for p in players:
        try:
            if int(p.get("PlayerId", -1)) != 0:
                return False
        except Exception:
            # Unknown row shape → play safe
            return False

    # Only the server pseudo-player remains → empty
    return True

@app.post("/api/dedi/getplayerlist")
def api_dedi_getplayerlist():
    data = request.get_json(force=True, silent=True) or {}
    name     = (data.get("name") or "").strip()
    max_cnt  = int(data.get("max", 0))      # 0 = all
    start    = int(data.get("start", 1))    # 1 = skip the server row at index 0
    version  = int(data.get("version", 2))  # 2 = forever incl. servers (we start at 1)
    if not name:
        abort_json(400, "Missing 'name'")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")
    require_inst_admin(inst)

    login = inst.get("xmlrpc_login")
    pw    = inst.get("xmlrpc_password")
    if not login or pw is None:
        abort_json(400, "xmlrpc_login/xmlrpc_password not configured")

    try:
        res = gbx_call_sequence(inst, [
            ("Authenticate", [login, pw]),
            ("GetPlayerList", [max_cnt, start, version]),
        ], timeout=5.0)
    except RuntimeError as e:
        abort_json(400, f"XML-RPC fault: {e}")
    except Exception as e:
        abort_json(502, f"GetPlayerList failed: {e}")

    if not res or not res[0]:
        abort_json(401, "Authenticate returned falsy")

    players = res[1] or []
    return jsonify({"ok": True, "count": len(players), "players": players,
                    "used": {"max": max_cnt, "start": start, "version": version}})

@app.post("/api/dedi/is_empty")
def api_dedi_is_empty():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort_json(400, "Missing 'name'")
    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        abort_json(404, "Unknown instance")
    require_inst_admin(inst)

    # exact spec you asked for: 0 1 2
    try:
        res = gbx_call_sequence(inst, [
            ("Authenticate", [inst.get("xmlrpc_login"), inst.get("xmlrpc_password")]),
            ("GetPlayerList", [0, 1, 2]),
        ], timeout=5.0)
    except Exception as e:
        abort_json(502, f"GetPlayerList failed: {e}")

    if not res or not res[0]:
        abort_json(401, "Authenticate returned falsy")
    players = res[1] or []
    return jsonify({"ok": True, "empty": len(players) == 0, "count": len(players)})

# =============================================================================
# WebSocket: live log stream
# =============================================================================

@sock.route("/ws/ping")
def ws_ping(ws):
    # Debug: did the cookie/session arrive with the WS upgrade?
    try:
        log_line(f"WS {request.path} cookies={bool(request.cookies)} user={bool(session.get('user'))}")
        ws.send("hello\n")
    except Exception:
        return
    while True:
        msg = ws.receive()
        if not msg:
            break
        ws.send(f"echo: {msg}\n")

@sock.route("/ws/log/<name>/<kind>")
def ws_log(ws, name: str, kind: str):
    log_line(f"WS {request.path} cookies={bool(request.cookies)} user={bool(session.get('user'))}")
    user = session.get("user")
    if not user:
        try: ws.send("Login required")
        except Exception: pass
        return

    inst = next((i for i in INSTANCES if i["name"] == name), None)
    if not inst:
        try: ws.send("ERR unknown instance")
        except Exception: pass
        return

    if not is_group_admin_for_inst(user, inst):
        try: ws.send("Forbidden")
        except Exception: pass
        return

    kind_l = (kind or "").lower()
    if kind_l not in ("server", "controller"):
        try: ws.send('Invalid kind; use "server" or "controller"')
        except Exception: pass
        return

    path = inst.get("server_log") if kind_l == "server" else inst.get("controller_log")
    if not path:
        try: ws.send("No log configured")
        except Exception: pass
        return

    # Tail logic (blocking loop is fine for WS handler thread)
    try:
        while not os.path.exists(path):
            time.sleep(0.5)

        # send last lines
        for line in _read_last_lines(path, 200):
            pretty = clean_log_line(line)
            if pretty:
                ws.send(pretty)

        pos = os.path.getsize(path)
        while True:
            if not os.path.exists(path):
                time.sleep(0.5)
                continue
            try:
                size = os.path.getsize(path)
            except FileNotFoundError:
                time.sleep(0.5)
                continue
            if size < pos:
                pos = 0  # rotated
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(pos, os.SEEK_SET)
                    chunk = f.read()
                    if not chunk:
                        time.sleep(0.5)
                    else:
                        for line in chunk.splitlines():
                            pretty = clean_log_line(line)
                            if pretty:
                                ws.send(pretty)
                        pos = f.tell()
            except FileNotFoundError:
                time.sleep(0.5)
                continue
    except Exception:
        # Client closed or other I/O issue: just end.
        return

# =============================================================================
# Lifecycle (bootstrap + monitor in a background thread)
# =============================================================================

_bg_started = False

def _start_background():
    global _bg_started
    if _bg_started:
        return
    _bg_started = True
    eventlet.spawn_n(_initial_bootstrap_sync)
    eventlet.spawn_n(monitor_loop_sync)

@app.before_request
def _maybe_start_bg():
    _start_background()

# =============================================================================
# Run (if needed)
# =============================================================================

if __name__ == "__main__":
    from eventlet import wsgi
    listener = eventlet.listen(("0.0.0.0", 8000))
    _start_background()  # ensure monitor starts even with zero traffic
    wsgi.server(listener, app)