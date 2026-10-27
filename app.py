#!/usr/bin/env python3
"""
singbox-panel — мини веб-панель для sing-box (клиент + TUN) на headless Debian.

Возможности:
  * вход по системным логину/паролю (PAM)
  * статус службы, аптайм, трафик TUN-интерфейса (график), логи
  * start / stop / restart / reload службы
  * редактор конфига: проверка `sing-box check`, бэкапы, откат при неудачном запуске
  * визуальный редактор маршрутизации (route.rules / route.final)
  * импорт узлов из подписки (sing-box JSON, base64-список ссылок:
    vless / vmess / trojan / ss / hysteria2), автообновление

Настройка через переменные окружения (см. блок ниже).
Запускать от root (нужны systemctl и запись в конфиг).
"""
import base64
import concurrent.futures
import ctypes
import ctypes.util
import grp
import hashlib
import inspect
import json
import os
import platform
import pwd
import random
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ----------------------------------------------------------------- настройки
CONFIG = os.environ.get("SBP_CONFIG", "/etc/sing-box/config.json")
SERVICE = os.environ.get("SBP_SERVICE", "sing-box")
BINARY = os.environ.get("SBP_BINARY", "sing-box")
HOST = os.environ.get("SBP_HOST", "0.0.0.0")
PORT = int(os.environ.get("SBP_PORT", "8088"))
DATA = os.environ.get("SBP_DATA", "/var/lib/singbox-panel")
TUN = os.environ.get("SBP_TUN", "")  # имя интерфейса; пусто = авто
# отдельная служба singbox-panel (без pam_securetty из login); если файла нет — прежний «login»
PAM_SERVICE = os.environ.get("SBP_PAM_SERVICE") or ("singbox-panel" if os.path.isfile("/etc/pam.d/singbox-panel") else "login")
# кому можно входить: члены групп ИЛИ перечисленные пользователи. Пусто в обоих = любой
ALLOWED_GROUPS = [g for g in os.environ.get("SBP_GROUPS", "sudo").split(",") if g]
ALLOWED_USERS = [u for u in os.environ.get("SBP_USERS", "").split(",") if u]
SESSION_TTL = 12 * 3600
APP_VERSION = "dev"  # подставляется при сборке пакета
PREFIX = "sub-"  # префикс тегов узлов, пришедших из подписки
BACKUP_KEEP = 30
SYSTEMD_DIR = os.environ.get("SBP_SYSTEMD_DIR", "/etc/systemd/system")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_FILE = os.path.abspath(__file__)
try:
    APP_MTIME = os.path.getmtime(APP_FILE)
except OSError:
    APP_MTIME = 0
BACKUPS = os.path.join(DATA, "backups")
STATE_FILE = os.path.join(DATA, "state.json")
LOCK = threading.RLock()
SESSIONS = {}


# ------------------------------------------- мини-веб-сервер (только stdlib)
# Заменяет FastAPI+uvicorn: пакету не нужны зависимости из PyPI.
# Обработчики объявляются как раньше: @app.get/@app.post, параметры:
#   body: dict (JSON тела), request: Request, response: Response,
#   user: str = Depends(auth), прочие параметры — query-строка (int/str/bool).
class HTTPException(Exception):
    def __init__(self, status_code, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class Depends:
    def __init__(self, fn):
        self.fn = fn


class HTMLResponse(str):
    """Маркер: вернуть строку как text/html."""


class Request:
    def __init__(self, method, path, query, headers, body):
        self.method, self.path, self.query, self.headers, self._body = method, path, query, headers, body
        self.cookies = {}
        c = SimpleCookie()
        try:
            c.load(headers.get("Cookie", ""))
            self.cookies = {k: m.value for k, m in c.items()}
        except Exception:
            pass

    def json(self):
        if not self._body.strip():
            return {}
        try:
            v = json.loads(self._body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(422, "Тело запроса — не JSON")
        if not isinstance(v, dict):
            raise HTTPException(422, "Ожидался JSON-объект")
        return v


class Response:
    def __init__(self):
        self.set_cookies = []

    def set_cookie(self, key, value, httponly=False, samesite=None, max_age=None, path="/"):
        c = f"{key}={value}; Path={path}"
        if max_age is not None:
            c += f"; Max-Age={int(max_age)}"
        if httponly:
            c += "; HttpOnly"
        if samesite:
            c += f"; SameSite={samesite.capitalize()}"
        self.set_cookies.append(c)

    def delete_cookie(self, key, path="/"):
        self.set_cookies.append(f"{key}=; Path={path}; Max-Age=0")


class MiniApp:
    def __init__(self):
        self.routes = {}
        self.startup_hooks = []

    def _route(self, method, path):
        def deco(fn):
            self.routes[(method, path)] = (fn, inspect.signature(fn))
            return fn
        return deco

    def get(self, path, response_class=None):
        return self._route("GET", path)

    def post(self, path, response_class=None):
        return self._route("POST", path)

    def on_event(self, name):
        def deco(fn):
            if name == "startup":
                self.startup_hooks.append(fn)
            return fn
        return deco

    def _resolve(self, fn, sig, req, resp):
        kw = {}
        for name, p in sig.parameters.items():
            d, ann = p.default, p.annotation
            if isinstance(d, Depends):
                kw[name] = self._resolve(d.fn, inspect.signature(d.fn), req, resp)
            elif ann is Request:
                kw[name] = req
            elif ann is Response:
                kw[name] = resp
            elif ann is dict:
                kw[name] = req.json()
            else:
                raw = req.query.get(name)
                if raw is None:
                    if d is inspect.Parameter.empty:
                        raise HTTPException(422, f"Не задан параметр {name}")
                    kw[name] = d
                else:
                    try:
                        kw[name] = (raw.lower() in ("1", "true", "yes", "on")) if ann is bool \
                            else int(raw) if ann is int else raw
                    except ValueError:
                        raise HTTPException(422, f"Параметр {name} задан неверно")
        return fn(**kw)

    def dispatch(self, method, raw_path, headers, body):
        """-> (status, content_type, bytes, [set-cookie])"""
        u = urllib.parse.urlsplit(raw_path)
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        resp = Response()
        try:
            route = self.routes.get((method, u.path))
            if route is None:
                if any(p == u.path for (_m, p) in self.routes):
                    raise HTTPException(405, "Метод не поддерживается")
                raise HTTPException(404, f"Не найдено: {method} {u.path}")
            fn, sig = route
            out = self._resolve(fn, sig, Request(method, u.path, query, headers, body), resp)
            if isinstance(out, HTMLResponse) or (isinstance(out, str) and u.path == "/"):
                return 200, "text/html; charset=utf-8", out.encode("utf-8"), resp.set_cookies
            return 200, "application/json; charset=utf-8", json.dumps(out, ensure_ascii=False).encode("utf-8"), resp.set_cookies
        except HTTPException as e:
            return e.status_code, "application/json; charset=utf-8", \
                json.dumps({"detail": e.detail}, ensure_ascii=False).encode("utf-8"), resp.set_cookies
        except Exception as e:
            traceback.print_exc()
            return 500, "application/json; charset=utf-8", \
                json.dumps({"detail": f"Внутренняя ошибка: {e}"}, ensure_ascii=False).encode("utf-8"), []

    def make_server(self, host, port):
        app_ = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 120
            server_version = "singbox-panel"

            def log_message(self, *a):
                pass

            def _handle(self):
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = 0
                if n > 32 * 1024 * 1024:
                    self.send_error(413)
                    self.close_connection = True
                    return
                body = self.rfile.read(n) if n else b""
                st, ct, data, cookies = app_.dispatch(self.command, self.path, self.headers, body)
                try:
                    self.send_response(st)
                    self.send_header("Content-Type", ct)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Panel-Version", APP_VERSION)
                    for c in cookies:
                        self.send_header("Set-Cookie", c)
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):   # браузер закрыл соединение (перезагрузка страницы)
                    self.close_connection = True

            do_GET = do_POST = do_HEAD = _handle

        class S(ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 64

        return S((host, port), H)

    def run(self, host, port):
        for hook in self.startup_hooks:
            hook()
        srv = self.make_server(host, port)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.server_close()


app = MiniApp()


# ------------------------------------------------------------------- утилиты
def run(cmd, timeout=30, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]}: команда не найдена"
    except OSError as e:                      # например, Exec format error у бинарника не той архитектуры
        return 126, f"{cmd[0]}: {e}"
    except subprocess.TimeoutExpired:
        return 124, "таймаут выполнения команды"


SUB_DEFAULTS = {"id": "", "name": "", "url": "", "groups": ["proxy"], "interval_h": 0, "prefix": "", "ua": "", "adopt": False,
                "last_attempt": 0, "last_update": 0, "last_count": 0, "last_error": "",
                "kind": "url", "links": "", "info": None}       # kind=links — ключи, вставленные вручную (vless:// и др.)
LEGACY_SUB_KEYS = ("url", "groups", "interval_h", "last_attempt", "last_update", "last_count", "last_error")


def load_state():
    st = {"subs": []}
    try:
        with open(STATE_FILE) as f:
            st.update(json.load(f))
    except (OSError, ValueError):
        pass
    legacy = {k: st.pop(k) for k in LEGACY_SUB_KEYS if k in st}       # прежний формат: одна подписка
    if legacy.get("url") and not st["subs"]:
        st["subs"].append({**SUB_DEFAULTS, "id": "main", "name": "Основная", "prefix": PREFIX, **legacy})
    st["subs"] = [{**SUB_DEFAULTS, **x} for x in st["subs"]]
    return st


def save_state(st):
    os.makedirs(DATA, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


# ---------------------------------------------------------------- авторизация
class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_PamMessage)),
                         ctypes.POINTER(ctypes.POINTER(_PamResponse)), ctypes.c_void_p)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


_pam_libs = {}


def _pam_load():
    if not _pam_libs:
        pam = ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
        libc.calloc.restype = ctypes.c_void_p
        libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        libc.strdup.restype = ctypes.c_void_p
        libc.strdup.argtypes = [ctypes.c_char_p]
        pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_PamConv),
                                  ctypes.POINTER(ctypes.c_void_p)]
        pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _pam_libs.update(pam=pam, libc=libc)
    return _pam_libs["pam"], _pam_libs["libc"]


def pam_ok(user, password):
    """Проверка логина/пароля через libpam напрямую (без python-pam)."""
    try:
        pam, libc = _pam_load()
    except OSError:
        raise HTTPException(500, "Не найдена библиотека libpam (apt install libpam0g)")
    pw = password.encode("utf-8")

    def conv(n, msgs, resp, _data):
        arr = libc.calloc(n, ctypes.sizeof(_PamResponse))
        if not arr:
            return 5                                    # PAM_BUF_ERR
        ptr = ctypes.cast(arr, ctypes.POINTER(_PamResponse))
        for i in range(n):
            if msgs[i].contents.msg_style in (1, 2):    # PAM_PROMPT_ECHO_OFF / ON
                ptr[i].resp = libc.strdup(pw)
        resp[0] = ptr
        return 0

    cb = _CONV(conv)
    handle = ctypes.c_void_p()
    pc = _PamConv(cb, None)
    if pam.pam_start(PAM_SERVICE.encode(), user.encode("utf-8"), ctypes.byref(pc), ctypes.byref(handle)) != 0:
        return False
    try:
        rc = pam.pam_authenticate(handle, 0)
        if rc == 0:
            rc = pam.pam_acct_mgmt(handle, 0)
        return rc == 0
    finally:
        pam.pam_end(handle, 0)


def user_allowed(user):
    if user in ALLOWED_USERS:
        return True
    if not ALLOWED_GROUPS and not ALLOWED_USERS:
        return True
    try:
        if pwd.getpwnam(user).pw_uid == 0:     # root пускаем всегда: панель и так работает от root
            return True
    except KeyError:
        return False
    if not ALLOWED_GROUPS and not ALLOWED_USERS:
        return True
    try:
        pw = pwd.getpwnam(user)
        names = set()
        for gid in os.getgrouplist(user, pw.pw_gid):
            try:
                names.add(grp.getgrgid(gid).gr_name)
            except KeyError:
                pass
        return bool(names & set(ALLOWED_GROUPS))
    except KeyError:
        return False


def auth(request: Request):
    s = SESSIONS.get(request.cookies.get("sbp", ""))
    if not s or s[1] < time.time():
        raise HTTPException(401, "Требуется вход")
    return s[0]


@app.post("/api/login")
def login(body: dict, response: Response):
    user = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not user or not password or not pam_ok(user, password):
        time.sleep(1)
        print(f"login: отказ PAM для «{user}» (неверный пароль, заблокированная учётка или запрет в /etc/pam.d/{PAM_SERVICE})", file=sys.stderr, flush=True)
        raise HTTPException(401, "Неверный логин или пароль")
    if not user_allowed(user):
        time.sleep(1)
        print(f"login: пароль «{user}» верный, но вход не разрешён (SBP_GROUPS={ALLOWED_GROUPS}, SBP_USERS={ALLOWED_USERS})", file=sys.stderr, flush=True)
        raise HTTPException(403, f"Пароль верный, но пользователю «{user}» вход не разрешён. Разрешены группы: {', '.join(ALLOWED_GROUPS) or '—'}"
                                 f"{'; пользователи: ' + ', '.join(ALLOWED_USERS) if ALLOWED_USERS else ''} (настройка SBP_GROUPS / SBP_USERS в /etc/default/singbox-panel)")
    for k in [k for k, v in SESSIONS.items() if v[1] < time.time()]:
        SESSIONS.pop(k, None)
    tok = secrets.token_urlsafe(32)
    SESSIONS[tok] = (user, time.time() + SESSION_TTL)
    response.set_cookie("sbp", tok, httponly=True, samesite="strict", max_age=SESSION_TTL)
    return {"ok": True, "user": user}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    SESSIONS.pop(request.cookies.get("sbp", ""), None)
    response.delete_cookie("sbp")
    return {"ok": True}


@app.get("/api/me")
def me(user: str = Depends(auth)):
    lt = pu_fresh(_pu["latest"])
    return {"ok": True, "user": user, "version": APP_VERSION,
            "update": lt["version"] if lt and lt.get("newer") else ""}


# --------------------------------------------------------------------- статус
_version = {"v": None}


def sb_version():
    if not _version["v"]:
        rc, out = run([BINARY, "version"])
        _version["v"] = out.splitlines()[0] if rc == 0 and out else ""
    return _version["v"]


def parse_ver(s):
    """'sing-box version 1.12.4' -> (1, 12, 4); суффиксы alpha/rc отбрасываются."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def read_net():
    res = {}
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            name, rest = line.split(":", 1)
            v = rest.split()
            res[name.strip()] = (int(v[0]), int(v[8]))
    return res


def tun_name(net):
    if TUN:
        return TUN
    try:
        with open(CONFIG) as f:
            for ib in json.load(f).get("inbounds", []):
                if ib.get("type") == "tun" and ib.get("interface_name"):
                    return ib["interface_name"]
    except (OSError, ValueError):
        pass
    for n in net:
        if n.startswith(("tun", "sing")):
            return n
    return "tun0"


def has_tun():
    try:
        return any(ib.get("type") == "tun" for ib in _cfg_read().get("inbounds", []))
    except (OSError, ValueError, AttributeError):
        return True        # конфиг не прочитан — не делаем вид, что TUN отсутствует


PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]


@app.post("/api/tun")
def tun_toggle(body: dict, user: str = Depends(auth)):
    """Добавляет/убирает TUN-вход (по кнопке). Свои записи помечены тегом panel-tun."""
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"Не удалось прочитать конфиг: {e}"}
        ibs = cfg.setdefault("inbounds", [])
        if not body.get("enable"):
            before = len(ibs)
            ibs[:] = [i for i in ibs if i.get("type") != "tun"]
            if len(ibs) == before:
                return {"ok": True, "message": "TUN в конфиге и так нет"}
            return apply_config(json.dumps(cfg), "apply")
        if any(i.get("type") == "tun" for i in ibs):
            return {"ok": True, "message": "TUN уже настроен"}
        ver = parse_ver(sb_version()) or (1, 12, 0)
        tun = {"type": "tun", "tag": "panel-tun", "interface_name": "tun0", "auto_route": True, "stack": "mixed"}
        if ver >= (1, 10, 0):
            tun["address"] = ["172.19.0.1/30"]
        else:
            tun["inet4_address"] = "172.19.0.1/30"
        ibs.insert(0, tun)
        route = cfg.setdefault("route", {})
        route["auto_detect_interface"] = True          # иначе исходящие sing-box зациклятся в собственный TUN
        rules = route.setdefault("rules", [])
        new = ver >= (1, 11, 0)
        lan = {"ip_cidr": PRIVATE_NETS, **({"action": "route"} if new else {}), "outbound": "direct"}
        if not any(isinstance(r, dict) and r.get("ip_cidr") == PRIVATE_NETS for r in rules):
            i = 0                                       # локальная сеть (SSH, эта панель) мимо туннеля, но после sniff/hijack-dns
            while i < len(rules) and isinstance(rules[i], dict) and rules[i].get("action") in ("sniff", "hijack-dns", "resolve"):
                i += 1
            rules.insert(i, lan)
        if new and not any(isinstance(r, dict) and r.get("action") == "sniff" for r in rules):
            rules.insert(0, {"action": "sniff"})
        if not any(o.get("tag") == "direct" for o in cfg.get("outbounds", [])):
            cfg.setdefault("outbounds", []).append({"type": "direct", "tag": "direct"})
        return apply_config(json.dumps(cfg), "apply")


@app.get("/api/status")
def status(user: str = Depends(auth)):
    rc, out = run(["systemctl", "show", SERVICE, "-p",
                   "ActiveState,SubState,MainPID,ActiveEnterTimestampMonotonic,MemoryCurrent,NRestarts,CPUUsageNSec,LoadState"])
    d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    uptime = None
    if d.get("ActiveState") == "active":
        try:
            uptime = max(0, time.monotonic() - int(d["ActiveEnterTimestampMonotonic"]) / 1e6)
        except (KeyError, ValueError):
            pass
    mem = d.get("MemoryCurrent", "")
    mem = int(mem) if mem.isdigit() and int(mem) < 2 ** 60 else None
    try:
        net = read_net()
    except OSError:
        net = {}
    iface = tun_name(net)
    src, rx, tx, conns = traffic_counters(d.get("ActiveState") == "active", net, iface)
    tot = traffic_feed(src, rx, tx, d.get("MainPID", "0"))
    dev = device_stats(d)
    return {
        "ok": True, "state": d.get("ActiveState", "unknown"), "substate": d.get("SubState", ""),
        "load_state": d.get("LoadState", ""),
        "pid": d.get("MainPID", "0"), "uptime": uptime, "memory": mem,
        "restarts": d.get("NRestarts", ""), "version": sb_version(),
        "iface": iface, "iface_found": iface in net, "tun_configured": has_tun(), "src": src, "conns": conns, "rx": rx, "tx": tx, "ts": time.time(), "dev": dev,
        "total": tot,
    }


# ------------------------------------------------- трафик за всё время (переживает перезапуски sing-box)
TRAFFIC_FILE = os.path.join(DATA, "traffic.json")
TRAFFIC_LOCK = threading.Lock()
_traffic = {"loaded": False, "since": 0, "rx": 0, "tx": 0, "last": None, "saved": 0.0}


def traffic_counters(active, net=None, iface=None):
    """Счётчики текущей сессии sing-box: из Clash API (TUN + прокси-порты) или с TUN-интерфейса."""
    if net is None:
        try:
            net = read_net()
        except OSError:
            net = {}
        iface = tun_name(net)
    rx, tx = net.get(iface, (None, None))
    src, conns = "iface", None
    if active and clash_conf():
        try:
            cj = clash_call("GET", "/connections", timeout=3)
            rx, tx, src = int(cj.get("downloadTotal", 0)), int(cj.get("uploadTotal", 0)), "clash"
            conns = len(cj.get("connections") or [])
        except (RuntimeError, ValueError, TypeError):
            pass
    return src, rx, tx, conns


def _traffic_load():
    if _traffic["loaded"]:
        return
    try:
        with open(TRAFFIC_FILE) as f:
            d = json.load(f)
        _traffic.update(since=int(d.get("since") or 0), rx=int(d.get("rx") or 0), tx=int(d.get("tx") or 0), last=d.get("last"))
    except (OSError, ValueError, TypeError):
        pass
    if not _traffic["since"]:
        _traffic["since"] = int(time.time())
    _traffic["loaded"] = True


def _traffic_save():
    try:
        os.makedirs(DATA, exist_ok=True)
        _write_bytes(TRAFFIC_FILE, json.dumps({k: _traffic[k] for k in ("since", "rx", "tx", "last")}).encode())
        _traffic["saved"] = time.time()
    except OSError:
        pass


def traffic_feed(src, rx, tx, pid, save_every=300):
    """Прибавляет прирост счётчиков сессии к общему итогу. Новая сессия (другой PID или счётчик меньше) —
    прибавляется целиком: счётчики начинаются с нуля. Смена источника — только новая точка отсчёта."""
    with TRAFFIC_LOCK:
        _traffic_load()
        if rx is None or tx is None:
            return {"rx": _traffic["rx"], "tx": _traffic["tx"], "since": _traffic["since"]}
        cur = {"src": src, "rx": int(rx), "tx": int(tx), "pid": str(pid)}
        last = _traffic["last"]
        if last and last.get("src") == src:
            if last.get("pid") == cur["pid"] and cur["rx"] >= last["rx"] and cur["tx"] >= last["tx"]:
                _traffic["rx"] += cur["rx"] - last["rx"]
                _traffic["tx"] += cur["tx"] - last["tx"]
            else:
                _traffic["rx"] += cur["rx"]
                _traffic["tx"] += cur["tx"]
        _traffic["last"] = cur
        if time.time() - _traffic["saved"] >= save_every:
            _traffic_save()
        return {"rx": _traffic["rx"], "tx": _traffic["tx"], "since": _traffic["since"]}


def traffic_loop():
    """Считает трафик и когда панель никто не открывает: раз в 30 секунд."""
    while True:
        time.sleep(30)
        try:
            rc, out = run(["systemctl", "show", SERVICE, "-p", "ActiveState,MainPID"])
            d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
            src, rx, tx, _ = traffic_counters(d.get("ActiveState") == "active")
            traffic_feed(src, rx, tx, d.get("MainPID", "0"))
        except Exception:
            pass


@app.post("/api/traffic")
def traffic_reset(body: dict, user: str = Depends(auth)):
    if body.get("action") != "reset":
        raise HTTPException(400, "Недопустимое действие")
    with TRAFFIC_LOCK:
        _traffic_load()
        _traffic.update(rx=0, tx=0, since=int(time.time()))
        _traffic_save()
    return {"ok": True, "message": "Счётчик трафика за всё время обнулён"}


@app.post("/api/service")
def service(body: dict, user: str = Depends(auth)):
    action = body.get("action")
    if action not in ("start", "stop", "restart", "reload"):
        raise HTTPException(400, "Недопустимое действие")
    rc, out = run(["systemctl", action, SERVICE], timeout=60)
    if rc != 0:
        return {"ok": False, "error": out or f"systemctl {action} завершился с кодом {rc}"}
    return {"ok": True, "message": f"{action}: выполнено"}


@app.get("/api/logs")
def logs(lines: int = 200, user: str = Depends(auth)):
    lines = max(10, min(lines, 1000))
    rc, out = run(["journalctl", "-u", SERVICE, "-n", str(lines), "--no-pager", "-o", "short-iso"])
    return {"ok": True, "text": out}


# --------------------------------------------------------------------- конфиг
def _active():
    return run(["systemctl", "is-active", SERVICE])[1] == "active"


def _backup_list():
    try:
        return sorted(os.listdir(BACKUPS), reverse=True)
    except OSError:
        return []


def apply_config(text, mode="apply"):
    """mode: check — только проверить, save — сохранить, apply — сохранить и перезапустить."""
    try:
        cfg = json.loads(text)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"Некорректный JSON: {e}"}
    if not isinstance(cfg, dict):
        return {"ok": False, "error": "Конфиг должен быть JSON-объектом"}
    pretty = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    cdir = os.path.dirname(os.path.abspath(CONFIG))

    with LOCK:
        check_path = os.path.join(cdir, ".panel-check.json")
        with open(check_path, "w") as f:
            f.write(pretty)
        try:
            rc, out = run([BINARY, "check", "-c", check_path], cwd=cdir)
        finally:
            try:
                os.remove(check_path)
            except OSError:
                pass
        if rc != 0:
            return {"ok": False, "error": "sing-box check:\n" + out}
        if mode == "check":
            return {"ok": True, "message": "Конфиг корректен"}

        os.makedirs(BACKUPS, exist_ok=True)
        bk_name = None
        mode_bits = 0o600
        if os.path.exists(CONFIG):
            bk_name = datetime.now().strftime("config-%Y%m%d-%H%M%S.json")
            shutil.copy2(CONFIG, os.path.join(BACKUPS, bk_name))
            mode_bits = os.stat(CONFIG).st_mode & 0o777
        new_path = CONFIG + ".panel-new"
        with open(new_path, "w") as f:
            f.write(pretty)
        os.chmod(new_path, mode_bits)
        os.replace(new_path, CONFIG)
        for old in _backup_list()[BACKUP_KEEP:]:
            try:
                os.remove(os.path.join(BACKUPS, old))
            except OSError:
                pass

        if mode == "save":
            return {"ok": True, "message": "Сохранено. Служба не перезапускалась"}

        rc, out = run(["systemctl", "restart", SERVICE], timeout=60)
        good = False
        if rc == 0:
            time.sleep(2.5)
            good = _active()
            if good:
                time.sleep(2)
                good = _active()
        if good:
            return {"ok": True, "message": "Применено, служба работает"}

        # откат
        tail = run(["journalctl", "-u", SERVICE, "-n", "15", "--no-pager"])[1]
        msg = "Служба не запустилась с новым конфигом"
        if bk_name:
            shutil.copy2(os.path.join(BACKUPS, bk_name), CONFIG)
            run(["systemctl", "restart", SERVICE], timeout=60)
            msg += ", прежний конфиг восстановлен"
        return {"ok": False, "error": f"{msg}\n\n{tail}"}


@app.get("/api/config")
def get_config(user: str = Depends(auth)):
    try:
        with open(CONFIG) as f:
            return {"ok": True, "text": f.read(), "path": CONFIG}
    except OSError as e:
        return {"ok": False, "error": f"Не удалось прочитать {CONFIG}: {e}"}


@app.post("/api/config")
def set_config(body: dict, user: str = Depends(auth)):
    mode = body.get("mode", "check")
    if mode not in ("check", "save", "apply"):
        raise HTTPException(400, "bad mode")
    return apply_config(str(body.get("text", "")), mode)


@app.get("/api/backups")
def backups(user: str = Depends(auth)):
    return {"ok": True, "items": _backup_list()}


@app.post("/api/backups/restore")
def restore(body: dict, user: str = Depends(auth)):
    name = os.path.basename(str(body.get("name", "")))
    path = os.path.join(BACKUPS, name)
    if not name or not os.path.isfile(path):
        return {"ok": False, "error": "Бэкап не найден"}
    with open(path) as f:
        return apply_config(f.read(), "apply")


# -------------------------------------------------------------------- подписка
SKIP_TYPES = {"direct", "block", "dns", "selector", "urltest"}


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def q1(qs, key, default=""):
    return qs.get(key, [default])[0]


def tls_block(qs, sec, host=""):
    if sec not in ("tls", "reality"):
        return None
    t = {"enabled": True}
    sni = q1(qs, "sni") or q1(qs, "peer") or ""
    if sni:
        t["server_name"] = sni
    if q1(qs, "allowInsecure") in ("1", "true") or q1(qs, "insecure") in ("1", "true"):
        t["insecure"] = True
    if q1(qs, "alpn"):
        t["alpn"] = q1(qs, "alpn").split(",")
    fp = q1(qs, "fp")
    if fp or sec == "reality":
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    if sec == "reality":
        t["reality"] = {"enabled": True, "public_key": q1(qs, "pbk"), "short_id": q1(qs, "sid")}
    return t


def transport_block(typ, path="", host="", service=""):
    if typ == "ws":
        tr = {"type": "ws", "path": path or "/"}
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if typ == "grpc":
        return {"type": "grpc", "service_name": service}
    if typ in ("http", "h2"):
        return {"type": "http", "host": [host] if host else [], "path": path or "/"}
    if typ == "httpupgrade":
        return {"type": "httpupgrade", "path": path or "/", "host": host}
    return None


def parse_vless(u):
    p = urllib.parse.urlsplit(u)
    qs = urllib.parse.parse_qs(p.query)
    o = {"type": "vless", "tag": urllib.parse.unquote(p.fragment) or p.hostname,
         "server": p.hostname, "server_port": p.port, "uuid": urllib.parse.unquote(p.username or "")}
    if q1(qs, "flow"):
        o["flow"] = q1(qs, "flow")
    tls = tls_block(qs, q1(qs, "security"))
    if tls:
        o["tls"] = tls
    tr = transport_block(q1(qs, "type", "tcp"), q1(qs, "path"), q1(qs, "host"), q1(qs, "serviceName"))
    if tr:
        o["transport"] = tr
    return o


def parse_trojan(u):
    p = urllib.parse.urlsplit(u)
    qs = urllib.parse.parse_qs(p.query)
    o = {"type": "trojan", "tag": urllib.parse.unquote(p.fragment) or p.hostname,
         "server": p.hostname, "server_port": p.port, "password": urllib.parse.unquote(p.username or "")}
    tls = tls_block(qs, q1(qs, "security", "tls"))
    if tls:
        o["tls"] = tls
    tr = transport_block(q1(qs, "type", "tcp"), q1(qs, "path"), q1(qs, "host"), q1(qs, "serviceName"))
    if tr:
        o["transport"] = tr
    return o


def parse_ss(u):
    body = u[len("ss://"):]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    body = body.split("?")[0].rstrip("/")
    if "@" not in body:
        body = b64d(body)
    userinfo, hostport = body.rsplit("@", 1)
    userinfo = urllib.parse.unquote(userinfo)
    if ":" not in userinfo:
        userinfo = b64d(userinfo)
    method, password = userinfo.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    return {"type": "shadowsocks", "tag": name or host, "server": host,
            "server_port": int(port), "method": method, "password": password}


def parse_vmess(u):
    j = json.loads(b64d(u[len("vmess://"):]))
    o = {"type": "vmess", "tag": j.get("ps") or j["add"], "server": j["add"],
         "server_port": int(j["port"]), "uuid": j["id"],
         "security": j.get("scy") or "auto", "alter_id": int(j.get("aid") or 0)}
    if j.get("tls") == "tls":
        t = {"enabled": True}
        if j.get("sni") or j.get("host"):
            t["server_name"] = j.get("sni") or j.get("host")
        if j.get("alpn"):
            t["alpn"] = j["alpn"].split(",")
        if j.get("fp"):
            t["utls"] = {"enabled": True, "fingerprint": j["fp"]}
        o["tls"] = t
    tr = transport_block(j.get("net", "tcp"), j.get("path", ""), j.get("host", ""), j.get("path", ""))
    if tr:
        o["transport"] = tr
    return o


def parse_hy2(u):
    p = urllib.parse.urlsplit(u)
    qs = urllib.parse.parse_qs(p.query)
    pw = urllib.parse.unquote(p.username or "")
    if p.password:
        pw += ":" + urllib.parse.unquote(p.password)
    o = {"type": "hysteria2", "tag": urllib.parse.unquote(p.fragment) or p.hostname,
         "server": p.hostname, "server_port": p.port, "password": pw,
         "tls": {"enabled": True}}
    if q1(qs, "sni"):
        o["tls"]["server_name"] = q1(qs, "sni")
    if q1(qs, "insecure") in ("1", "true"):
        o["tls"]["insecure"] = True
    if q1(qs, "obfs"):
        o["obfs"] = {"type": q1(qs, "obfs"), "password": q1(qs, "obfs-password")}
    return o


PARSERS = {"vless": parse_vless, "trojan": parse_trojan, "ss": parse_ss,
           "vmess": parse_vmess, "hysteria2": parse_hy2, "hy2": parse_hy2}


def parse_subscription(raw):
    raw = raw.strip()
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if data is not None:
        obs = data.get("outbounds") if isinstance(data, dict) else data
        if not isinstance(obs, list):
            raise ValueError("В JSON нет списка outbounds")
        return [o for o in obs if isinstance(o, dict) and o.get("tag") and o.get("type") not in SKIP_TYPES], 0
    if "://" not in raw:
        raw = b64d(raw)
    nodes, bad = [], 0
    for line in raw.splitlines():
        line = line.strip()
        scheme = line.split("://", 1)[0].lower() if "://" in line else ""
        if scheme not in PARSERS:
            continue
        try:
            nodes.append(PARSERS[scheme](line))
        except Exception:
            bad += 1
    return nodes, bad


def finalize(nodes, prefix=PREFIX):
    seen, out = set(), []
    for n in nodes:
        base = prefix + re.sub(r"\s+", " ", str(n["tag"])).strip()
        tag, i = base, 2
        while tag in seen:
            tag = f"{base} #{i}"
            i += 1
        seen.add(tag)
        n = dict(n)
        n["tag"] = tag
        out.append(n)
    return out


DEFAULT_UA = "sing-box/1.12.0 (singbox-panel)"
# часть панелей (Marzban/PasarGuard/Remnawave и др.) отвечает 404/403 или другим форматом на неизвестный User-Agent
FALLBACK_UAS = ["v2rayN/7.0.0", "clash-verge/v2.0.0", "Hiddify/2.5.0", "Happ/1.0"]


_LAST_HDRS = {}           # url -> заголовки последнего ответа (subscription-userinfo и др.)


def fetch(url, ua=None):
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("URL подписки должен начинаться с http:// или https://")
    req = urllib.request.Request(url, headers={"User-Agent": ua or DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        _LAST_HDRS[url] = {k.lower(): v for k, v in r.headers.items()}
        return r.read().decode("utf-8", "replace")


def parse_userinfo(hdrs):
    """Заголовок subscription-userinfo: upload=…; download=…; total=…; expire=… (+ profile-title)."""
    if not hdrs:
        return None
    raw = hdrs.get("subscription-userinfo", "")
    info = {}
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() in ("upload", "download", "total", "expire"):
            try:
                info[k.strip().lower()] = int(float(v.strip()))
            except ValueError:
                pass
    title = hdrs.get("profile-title", "").strip()
    if title.lower().startswith("base64:"):
        try:
            title = base64.b64decode(title[7:] + "===").decode("utf-8", "replace")
        except (ValueError, TypeError):
            title = ""
    if title:
        info["title"] = title[:100]
    if not info:
        return None
    info["checked"] = int(time.time())
    return info


def fetch_nodes(sub):
    """Скачивает подписку; если сервер отвечает ошибкой или без узлов — пробует другие User-Agent."""
    custom = (sub.get("ua") or "").strip()
    uas = [custom] if custom else [None] + FALLBACK_UAS
    tried = []
    for ua in uas:
        label = ua or DEFAULT_UA
        try:
            _LAST_HDRS.pop(sub["url"], None)
            raw = fetch(sub["url"]) if ua is None else fetch(sub["url"], ua)
            nodes, bad = parse_subscription(raw)
            if nodes:
                sub["info"] = parse_userinfo(_LAST_HDRS.get(sub["url"])) or {"checked": int(time.time())}
                return nodes, bad
            tried.append(f"{label} → в ответе нет узлов")
        except urllib.error.HTTPError as e:
            tried.append(f"{label} → HTTP {e.code}")
        except urllib.error.URLError as e:
            raise ValueError(f"Не удалось подключиться к серверу подписки: {e.reason}")
        except Exception as e:
            tried.append(f"{label} → {e}")
    raise ValueError("Сервер подписки не отдал узлы. Пробовали User-Agent: " + "; ".join(tried)
                     + ". Проверьте ссылку или укажите свой User-Agent в настройках подписки")


def _owned(tag, prefix, other_prefixes):
    """Тег принадлежит подписке с этим префиксом (побеждает самый длинный совпавший префикс)."""
    t = str(tag or "")
    return t.startswith(prefix) and not any(t.startswith(p) and len(p) > len(prefix) for p in other_prefixes)


def _replace_refs(cfg, mapping):
    """Заменяет теги в ссылках: группы, default, правила, final, detour."""
    def fix(t):
        return mapping.get(t, t)
    for o in (cfg.get("outbounds") or []) + (cfg.get("endpoints") or []):
        if isinstance(o.get("outbounds"), list):
            seen, out = set(), []
            for t in o["outbounds"]:
                t = fix(t)
                if t not in seen:
                    seen.add(t)
                    out.append(t)
            o["outbounds"] = out
        for k in ("default", "detour"):
            if isinstance(o.get(k), str):
                o[k] = fix(o[k])
    route = cfg.get("route") or {}
    if isinstance(route.get("final"), str):
        route["final"] = fix(route["final"])
    for r in route.get("rules") or []:
        if isinstance(r, dict) and isinstance(r.get("outbound"), str):
            r["outbound"] = fix(r["outbound"])
    for sv in (cfg.get("dns") or {}).get("servers") or []:
        if isinstance(sv, dict) and isinstance(sv.get("detour"), str):
            sv["detour"] = fix(sv["detour"])


def merge_nodes(cfg, nodes, groups, prefix=PREFIX, other_prefixes=(), adopt=False):
    outs = cfg.setdefault("outbounds", [])
    old = {o.get("tag") for o in outs if _owned(o.get("tag"), prefix, other_prefixes)}
    outs[:] = [o for o in outs if o.get("tag") not in old]
    outs.extend(nodes)
    new = [n["tag"] for n in nodes]
    if adopt:       # узлы, добавленные вручную с теми же именами, заменяются узлами подписки (ссылки переписываются)
        base = {n["tag"][len(prefix):]: n["tag"] for n in nodes if n["tag"].startswith(prefix)}
        mine = [prefix, *other_prefixes]
        plain = {"selector", "urltest", "direct", "block", "dns"}
        mapping = {o["tag"]: base[o["tag"]] for o in outs
                   if o.get("tag") in base and o.get("type") not in plain and not any(o["tag"].startswith(p) for p in mine)}
        if mapping:
            outs[:] = [o for o in outs if o.get("tag") not in mapping]
            _replace_refs(cfg, mapping)
    gone = old - set(new)
    for o in outs:                                  # свои группы пользователя теряют только исчезнувшие узлы
        if o.get("type") in ("selector", "urltest") and o.get("tag") not in groups:
            o["outbounds"] = [t for t in o.get("outbounds", []) if t not in gone]
            if o.get("default") in gone:
                o.pop("default")
    for g in groups:
        existing = next((o for o in outs if o.get("tag") == g), None)
        if existing and existing.get("type") in ("selector", "urltest"):
            kept = [t for t in existing.get("outbounds", []) if t not in old]
            existing["outbounds"] = kept + [t for t in new if t not in kept]
            if existing.get("default") in old:
                existing.pop("default")
        elif existing is None:
            if not any(o.get("tag") == "direct" for o in outs):
                outs.append({"type": "direct", "tag": "direct"})
            outs.insert(0, {"type": "selector", "tag": g, "outbounds": new + ["direct"]})
            route = cfg.setdefault("route", {})
            if route.get("final") in (None, "", "direct"):      # иначе новая группа не использовалась бы: весь трафик шёл бы direct
                route["final"] = g


def dangling_refs(cfg):
    """Ссылки route.final / route.rules на несуществующие outbound."""
    tags = {o.get("tag") for o in (cfg.get("outbounds") or [])} | {e.get("tag") for e in (cfg.get("endpoints") or [])}
    route = cfg.get("route") or {}
    bad = []
    if route.get("final") and route["final"] not in tags:
        bad.append(f"route.final → {route['final']}")
    for i, r in enumerate(route.get("rules") or []):
        t = r.get("outbound") if isinstance(r, dict) else None
        if t and t not in tags:
            bad.append(f"правило №{i + 1} → {t}")
    return bad


def update_subscriptions(sids=None, restart=True, dry=False, auto=False):
    """Обновляет выбранные подписки (None = все с URL) и применяет конфиг один раз."""
    with LOCK:
        st = load_state()
        subs = [x for x in st["subs"] if (sids is None or x["id"] in sids) and (sids is not None or x["url"] or x.get("links"))]
        if not subs:
            return {"ok": False, "error": "URL подписки не задан" if not st["subs"] else "Подписка не найдена"}
        now = time.time()
        loaded, failed = [], []
        for sub in subs:
            sub["last_attempt"] = now
            try:
                if sub.get("kind") == "links":
                    nodes, bad = parse_subscription(sub.get("links") or "")
                    if not nodes:
                        raise ValueError("Не удалось разобрать ни одной ссылки (поддерживаются: " + ", ".join(f"{p}://" for p in PARSERS) + ")")
                elif not sub["url"]:
                    raise ValueError("URL подписки не задан")
                else:
                    nodes, bad = fetch_nodes(sub)
                nodes = finalize(nodes, sub["prefix"])
                if not nodes:
                    raise ValueError("В подписке не найдено ни одного поддерживаемого узла")
                total = len(nodes)
                # каждый узел проверяется вашим sing-box отдельно: что версия не понимает, отбрасывается с причиной
                nodes, rejected, checked = validate_nodes(nodes)
                if not nodes:
                    raise ValueError(f"Ни один из {total} узлов не подходит вашей версии sing-box "
                                     f"({sb_version() or '?'}). Пример причины: {rejected[0]['reason']}")
                loaded.append({"sub": sub, "nodes": nodes, "bad": bad, "rejected": rejected, "checked": checked, "total": total})
            except Exception as e:
                sub["last_error"] = str(e)
                failed.append({"id": sub["id"], "name": sub["name"], "ok": False, "error": str(e)})
        if not loaded:
            save_state(st)
            return {"ok": False, "error": "; ".join(f"{f['name']}: {f['error']}" for f in failed), "results": failed}
        summary = [{"tag": n["tag"], "type": n["type"], "server": n.get("server", ""), "sub": L["sub"]["name"]}
                   for L in loaded for n in L["nodes"]]
        rejected_all = [r for L in loaded for r in L["rejected"]]
        skipped = sum(L["bad"] for L in loaded)
        count = sum(len(L["nodes"]) for L in loaded)
        total = sum(L["total"] for L in loaded)
        note = (f", отклонено вашей версией: {len(rejected_all)}" if rejected_all else "") + \
               ("" if all(L["checked"] for L in loaded) else ", проверка узлов версией НЕ выполнялась (sing-box не найден?)")
        results = failed + [{"id": L["sub"]["id"], "name": L["sub"]["name"], "ok": True, "count": len(L["nodes"])} for L in loaded]
        fail_note = ("; не обновились: " + "; ".join(f"{f['name']} ({f['error']})" for f in failed)) if failed else ""
        if dry:
            save_state(st)
            return {"ok": True, "nodes": summary, "skipped": skipped, "rejected": rejected_all,
                    "checked": all(L["checked"] for L in loaded), "results": results,
                    "message": f"Подходит узлов: {count} из {total}" + (f", не разобрано: {skipped}" if skipped else "") + note + fail_note}
        try:
            with open(CONFIG) as f:
                cfg = json.load(f)
            before = json.dumps(cfg, sort_keys=True)
            bad_before = set(dangling_refs(cfg))
            prefixes = [x["prefix"] for x in st["subs"]]
            for L in loaded:
                for gs in group_status(cfg, set(), L["sub"]["groups"] or ["proxy"]):
                    if not gs["ok"]:
                        raise ValueError(f"Группа «{gs['name']}» имеет тип {gs['type']}: узлы можно добавлять только в selector или urltest")
            for L in loaded:
                sub = L["sub"]
                merge_nodes(cfg, L["nodes"], sub["groups"] or ["proxy"], sub["prefix"], [q for q in prefixes if q != sub["prefix"]],
                            adopt=bool(sub.get("adopt")))
            broken = [x for x in dangling_refs(cfg) if x not in bad_before]
            if broken:
                raise ValueError("Обновление отменено: после него пропали серверы, на которые ведут правила маршрутизации: "
                                 + ", ".join(broken) + ". Измените эти правила (вкладка «Маршрутизация») или направьте их в группу.")
            if auto and json.dumps(cfg, sort_keys=True) == before:
                for L in loaded:
                    L["sub"]["last_update"], L["sub"]["last_error"] = time.time(), ""
                save_state(st)
                return {"ok": True, "message": "Без изменений"}
            gnote = []
            for L in loaded:
                tags = {n["tag"] for n in L["nodes"]}
                gnote += [f"{L['sub']['name']} → {g['name']}: {g['have']} из {len(tags)}" + ("" if g["exists"] else "")
                          for g in group_status(cfg, tags, L["sub"]["groups"] or ["proxy"])]
            # автообновление не должно запускать службу, которую владелец остановил
            res = apply_config(json.dumps(cfg), "apply" if restart and not (auto and not _active()) else "save")
        except Exception as e:
            for L in loaded:
                L["sub"]["last_error"] = str(e)
            save_state(st)
            return {"ok": False, "error": str(e), "results": results}
        for L in loaded:
            sub = L["sub"]
            if res["ok"]:
                sub["last_update"], sub["last_count"], sub["last_error"] = time.time(), len(L["nodes"]), ""
            else:
                sub["last_error"] = res["error"]
        save_state(st)
        res["nodes"], res["skipped"], res["rejected"], res["results"] = summary, skipped, rejected_all, results
        if res["ok"]:
            res["message"] = (f"Импортировано узлов: {count}{note}. " + res["message"] + fail_note
                              + ". В группах: " + "; ".join(gnote)
                              + ("" if restart else ". Сохранено БЕЗ перезапуска: на вкладке «Серверы» изменения появятся после перезапуска sing-box"))
            res["groups"] = gnote
        return res


def update_subscription(restart=True, dry=False, auto=False, sid=None):
    return update_subscriptions([sid] if sid else None, restart=restart, dry=dry, auto=auto)


def group_status(cfg, tags, groups):
    """Для каждой целевой группы: есть ли она в конфиге, какого типа и сколько узлов подписки в ней."""
    outs = (cfg or {}).get("outbounds", [])
    res = []
    for g in groups:
        o = next((x for x in outs if x.get("tag") == g), None)
        res.append({"name": g, "exists": o is not None, "type": (o or {}).get("type", ""),
                    "have": sum(1 for t in (o or {}).get("outbounds", []) if t in tags),
                    "ok": o is None or (o or {}).get("type") in ("selector", "urltest")})
    return res


def _sub_view(st, cfg):
    prefixes = [x["prefix"] for x in st["subs"]]
    outs = [o.get("tag") for o in (cfg or {}).get("outbounds", [])] if cfg else []
    res = []
    for x in st["subs"]:
        others = [q for q in prefixes if q != x["prefix"]]
        mine = {t for t in outs if _owned(t, x["prefix"], others)}
        res.append({**x, "node_count": len(mine), "group_status": group_status(cfg, mine, x["groups"] or ["proxy"])})
    return res


@app.get("/api/subs")
def get_subs(user: str = Depends(auth)):
    try:
        cfg = _cfg_read()
    except (OSError, ValueError):
        cfg = None
    return {"ok": True, "subs": _sub_view(load_state(), cfg)}


def _legacy_sub(st):
    return next((x for x in st["subs"] if x["id"] == "main"), None) or (st["subs"][0] if st["subs"] else None)


@app.get("/api/sub")
def get_sub_legacy(user: str = Depends(auth)):
    """Для старой (закэшированной) страницы: одна подписка в прежнем формате."""
    x = _legacy_sub(load_state()) or SUB_DEFAULTS
    return {"ok": True, **{k: x[k] for k in LEGACY_SUB_KEYS}}


@app.post("/api/sub")
def set_sub_legacy(body: dict, user: str = Depends(auth)):
    with LOCK:
        st = load_state()
        x = _legacy_sub(st)
        if x is None:
            x = {**SUB_DEFAULTS, "id": "main", "name": "Основная", "prefix": PREFIX}
            st["subs"].append(x)
        x["url"] = str(body.get("url", "")).strip()
        x["groups"] = _parse_groups(body.get("groups"))
        x["interval_h"] = max(0, int(body.get("interval_h") or 0))
        save_state(st)
    return {"ok": True, "message": "Настройки подписки сохранены"}


@app.post("/api/sub/update")
def sub_update_legacy(body: dict, user: str = Depends(auth)):
    x = _legacy_sub(load_state())
    if x is None:
        return {"ok": False, "error": "URL подписки не задан"}
    return update_subscription(restart=bool(body.get("restart", True)), dry=bool(body.get("dry", False)), sid=x["id"])


def _parse_groups(v):
    return [g.strip() for g in str(v or "proxy").split(",") if g.strip()] or ["proxy"]


@app.post("/api/subs")
def set_subs(body: dict, user: str = Depends(auth)):
    act = body.get("action")
    if act == "info":
        res = sub_info_refresh(body.get("id"))
        bad = [r for r in res if not r["ok"]]
        return {"ok": not bad or len(bad) < len(res), "results": res,
                "message": "Данные подписок обновлены", "error": "; ".join(r["error"] for r in bad)}
    if act == "update":
        sid = body.get("id")
        return update_subscriptions([sid] if sid else None, restart=bool(body.get("restart", True)), dry=bool(body.get("dry", False)))
    with LOCK:
        st = load_state()
        if act == "save":
            name, url = str(body.get("name", "")).strip(), str(body.get("url", "")).strip()
            kind = "links" if body.get("kind") == "links" else "url"
            links = "\n".join(l.strip() for l in str(body.get("links") or "").splitlines() if l.strip())[:200000]
            if not name:
                return {"ok": False, "error": "Укажите имя подписки"}
            if kind == "links":
                url = ""
                good, bad = parse_subscription(links) if "://" in links else ([], 0)
                if not good:
                    return {"ok": False, "error": "Вставьте хотя бы одну ссылку вида vless://… (поддерживаются: "
                                                  + ", ".join(f"{p}://" for p in PARSERS) + ")"}
            elif not url.lower().startswith(("http://", "https://")):
                return {"ok": False, "error": "URL подписки должен начинаться с http:// или https://"}
            try:
                interval = max(0, int(body.get("interval_h") or 0))
            except ValueError:
                return {"ok": False, "error": "Автообновление: число часов"}
            sub = next((x for x in st["subs"] if x["id"] == body.get("id")), None) if body.get("id") else None
            if any(x["name"].lower() == name.lower() and x is not sub for x in st["subs"]):
                return {"ok": False, "error": "Подписка с таким именем уже есть"}
            if sub is None:
                prefix = str(body.get("prefix") or f"{name} · ")
                if len(prefix.strip()) < 2:
                    return {"ok": False, "error": "Префикс тегов слишком короткий"}
                if any(x["prefix"] == prefix for x in st["subs"]):
                    return {"ok": False, "error": "Такой префикс тегов уже используется другой подпиской"}
                try:
                    tags = [o.get("tag", "") for o in _cfg_read().get("outbounds", [])]
                except (OSError, ValueError):
                    tags = []
                clash = [t for t in tags if t.startswith(prefix)]
                if clash:
                    return {"ok": False, "error": f"Префикс «{prefix}» совпадает с уже существующими тегами ({clash[0]}…). Задайте другой префикс"}
                sub = {**SUB_DEFAULTS, "id": secrets.token_hex(3), "prefix": prefix}
                st["subs"].append(sub)
            sub.update(name=name, url=url, groups=_parse_groups(body.get("groups")), interval_h=interval if kind == "url" else 0,
                       ua=str(body.get("ua") or "").strip()[:200], adopt=bool(body.get("adopt")), kind=kind, links=links)
            if kind == "links":
                sub["info"] = None
            save_state(st)
            return {"ok": True, "id": sub["id"], "message": "Ключи сохранены" if kind == "links" else "Подписка сохранена"}

        if act == "delete":
            sub = next((x for x in st["subs"] if x["id"] == body.get("id")), None)
            if not sub:
                return {"ok": False, "error": "Подписка не найдена"}
            msg = f"Подписка «{sub['name']}» удалена"
            if body.get("remove_nodes"):
                try:
                    cfg = _cfg_read()
                except (OSError, ValueError) as e:
                    return {"ok": False, "error": f"Конфиг не прочитан: {e}"}
                others = [x["prefix"] for x in st["subs"] if x is not sub]
                bad_before = set(dangling_refs(cfg))
                merge_nodes(cfg, [], [], sub["prefix"], others)         # убирает узлы подписки и ссылки на них из групп
                broken = [x for x in dangling_refs(cfg) if x not in bad_before]
                if broken:
                    return {"ok": False, "error": "Узлы удалить нельзя: на них ведут правила маршрутизации: " + ", ".join(broken)}
                res = apply_config(json.dumps(cfg), "apply" if body.get("restart", True) else "save")
                if not res["ok"]:
                    return res
                msg += ", её узлы убраны из конфига"
            st["subs"] = [x for x in st["subs"] if x is not sub]
            save_state(st)
            return {"ok": True, "message": msg}
    raise HTTPException(400, "Недопустимое действие")


def sub_info_refresh(sid=None):
    """Только срок действия и трафик (заголовок subscription-userinfo): скачиваем подписку, конфиг не меняем."""
    subs = [x for x in load_state()["subs"] if x.get("url") and (not sid or x["id"] == sid)]
    res = []
    for sub in subs:                                # сеть — без LOCK, чтобы не задерживать остальные действия
        try:
            _LAST_HDRS.pop(sub["url"], None)
            fetch(sub["url"], sub.get("ua") or None)
            res.append({"id": sub["id"], "ok": True, "info": parse_userinfo(_LAST_HDRS.get(sub["url"]))})
        except Exception as e:
            res.append({"id": sub["id"], "ok": False, "error": f"{sub['name']}: {e}"})
    with LOCK:
        st = load_state()
        for r in res:
            x = next((q for q in st["subs"] if q["id"] == r["id"]), None)
            if x is not None:
                x["info_try"] = int(time.time())       # и при ошибке: следующая попытка не раньше чем через INFO_EVERY
                if r["ok"]:
                    x["info"] = r["info"] or {"checked": int(time.time())}
        save_state(st)
    return res


INFO_EVERY = 6 * 3600


def auto_loop():
    while True:
        time.sleep(60)
        try:
            st = load_state()
            due = [x["id"] for x in st["subs"] if x.get("interval_h") and x.get("url")
                   and time.time() - x.get("last_attempt", 0) >= x["interval_h"] * 3600]
            if due:
                update_subscriptions(due, restart=True, auto=True)
            for x in load_state()["subs"]:          # срок и трафик подписки — раз в 6 часов
                last = max((x.get("info") or {}).get("checked") or 0, x.get("info_try") or 0, x.get("last_update") or 0)
                if x.get("url") and time.time() - last >= INFO_EVERY:
                    sub_info_refresh(x["id"])
        except Exception:
            pass


def detect_service():
    """Имя установленной службы sing-box (sing-box, sing-box-client…); '' если ничего не нашли."""
    rc, out = run(["systemctl", "list-unit-files", "--no-legend", "--type=service", "sing-box*.service"])
    names = []
    for line in out.splitlines() if rc == 0 else []:
        parts = line.split()
        if parts and parts[0].endswith(".service") and "@" not in parts[0]:
            names.append(parts[0][:-len(".service")])
    if not names or "sing-box" in names:
        return "sing-box" if names else ""
    return names[0]


@app.on_event("startup")
def _startup():
    global BINARY, SERVICE
    os.makedirs(DATA, exist_ok=True)
    if "SBP_SERVICE" not in os.environ:       # имя службы не задано: берём установленную sing-box*.service
        found = detect_service()
        if found:
            SERVICE = found
    if "SBP_BINARY" not in os.environ:        # версию и проверки берём у того бинарника, что реально запускает служба
        b = service_binary()
        if b:
            BINARY = b
    presets_load_cache()                       # списки наборов, скачанные с GitHub раньше
    threading.Thread(target=auto_loop, daemon=True).start()
    threading.Thread(target=watch_code, daemon=True).start()
    threading.Thread(target=pu_loop, daemon=True).start()
    threading.Thread(target=fo_loop, daemon=True).start()
    threading.Thread(target=traffic_loop, daemon=True).start()
    threading.Thread(target=presets_loop, daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(5), migrate_presets(auto=True)), daemon=True).start()


# ------------------------------------------------- готовые наборы маршрутизации
PRESET_REV = 2           # увеличивайте при изменении списков; прежние списки добавляйте в PRESET_HISTORY
PRESETS = {
    "lan": {"t": "Локальные адреса (192.168.x.x, 10.x.x.x…)", "d": "direct",
            "r": [{"ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]}]},
    "ru": {"t": "Российские домены (.ru, .su, .рф)", "d": "direct", "r": [{"domain_suffix": ["ru", "su", "xn--p1ai"]}]},
    "youtube": {"t": "YouTube", "d": "proxy", "r": [{"domain_suffix": [
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com"]}]},
    "telegram": {"t": "Telegram", "d": "proxy", "r": [
        {"domain_suffix": ["telegram.org", "t.me", "telegram.me", "telegra.ph", "tdesktop.com", "telesco.pe", "cdn-telegram.org"]},
        {"ip_cidr": ["91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.56.0/22", "149.154.160.0/20", "185.76.151.0/24"]}]},
    "ai": {"t": "ChatGPT / OpenAI / Claude", "d": "proxy", "r": [{"domain_suffix": [
        "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "anthropic.com", "claude.ai"]}]},
    "discord": {"t": "Discord", "d": "proxy", "r": [{"domain_suffix": [
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]}]},
    "meta": {"t": "Instagram / Facebook / WhatsApp / Threads", "d": "proxy", "r": [{"domain_suffix": [
        "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "whatsapp.com", "whatsapp.net", "threads.net"]}]},
    "twitter": {"t": "X (Twitter)", "d": "proxy", "r": [{"domain_suffix": ["twitter.com", "x.com", "twimg.com", "t.co"]}]},
    "netflix": {"t": "Netflix", "d": "proxy", "r": [{"domain_suffix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"]}]},
    "spotify": {"t": "Spotify", "d": "proxy", "r": [{"domain_suffix": ["spotify.com", "scdn.co", "spotifycdn.com"]}]},
    "reddit": {"t": "Reddit", "d": "proxy", "r": [{"domain_suffix": [
        "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com", "redditinc.com"]}]},
}
# прежние версии списков: {id набора: {поле: [[старый список], …]}}. Правило с таким списком при обновлении получит новый.
PRESET_HISTORY = {}
PRESET_BUILTIN_REV = PRESET_REV          # наборы, вшитые в эту версию панели

# Свежие списки наборов лежат в репозитории (presets.json) и скачиваются отдельно от панели — раз в 2 часа и по кнопке.
# Скачивание только обновляет списки в панели; в конфиг они попадают по кнопке «Обновить списки наборов».
PRESETS_URL = "https://raw.githubusercontent.com/maxhoney920/singbox-panel/main/presets.json"
PRESETS_FILE = os.path.join(DATA, "presets.json")
PRESETS_EVERY = 2 * 3600
PRESET_FIELDS = ("domain_suffix", "domain", "domain_keyword", "ip_cidr")
_presets = {"source": "встроенные", "checked": 0, "error": ""}


def presets_validate(d):
    """Проверяет присланные наборы: только простые правила по доменам/подсетям, разумные размеры."""
    if not isinstance(d, dict) or not isinstance(d.get("rev"), int) or not isinstance(d.get("presets"), dict):
        raise ValueError("нет полей rev/presets")
    out, hist = {}, {}
    for pid, P in d["presets"].items():
        if not re.fullmatch(r"[a-z0-9_-]{1,32}", str(pid)) or not isinstance(P, dict):
            raise ValueError(f"неверный id набора {pid!r}")
        t, d_ = str(P.get("t", ""))[:100], P.get("d")
        if not t or d_ not in ("direct", "proxy") or not isinstance(P.get("r"), list) or not 0 < len(P["r"]) <= 10:
            raise ValueError(f"набор {pid}: нужны t, d (direct/proxy) и r")
        rules = []
        for r in P["r"]:
            if not isinstance(r, dict) or len(r) != 1 or next(iter(r)) not in PRESET_FIELDS:
                raise ValueError(f"набор {pid}: правило должно содержать одно поле из {', '.join(PRESET_FIELDS)}")
            f, vals = next(iter(r.items()))
            if not isinstance(vals, list) or not 0 < len(vals) <= 2000 or not all(isinstance(v, str) and 0 < len(v) <= 253 for v in vals):
                raise ValueError(f"набор {pid}: неверный список {f}")
            rules.append({f: list(vals)})
        out[pid] = {"t": t, "d": d_, "r": rules}
        if P.get("t_en"):
            out[pid]["t_en"] = str(P["t_en"])[:100]
    for pid, H in (d.get("history") or {}).items():
        if pid in out and isinstance(H, dict):
            hist[pid] = {f: [list(map(str, l)) for l in ls if isinstance(l, list)] for f, ls in H.items()
                         if f in PRESET_FIELDS and isinstance(ls, list)}
    return d["rev"], out, hist


def presets_apply(rev, presets, hist, source):
    """Заменяет списки наборов в памяти. Прежние списки попадают в историю, чтобы правила из них узнавались."""
    global PRESETS, PRESET_HISTORY, PRESET_REV
    merged = {pid: {f: [list(l) for l in ls] for f, ls in H.items()} for pid, H in PRESET_HISTORY.items()}
    for pid, H in hist.items():
        for f, ls in H.items():
            dst = merged.setdefault(pid, {}).setdefault(f, [])
            dst += [l for l in ls if sorted(l) not in [sorted(x) for x in dst]]
    for pid, P in PRESETS.items():                 # старые списки этой панели → в историю
        for pr in P["r"]:
            f = next(iter(pr))
            new = next((q[f] for q in (presets.get(pid) or {}).get("r", []) if f in q), None)
            if new is not None and sorted(new) != sorted(pr[f]):
                dst = merged.setdefault(pid, {}).setdefault(f, [])
                if sorted(pr[f]) not in [sorted(x) for x in dst]:
                    dst.append(list(pr[f]))
    PRESETS, PRESET_HISTORY, PRESET_REV = presets, merged, rev
    _presets["source"] = source


def presets_load_cache():
    try:
        with open(PRESETS_FILE) as f:
            rev, p, h = presets_validate(json.load(f))
    except (OSError, ValueError, TypeError):
        return
    if rev > PRESET_REV:
        presets_apply(rev, p, h, "GitHub (сохранённые)")


def presets_fetch():
    """Скачивает presets.json с GitHub; если там версия новее — обновляет списки в панели (конфиг не трогает)."""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    op.addheaders = [("User-Agent", "singbox-panel/" + APP_VERSION)]
    _presets["checked"] = int(time.time())
    try:
        with op.open(PRESETS_URL, timeout=30) as r:
            raw = r.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("файл больше 2 МБ")
        rev, p, h = presets_validate(json.loads(raw.decode("utf-8")))
    except (OSError, ValueError, TypeError) as e:
        _presets["error"] = f"Не удалось получить наборы с GitHub: {e}"
        return {"ok": False, "error": _presets["error"]}
    _presets["error"] = ""
    if rev <= PRESET_REV:
        return {"ok": True, "updated": False, "message": f"Списки наборов актуальны (версия {PRESET_REV})"}
    with LOCK:
        presets_apply(rev, p, h, "GitHub")
        try:
            os.makedirs(DATA, exist_ok=True)
            _write_bytes(PRESETS_FILE, raw)
        except OSError:
            pass
    return {"ok": True, "updated": True, "message": f"Загружены списки наборов версии {rev}. "
            "Если в конфиге есть правила из прежних списков, нажмите «Обновить списки наборов»"}


def presets_loop():
    time.sleep(random.randint(60, 600))
    while True:
        if time.time() - _presets["checked"] >= PRESETS_EVERY:
            try:
                presets_fetch()
            except Exception:
                traceback.print_exc()
        time.sleep(600)


def _preset_rule_field(rule):
    keys = set(rule) - {"action", "outbound"}
    return next(iter(keys)) if len(keys) == 1 and isinstance(rule.get(next(iter(keys))), list) else None


def preset_label(rule):
    """Название набора, если правило в точности совпадает с текущим или прежним списком набора."""
    f = _preset_rule_field(rule) if isinstance(rule, dict) else None
    if not f:
        return None
    cur = set(map(str, rule[f]))
    for pid, P in PRESETS.items():
        for pr in P["r"]:
            if f in pr and (cur == set(pr[f]) or any(cur == set(o) for o in PRESET_HISTORY.get(pid, {}).get(f, []))):
                return pid, P["t"], cur == set(pr[f])
    return None


def migrate_presets(auto=False):
    """Обновляет в конфиге правила, созданные из готовых наборов прежних версий панели (направление сохраняется)."""
    with LOCK:
        st = load_state()
        if auto and st.get("preset_rev", 0) >= PRESET_BUILTIN_REV:     # сами — только после обновления панели
            return {"ok": True, "message": "Наборы уже актуальны", "changed": 0}
        try:
            cfg = _cfg_read()
        except (OSError, ValueError):
            return {"ok": False, "error": "Конфиг не прочитан", "changed": 0}
        n = 0
        for r in (cfg.get("route") or {}).get("rules", []) or []:
            lab = preset_label(r)
            if lab and not lab[2]:
                f = _preset_rule_field(r)
                new = next(pr[f] for pr in PRESETS[lab[0]]["r"] if f in pr)
                r[f] = list(new)
                n += 1
        res = {"ok": True, "message": "Наборы уже актуальны", "changed": 0}
        if n:
            res = apply_config(json.dumps(cfg), "apply" if not (auto and not _active()) else "save")
            res["changed"] = n if res.get("ok") else 0
            if res.get("ok"):
                res["message"] = f"Обновлено правил из наборов: {n}. " + res.get("message", "")
        if res.get("ok"):
            st["preset_rev"] = PRESET_BUILTIN_REV
            save_state(st)
        return res


def _is_p2p(r):
    return isinstance(r, dict) and r.get("protocol") in (["bittorrent"], "bittorrent") and not (set(r) - {"protocol", "action", "outbound"})


@app.post("/api/p2p")
def p2p_toggle(body: dict, user: str = Depends(auth)):
    """Постоянное правило: BitTorrent → direct. Сразу записывается в конфиг и применяется."""
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"Не удалось прочитать конфиг: {e}"}
        route = cfg.setdefault("route", {})
        rules = route["rules"] = [r for r in route.get("rules", []) or [] if not _is_p2p(r)]
        if body.get("enable"):
            direct = next((o["tag"] for o in cfg.get("outbounds", []) if o.get("type") == "direct" and o.get("tag")), None)
            if not direct:
                direct = "direct"
                cfg.setdefault("outbounds", []).append({"type": "direct", "tag": direct})
            new = (parse_ver(sb_version()) or (1, 12, 0)) >= (1, 11, 0)
            if new:
                if not any(isinstance(r, dict) and r.get("action") == "sniff" for r in rules):
                    rules.insert(0, {"action": "sniff"})
            else:
                for ib in cfg.get("inbounds", []) or []:
                    if ib.get("type") in ("tun", "mixed"):
                        ib["sniff"] = True
            idx = 0
            while idx < len(rules) and isinstance(rules[idx], dict) and rules[idx].get("action") in ("sniff", "hijack-dns", "resolve"):
                idx += 1
            rules.insert(idx, {"protocol": ["bittorrent"], **({"action": "route"} if new else {}), "outbound": direct})
        return apply_config(json.dumps(cfg), "apply")


@app.get("/api/presets")
def presets_list(user: str = Depends(auth)):
    return {"ok": True, "presets": PRESETS, "history": PRESET_HISTORY, "rev": PRESET_REV, **_presets}


@app.post("/api/presets/fetch")
def presets_fetch_api(body: dict, user: str = Depends(auth)):
    return {**presets_fetch(), "rev": PRESET_REV, **{k: v for k, v in _presets.items() if k != "error"}}


@app.post("/api/presets/add")
def presets_add(body: dict, user: str = Depends(auth)):
    """Добавляет правила готовых наборов с направлением target ('direct' или тег outbound). Повтор меняет направление."""
    ids = [i for i in (body.get("ids") or []) if i in PRESETS]
    if not ids:
        return {"ok": False, "error": "Набор не выбран"}
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"Не удалось прочитать конфиг: {e}"}
        outs = cfg.get("outbounds", []) or []
        target = str(body.get("target") or "direct")
        if target == "direct":
            target = next((o["tag"] for o in outs if o.get("type") == "direct" and o.get("tag")), "")
            if not target:
                target = "direct"
                cfg.setdefault("outbounds", []).append({"type": "direct", "tag": "direct"})
        elif not any(o.get("tag") == target for o in outs):
            return {"ok": False, "error": "Такого outbound в конфиге нет"}
        new = (parse_ver(sb_version()) or (1, 12, 0)) >= (1, 11, 0)
        rules = cfg.setdefault("route", {}).setdefault("rules", [])
        fresh = []
        for pid in ids:
            for pr in PRESETS[pid]["r"]:
                f = next(iter(pr))
                ex = next((r for r in rules if isinstance(r, dict) and _preset_rule_field(r) == f and set(r[f]) == set(pr[f])), None)
                for k in ("action", "outbound"):
                    (ex or {}).pop(k, None)
                tgt = {**({"action": "route"} if new else {}), "outbound": target}
                if ex is not None:
                    ex.update(tgt)
                else:
                    fresh.append({f: list(pr[f]), **tgt})
        idx = 0
        while idx < len(rules) and isinstance(rules[idx], dict) and rules[idx].get("action") in ("sniff", "hijack-dns", "resolve"):
            idx += 1
        rules[idx:idx] = fresh
        return apply_config(json.dumps(cfg), "apply")


@app.get("/api/wizard")
def wizard_get(user: str = Depends(auth)):
    """Мастер быстрого старта: один раз и только если sing-box в системе нет."""
    return {"ok": True, "show": (not load_state().get("wizard_done")) and not service_binary()}


@app.post("/api/wizard")
def wizard_set(body: dict, user: str = Depends(auth)):
    with LOCK:
        st = load_state()
        st["wizard_done"] = True
        save_state(st)
    return {"ok": True}


@app.post("/api/presets/update")
def presets_update(body: dict, user: str = Depends(auth)):
    return migrate_presets()


# ------------------------------------------------------------------- страница
def code_changed():
    """Файл app.py на диске новее запущенного кода (пакет обновили, а служба не перезапустилась)."""
    try:
        return os.path.getmtime(APP_FILE) != APP_MTIME
    except OSError:
        return False


_restart_flag = {"done": False}


def restart_if_stale():
    if code_changed() and not _restart_flag["done"] and schedule_self_restart():
        _restart_flag["done"] = True
        return True
    return False


def watch_code():
    while True:
        time.sleep(15)
        restart_if_stale()


@app.get("/", response_class=HTMLResponse)
def index():
    if restart_if_stale():
        return HTMLResponse('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="4">'
                            '<body style="background:#0f1218;color:#e6e9ef;font:16px system-ui;padding:40px">'
                            'Панель обновилась и перезапускается… страница обновится сама.')
    with open(os.path.join(BASE_DIR, "index.html"), encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ------------------------------------------------- серверы (через Clash API)
GROUP_TYPES = {"selector", "urltest", "fallback", "loadbalance"}
CLASH_DEFAULT = "127.0.0.1:9095"
_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # без системных прокси


def _cfg_read():
    with open(CONFIG) as f:
        return json.load(f)


def _q(s):
    return urllib.parse.quote(str(s), safe="")


def clash_conf():
    """(base_url, secret) из конфига sing-box или None, если Clash API не включён."""
    try:
        ca = (_cfg_read().get("experimental") or {}).get("clash_api") or {}
    except (OSError, ValueError):
        return None
    addr = ca.get("external_controller")
    if not addr or ":" not in addr:
        return None
    host, _, port = addr.rpartition(":")
    if host in ("", "0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    return f"http://{host}:{port}", ca.get("secret", "")


def clash_call(method, path, body=None, timeout=10):
    conf = clash_conf()
    if not conf:
        raise RuntimeError("Clash API не включён в конфиге")
    base, secret = conf
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if secret:
        req.add_header("Authorization", "Bearer " + secret)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with _direct.open(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", "replace")
        try:
            msg = json.loads(msg).get("message", msg)
        except ValueError:
            pass
        raise RuntimeError(msg or f"HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Clash API недоступен: {e}. Служба запущена?")
    return json.loads(raw) if raw.strip() else {}


@app.get("/api/proxies")
def proxies(user: str = Depends(auth)):
    try:
        cfg = _cfg_read()
    except (OSError, ValueError):
        cfg = {}
    exp = cfg.get("experimental") or {}
    final = (cfg.get("route") or {}).get("final", "")
    persist = bool((exp.get("cache_file") or {}).get("enabled") or (exp.get("clash_api") or {}).get("store_selected"))
    if not clash_conf():
        return {"ok": True, "enabled": False, "groups": [], "final": final, "persist": persist}
    try:
        data = clash_call("GET", "/proxies").get("proxies", {})
    except RuntimeError as e:
        return {"ok": False, "enabled": True, "error": str(e), "final": final, "persist": persist}
    groups = []
    for name, p in data.items():
        if name == "GLOBAL" or str(p.get("type", "")).lower() not in GROUP_TYPES:
            continue
        nodes = []
        for n in p.get("all", []):
            q = data.get(n, {})
            hist = q.get("history") or []
            nodes.append({"name": n, "type": q.get("type", ""), "now": q.get("now", ""),
                          "delay": hist[-1].get("delay") if hist else None})
        groups.append({"name": name, "type": p.get("type", ""), "now": p.get("now", ""), "nodes": nodes})

    def chain(start):
        """start -> выбранный узел -> … до конечного outbound (так видно реальный выход трафика)."""
        res, seen, cur = [], set(), start
        while cur and cur not in seen:
            seen.add(cur)
            q = data.get(cur)
            res.append({"name": cur, "type": (q or {}).get("type", "")})
            if not q or str(q.get("type", "")).lower() not in GROUP_TYPES:
                break
            cur = q.get("now", "")
        return res

    targets = []                                   # куда ведут правила маршрутизации (кроме final)
    for r in (cfg.get("route") or {}).get("rules", []) or []:
        t = r.get("outbound") if isinstance(r, dict) else None
        if t and t != final and t not in targets:
            targets.append(t)
    flows = []
    if final:
        flows.append({"label": "Весь остальной трафик (route.final)", "chain": chain(final)})
    flows += [{"label": f"По правилам маршрутизации → {t}", "chain": chain(t)} for t in targets]
    used = {c["name"] for f in flows for c in f["chain"]}
    for f in flows:                                # все группы, в которые можно попасть выбором узла, тоже участвуют
        for c in f["chain"]:
            for n in (data.get(c["name"]) or {}).get("all", []):
                used.add(n)
    for g in groups:
        g["used"] = g["name"] in used
    groups.sort(key=lambda g: g["name"] != final)  # группа из route.final — первой
    return {"ok": True, "enabled": True, "groups": groups, "final": final, "persist": persist, "flows": flows}


@app.post("/api/proxies/select")
def proxy_select(body: dict, user: str = Depends(auth)):
    group, name = str(body.get("group", "")), str(body.get("name", ""))
    if not group or not name:
        raise HTTPException(400, "group и name обязательны")
    try:
        clash_call("PUT", f"/proxies/{_q(group)}", {"name": name})
        if body.get("drop"):
            clash_call("DELETE", "/connections")
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "message": f"{group} → {name}" + (" (соединения сброшены)" if body.get("drop") else "")}


@app.post("/api/proxies/delay")
def proxy_delay(body: dict, user: str = Depends(auth)):
    group, name = str(body.get("group", "")), str(body.get("name", ""))
    qs = urllib.parse.urlencode({"url": "https://www.gstatic.com/generate_204", "timeout": 5000})
    try:
        if name:
            r = clash_call("GET", f"/proxies/{_q(name)}/delay?{qs}", timeout=20)
            return {"ok": True, "delays": {name: r.get("delay", 0)}}
        if not group:
            raise HTTPException(400, "group или name обязательны")
        try:
            r = clash_call("GET", f"/group/{_q(group)}/delay?{qs}", timeout=30)
            return {"ok": True, "delays": r}
        except RuntimeError as e:
            if "недоступен" in str(e):
                raise
            # старый sing-box без /group/.../delay: меряем узлы по одному
            return {"ok": True, "delays": _delays_each(group, qs), "note": "по одному (fallback)"}
    except RuntimeError as e:
        # одиночный узел при таймауте/ошибке сети sing-box отдаёт ошибку: считаем «недоступен»
        if name:
            return {"ok": True, "delays": {name: 0}, "note": str(e)}
        return {"ok": False, "error": str(e)}


# ------------------------------------------------- резервный сервер (failover через панель)
FO_URL = "https://www.gstatic.com/generate_204"
_fo = {"fails": 0, "oks": 0, "last": 0.0, "primary_ok": None, "now": "", "error": "", "events": [], "warned": False}


def fo_event(msg):
    _fo["events"] = ([{"t": int(time.time()), "msg": msg}] + _fo["events"])[:15]
    print("failover: " + msg, file=sys.stderr, flush=True)


def fo_probe(name):
    qs = urllib.parse.urlencode({"url": FO_URL, "timeout": 5000})
    try:
        return int(clash_call("GET", f"/proxies/{_q(name)}/delay?{qs}", timeout=12).get("delay", 0)) > 0
    except (RuntimeError, ValueError, TypeError):
        return False


def fo_tick():
    c = load_state().get("failover") or {}
    if not c.get("enabled"):
        return
    group, pri, bak = c["group"], c["primary"], c["backup"]
    try:
        now = clash_call("GET", f"/proxies/{_q(group)}").get("now", "")
    except RuntimeError as e:
        _fo["error"] = str(e)
        return
    _fo["error"] = ""
    ok = fo_probe(pri)
    _fo["primary_ok"], _fo["now"], _fo["last"] = ok, now, time.time()
    if ok:
        _fo["fails"], _fo["oks"], _fo["warned"] = 0, _fo["oks"] + 1, False
    else:
        _fo["fails"], _fo["oks"] = _fo["fails"] + 1, 0
    try:
        if now == pri and not ok and _fo["fails"] >= int(c.get("fails", 3)):
            if fo_probe(bak):
                clash_call("PUT", f"/proxies/{_q(group)}", {"name": bak})
                clash_call("DELETE", "/connections")
                _fo["now"], _fo["warned"] = bak, False
                fo_event(f"основной «{pri}» не отвечает {_fo['fails']} проверок подряд — переключено на резерв «{bak}»")
            elif not _fo["warned"]:
                _fo["warned"] = True
                fo_event(f"основной «{pri}» не отвечает, но и резерв «{bak}» недоступен — остаюсь на основном")
        elif now == bak and ok and _fo["oks"] >= 2:
            clash_call("PUT", f"/proxies/{_q(group)}", {"name": pri})
            _fo["now"] = pri
            fo_event(f"основной «{pri}» снова работает — возврат с резерва")
    except RuntimeError as e:
        _fo["error"] = str(e)


def fo_loop():
    while True:
        try:
            iv = int((load_state().get("failover") or {}).get("interval", 30))
        except (TypeError, ValueError):
            iv = 30
        time.sleep(max(10, min(iv, 300)))
        try:
            fo_tick()
        except Exception:
            traceback.print_exc()


def _fo_view():
    c = load_state().get("failover") or {}
    mode = ""
    if c.get("enabled") and _fo["now"]:
        mode = "primary" if _fo["now"] == c.get("primary") else "backup" if _fo["now"] == c.get("backup") else "other"
    return {"ok": True, "cfg": c, "status": {**{k: _fo[k] for k in ("fails", "primary_ok", "now", "error", "last", "events")}, "mode": mode}}


@app.get("/api/failover")
def failover_get(user: str = Depends(auth)):
    return _fo_view()


@app.post("/api/failover")
def failover_set(body: dict, user: str = Depends(auth)):
    if body.get("action") == "disable":
        with LOCK:
            st = load_state()
            st["failover"] = {**(st.get("failover") or {}), "enabled": False}
            save_state(st)
        fo_event("резервирование выключено")
        return {"ok": True, "message": "Резервирование выключено", **_fo_view()}
    if body.get("action") != "enable":
        raise HTTPException(400, "Недопустимое действие")
    group, pri, bak = (str(body.get(k, "")) for k in ("group", "primary", "backup"))
    if not group or not pri or not bak or pri == bak:
        return {"ok": False, "error": "Выберите группу, основной и резервный серверы (разные)"}
    try:
        info = clash_call("GET", f"/proxies/{_q(group)}")
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    if str(info.get("type", "")).lower() != "selector":
        return {"ok": False, "error": "Группа должна быть типа selector"}
    if pri not in info.get("all", []) or bak not in info.get("all", []):
        return {"ok": False, "error": "Оба сервера должны входить в выбранную группу"}
    try:
        n = max(2, min(int(body.get("fails", 3)), 10))
        iv = max(10, min(int(body.get("interval", 30)), 300))
    except (TypeError, ValueError):
        return {"ok": False, "error": "Неверные числа"}
    try:
        clash_call("PUT", f"/proxies/{_q(group)}", {"name": pri})
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    with LOCK:
        st = load_state()
        st["failover"] = {"enabled": True, "group": group, "primary": pri, "backup": bak, "fails": n, "interval": iv}
        save_state(st)
    _fo.update(fails=0, oks=0, warned=False, primary_ok=None, now=pri)
    fo_event(f"резервирование включено: «{pri}» → резерв «{bak}» (проверка раз в {iv} с, переключение после {n} неудач)")
    return {"ok": True, "message": f"Резервирование включено: основной «{pri}», резерв «{bak}»", **_fo_view()}


@app.post("/api/clash/enable")
def clash_enable(user: str = Depends(auth)):
    """Включает Clash API (только 127.0.0.1) и cache_file, чтобы выбор узла переживал перезапуск."""
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"Не удалось прочитать конфиг: {e}"}
        exp = cfg.setdefault("experimental", {})
        ca = exp.setdefault("clash_api", {})
        changed = []
        if not ca.get("external_controller"):
            ca["external_controller"] = CLASH_DEFAULT
            changed.append("clash_api")
        if "secret" not in ca:
            ca["secret"] = secrets.token_hex(16)
        ver = parse_ver(sb_version())
        if ver and ver < (1, 8, 0):          # старый формат: сохранение выбора внутри clash_api
            if not ca.get("store_selected"):
                ca["store_selected"] = True
                ca.setdefault("cache_file", "cache.db")
                changed.append("cache_file")
        else:
            cf = exp.setdefault("cache_file", {})
            if not cf.get("enabled"):
                cf["enabled"] = True
                changed.append("cache_file")
        if not changed:
            return {"ok": True, "message": "Уже включено"}
        return apply_config(json.dumps(cfg), "apply")


@app.post("/api/proxies/convert")
def proxy_convert(body: dict, user: str = Depends(auth)):
    """urltest/fallback → selector, чтобы можно было выбирать узел вручную."""
    group = str(body.get("group", ""))
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": str(e)}
        o = next((x for x in cfg.get("outbounds", []) if x.get("tag") == group), None)
        if not o or o.get("type") not in ("urltest", "fallback"):
            return {"ok": False, "error": "Группа не найдена или уже selector"}
        o["type"] = "selector"
        for k in ("url", "interval", "tolerance", "idle_timeout"):
            o.pop(k, None)
        return apply_config(json.dumps(cfg), "apply")


@app.post("/api/proxies/final")
def proxy_final(body: dict, user: str = Depends(auth)):
    """Направляет весь остальной трафик (route.final) в выбранный outbound/группу."""
    tag = str(body.get("tag", ""))
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": str(e)}
        if not any(o.get("tag") == tag for o in cfg.get("outbounds", [])):
            return {"ok": False, "error": "Такого outbound в конфиге нет"}
        cfg.setdefault("route", {})["final"] = tag
        return apply_config(json.dumps(cfg), "apply")


def _delays_each(group, qs):
    members = clash_call("GET", f"/proxies/{_q(group)}").get("all", [])

    def one(n):
        try:
            return n, clash_call("GET", f"/proxies/{_q(n)}/delay?{qs}", timeout=20).get("delay", 0)
        except RuntimeError:
            return n, 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        return dict(ex.map(one, members))


# ------------------------------------------------ проверка узлов подписки версией sing-box
def validate_nodes(nodes):
    """Каждый узел проверяется отдельно командой `sing-box check`.
    Возвращает (подходящие, [{tag, reason}], проверка_выполнена)."""
    tmp = tempfile.mkdtemp(prefix="sbp-")

    def check(obj, name):
        p = os.path.join(tmp, name)
        with open(p, "w") as f:
            json.dump({"outbounds": [obj]}, f)
        return run([BINARY, "check", "-c", p], timeout=20)

    try:
        # пробный прогон: если даже пустой direct не проходит, проверять нечем (нет бинарника и т.п.)
        if check({"type": "direct", "tag": "probe"}, "probe.json")[0] != 0:
            return nodes, [], False

        def one(item):
            i, n = item
            if n.get("detour"):               # зависит от другого outbound, изолированно не проверить
                return n, None
            rc, out = check(n, f"n{i}.json")
            if rc == 0:
                return n, None
            line = next((l.strip() for l in out.splitlines() if l.strip()), "ошибка проверки")
            return n, re.sub(r"^(FATAL|ERROR|WARN)\S*\s*", "", line)[:200]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            res = list(ex.map(one, enumerate(nodes)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ok = [n for n, e in res if e is None]
    bad = [{"tag": n["tag"], "reason": e} for n, e in res if e is not None]
    return ok, bad, True


# ------------------------------------------------ устройство: CPU / память / температура
def read_cpu():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return sum(v), v[3] + v[4]               # всего, простой (idle + iowait)


def read_meminfo():
    d = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                d[k] = int(parts[0]) * 1024
    return d


def read_temp():
    best = None
    try:
        for z in os.listdir("/sys/class/thermal"):
            if z.startswith("thermal_zone"):
                with open(f"/sys/class/thermal/{z}/temp") as f:
                    t = int(f.read().strip()) / 1000
                best = t if best is None else max(best, t)
    except (OSError, ValueError):
        pass
    return best


def device_stats(show):
    out = {"cores": os.cpu_count() or 1, "load": None, "cpu_total": None, "cpu_idle": None,
           "svc_cpu_ns": None, "mem": None, "temp": read_temp()}
    try:
        out["load"] = list(os.getloadavg())
        out["cpu_total"], out["cpu_idle"] = read_cpu()
        m = read_meminfo()
        out["mem"] = {"total": m["MemTotal"], "avail": m.get("MemAvailable", m["MemFree"]),
                      "swap_total": m.get("SwapTotal", 0), "swap_free": m.get("SwapFree", 0)}
    except (OSError, ValueError, KeyError, IndexError):
        pass
    ns = show.get("CPUUsageNSec", "")
    if ns.isdigit() and int(ns) < 2 ** 63:
        out["svc_cpu_ns"] = int(ns)
    return out


# ------------------------------------------------ лимиты ресурсов (systemd drop-in)
LIMITS_NAME = "90-singbox-panel-limits.conf"
_SIZE = re.compile(r"^(\d+(?:\.\d+)?)([KMGT]?)$")
_UNITS = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}


def limits_path():
    return os.path.join(SYSTEMD_DIR, f"{SERVICE}.service.d", LIMITS_NAME)


def size_bytes(s):
    m = _SIZE.match(s or "")
    return int(float(m.group(1)) * _UNITS[m.group(2)]) if m else None


def _norm_size(v, name):
    v = str(v or "").strip().upper().replace(" ", "")
    if not v:
        return ""
    if v == "INFINITY":
        return "infinity"
    if re.fullmatch(r"\d{1,3}%", v) or _SIZE.match(v):
        return v
    raise ValueError(f"{name}: неверный формат «{v}» (примеры: 300M, 1G, 30%, infinity)")


def _span_pct(s):
    """'1.5s' -> 150 (процентов одного ядра)."""
    if not s or s == "infinity":
        return None
    mult = {"us": 1e-6, "ms": 1e-3, "s": 1, "min": 60, "h": 3600}
    tot = sum(float(n) * mult[u] for n, u in re.findall(r"(\d+(?:\.\d+)?)(us|ms|s|min|h)", s))
    return round(tot * 100) if tot else None


def read_limits_form():
    try:
        with open(limits_path()) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    form = {"memory_high": "", "memory_max": "", "gomemlimit_mib": None,
            "cpu_quota": "", "no_swap": False, "oom_score": None}
    for ln in lines:
        k, _, v = ln.strip().partition("=")
        if k == "MemoryHigh":
            form["memory_high"] = v
        elif k == "MemoryMax":
            form["memory_max"] = v
        elif k == "MemorySwapMax":
            form["no_swap"] = v == "0"
        elif k == "CPUQuota":
            form["cpu_quota"] = v
        elif k == "OOMScoreAdjust":
            try:
                form["oom_score"] = int(v)
            except ValueError:
                pass
        elif k == "Environment" and v.startswith("GOMEMLIMIT="):
            m = re.match(r"(\d+)MiB$", v.split("=", 1)[1])
            if m:
                form["gomemlimit_mib"] = int(m.group(1))
    return form


def show_limits():
    rc, out = run(["systemctl", "show", SERVICE, "-p",
                   "MemoryHigh,MemoryMax,MemorySwapMax,MemoryCurrent,CPUQuotaPerSecUSec,OOMScoreAdjust"])
    d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)

    def num(k):
        v = d.get(k, "")
        return int(v) if v.isdigit() and int(v) < 2 ** 62 else None

    return {"memory_high": num("MemoryHigh"), "memory_max": num("MemoryMax"), "swap_max": num("MemorySwapMax"),
            "memory_current": num("MemoryCurrent"), "cpu_quota": _span_pct(d.get("CPUQuotaPerSecUSec")),
            "oom": d.get("OOMScoreAdjust")}


@app.get("/api/limits")
def get_limits(user: str = Depends(auth)):
    try:
        mem_total = read_meminfo()["MemTotal"]
    except (OSError, KeyError, ValueError):
        mem_total = None
    return {"ok": True, "form": read_limits_form(), "exists": os.path.exists(limits_path()),
            "live": show_limits(), "mem_total": mem_total, "service": SERVICE, "file": limits_path()}


@app.post("/api/limits")
def set_limits(body: dict, user: str = Depends(auth)):
    path, lines = limits_path(), None
    try:
        if not body.get("reset"):
            high = _norm_size(body.get("memory_high"), "MemoryHigh")
            mx = _norm_size(body.get("memory_max"), "MemoryMax")
            cpu = str(body.get("cpu_quota") or "").strip()
            if cpu and not re.fullmatch(r"\d{1,5}%", cpu):
                raise ValueError("CPUQuota: формат «150%» (100% = одно ядро)")
            go = body.get("gomemlimit_mib")
            go = int(go) if go not in (None, "", 0) else None
            if go is not None and go < 16:
                raise ValueError("GOMEMLIMIT: минимум 16 МиБ")
            oom = body.get("oom_score")
            oom = int(oom) if oom not in (None, "") else None
            if oom is not None and not -1000 <= oom <= 1000:
                raise ValueError("OOMScoreAdjust: от -1000 до 1000")
            hb, mb = size_bytes(high), size_bytes(mx)
            if hb and mb and hb > mb:
                raise ValueError("MemoryHigh не может быть больше MemoryMax")
            if go and mb and go * 1024 ** 2 > mb:
                raise ValueError("GOMEMLIMIT больше MemoryMax: сборщик мусора не успеет сработать до убийства")
            lines = []
            if high:
                lines.append(f"MemoryHigh={high}")
            if mx:
                lines.append(f"MemoryMax={mx}")
            if body.get("no_swap"):
                lines.append("MemorySwapMax=0")
            if cpu:
                lines.append(f"CPUQuota={cpu}")
            if oom is not None:
                lines.append(f"OOMScoreAdjust={oom}")
            if go:
                lines.append(f"Environment=GOMEMLIMIT={go}MiB")
            lines = lines or None
    except (ValueError, TypeError) as e:
        return {"ok": False, "error": str(e)}

    with LOCK:
        try:
            if lines is None:
                try:
                    os.remove(path)
                    os.rmdir(os.path.dirname(path))   # уберётся, только если каталог пуст
                except (FileNotFoundError, OSError):
                    pass
                msg = "Лимиты сброшены"
            else:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    f.write("# Управляется singbox-panel, ручные правки будут перезаписаны\n[Service]\n"
                            + "\n".join(lines) + "\n")
                os.chmod(tmp, 0o644)
                os.replace(tmp, path)
                msg = "Лимиты записаны"
        except OSError as e:
            return {"ok": False, "error": f"Не удалось записать {path}: {e}"}
        rc, out = run(["systemctl", "daemon-reload"])
        if rc != 0:
            return {"ok": False, "error": "systemctl daemon-reload: " + out}
        if body.get("restart"):
            rc, out = run(["systemctl", "restart", SERVICE], timeout=60)
            if rc != 0:
                return {"ok": False, "error": "Не удалось перезапустить службу:\n" + out}
            return {"ok": True, "message": msg + ", служба перезапущена"}
        # проверяем, подхватилось ли на лету
        live, stale = show_limits(), False
        for key, val in (("memory_high", lines and next((l for l in lines if l.startswith("MemoryHigh=")), None)),
                         ("memory_max", lines and next((l for l in lines if l.startswith("MemoryMax=")), None))):
            want = size_bytes(val.split("=", 1)[1]) if val else None
            if val and want and live[key] != want:
                stale = True
        tail = " (память/CPU применились на лету; GOMEMLIMIT и OOMScoreAdjust вступят после перезапуска)"
        if stale:
            tail = " — но systemd пока не применил значения на лету: перезапустите службу"
        return {"ok": True, "message": msg + tail}


# ------------------------------------------------ совместимость конфига с версией sing-box
def _ge(v, t):
    return v is not None and v >= t


def _fv(t):
    return ".".join(map(str, t))


def _rules(cfg):
    out = []

    def walk(rules, where):
        for r in rules or []:
            if isinstance(r, dict):
                out.append((where, r))
                if r.get("type") == "logical":
                    walk(r.get("rules"), where)

    walk((cfg.get("route") or {}).get("rules"), "route")
    walk((cfg.get("dns") or {}).get("rules"), "dns")
    return out


TUN_OLD = ("inet4_address", "inet6_address", "inet4_route_address", "inet6_route_address",
           "inet4_route_exclude_address", "inet6_route_exclude_address")
INBOUND_OLD = ("sniff", "sniff_override_destination", "sniff_timeout", "domain_strategy",
               "udp_disable_domain_unmapping")


def compat_report(cfg, ver):
    """Сверяет используемые поля с версией sing-box (по списку устаревших возможностей из документации).
    Возвращает findings и диапазон версий, на котором конфиг рабочий."""
    findings, state = [], {"lo": (0, 0, 0), "hi": None}
    vs = _fv(ver) if ver else "?"

    def add(level, msg):
        if ver:
            findings.append({"level": level, "msg": msg})

    def legacy(used, what, repl, repl_since, removed):
        if not used:
            return
        if removed:
            state["hi"] = removed if state["hi"] is None else min(state["hi"], removed)
        if removed and _ge(ver, removed):
            add("error", f"{what} — удалено в sing-box {_fv(removed)} (у вас {vs}). Замена: {repl}.")
        elif _ge(ver, repl_since):
            add("warn", f"{what} — устарело, замена: {repl}" +
                (f". Старое удалят в {_fv(removed)}." if removed else "."))
        else:
            add("info", f"{what} — старый формат, для вашей версии {vs} он правильный "
                        f"(замена «{repl}» появилась в {_fv(repl_since)}).")

    def modern(used, what, since):
        if not used:
            return
        state["lo"] = max(state["lo"], since)
        if ver and not _ge(ver, since):
            add("error", f"{what} — нужен sing-box ≥ {_fv(since)}, у вас {vs}.")

    inbounds = [i for i in cfg.get("inbounds") or [] if isinstance(i, dict)]
    outbounds = [o for o in cfg.get("outbounds") or [] if isinstance(o, dict)]
    route, dns, exp = cfg.get("route") or {}, cfg.get("dns") or {}, cfg.get("experimental") or {}
    rules = _rules(cfg)
    tun = [i for i in inbounds if i.get("type") == "tun"]
    srv = [s for s in dns.get("servers") or [] if isinstance(s, dict)]
    ca = exp.get("clash_api") or {}
    cache = exp.get("cache_file") if isinstance(exp.get("cache_file"), dict) else {}
    rsets = [r for r in route.get("rule_set") or [] if isinstance(r, dict)]

    legacy(any(k in t for t in tun for k in TUN_OLD), "tun: inet4_address / inet6_address / inet*_route_address",
           "address / route_address / route_exclude_address", (1, 10, 0), (1, 12, 0))
    modern(any("address" in t for t in tun), "tun: поле address", (1, 10, 0))
    legacy(any("gso" in t for t in tun), "tun: gso", "удалите поле, оно больше не работает", (1, 11, 0), (1, 13, 0))
    legacy(any(k in i for i in inbounds for k in INBOUND_OLD), "inbound: sniff / domain_strategy",
           "rule actions (sniff, resolve)", (1, 11, 0), (1, 13, 0))
    legacy(any(o.get("type") in ("block", "dns") for o in outbounds), "outbound типа block/dns",
           "rule actions (reject, hijack-dns)", (1, 11, 0), (1, 13, 0))
    legacy(any(o.get("type") == "wireguard" for o in outbounds), "outbound wireguard", "endpoints",
           (1, 11, 0), (1, 13, 0))
    modern(bool(cfg.get("endpoints")), "endpoints", (1, 11, 0))
    legacy(any(o.get("type") == "direct" and ("override_address" in o or "override_port" in o) for o in outbounds),
           "direct: override_address / override_port", "rule action route-options", (1, 11, 0), (1, 13, 0))
    modern(any("action" in r for _, r in rules), "правила с action", (1, 11, 0))
    legacy(any(k in r for _, r in rules for k in ("geoip", "geosite")) or "geoip" in route or "geosite" in route,
           "geoip / geosite", "rule_set", (1, 8, 0), (1, 12, 0))
    modern(bool(rsets) or any("rule_set" in r for _, r in rules), "rule_set", (1, 8, 0))
    legacy(any("rule_set_ipcidr_match_source" in r for _, r in rules), "rule_set_ipcidr_match_source",
           "rule_set_ip_cidr_match_source", (1, 10, 0), (1, 11, 0))
    legacy(any("address" in s and "type" not in s for s in srv), "dns.servers в старом формате (address)",
           "серверы нового формата (type)", (1, 12, 0), (1, 14, 0))
    modern(any("type" in s for s in srv), "dns.servers нового формата (type)", (1, 12, 0))
    legacy(any("outbound" in r for w, r in rules if w == "dns"), "dns-правило с outbound", "domain_resolver",
           (1, 12, 0), None)
    modern(bool(route.get("default_domain_resolver")) or any("domain_resolver" in o for o in outbounds),
           "domain_resolver", (1, 12, 0))
    legacy(any(k in ca for k in ("cache_file", "cache_id", "store_mode", "store_selected", "store_fakeip")),
           "clash_api: cache_file / store_selected", "experimental.cache_file", (1, 8, 0), None)
    modern(bool(cache), "experimental.cache_file", (1, 8, 0))
    legacy(any("download_detour" in r for r in rsets), "rule_set: download_detour", "http_client",
           (1, 14, 0), (1, 16, 0))
    legacy(bool(dns.get("independent_cache")), "dns.independent_cache", "см. migration guide sing-box",
           (1, 14, 0), (1, 16, 0))
    legacy(bool(cache.get("store_rdrc")), "cache_file.store_rdrc", "см. migration guide sing-box",
           (1, 14, 0), (1, 16, 0))

    lo, hi = state["lo"], state["hi"]
    conflict = bool(hi and lo >= hi)
    if conflict:
        findings.append({"level": "error", "msg": f"Конфиг смешивает форматы: новые поля требуют ≥ {_fv(lo)}, "
                         f"а старые удалены с {_fv(hi)}. Версии sing-box, на которой он целиком рабочий, нет."})
    order = {"error": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order[f["level"]])
    return {"findings": findings, "conflict": conflict,
            "range": {"min": _fv(lo) if lo > (0, 0, 0) else None, "max_excl": _fv(hi) if hi else None}}


@app.get("/api/compat")
def compat(user: str = Depends(auth)):
    try:
        cfg = _cfg_read()
    except (OSError, ValueError) as e:
        return {"ok": False, "error": f"Конфиг не прочитан: {e}"}
    raw = sb_version()
    r = compat_report(cfg, parse_ver(raw))
    r.update(ok=True, version=raw)
    return r


# ------------------------------------------------ обновление sing-box
BIN_BACKUPS = os.path.join(DATA, "bin-backups")
UPD_DIR = os.path.join(DATA, "update")
UPDATE_LOCK = threading.Lock()
SETTLE = (2.5, 2.0)                           # паузы перед проверкой, что служба поднялась после замены
BIN_KEEP = 5
REL_URL = "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20"
DL_PREFIX = "https://github.com/SagerNet/sing-box/releases/download/"
ARCHES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7",
          "i686": "386", "i386": "386", "s390x": "s390x", "riscv64": "riscv64", "loongarch64": "loong64"}
_rel = {"t": 0.0, "data": []}


def service_binary():
    """Путь к бинарнику, который реально запускает служба (из ExecStart), иначе первый sing-box из PATH."""
    rc, out = run(["systemctl", "show", SERVICE, "-p", "ExecStart"])
    m = re.search(r"path=(\S+)", out)
    if m and os.path.isfile(m.group(1)):
        return m.group(1)
    return shutil.which(BINARY)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ход долгих операций (скачивание, установка) для полосы прогресса в интерфейсе
PROG = {"task": "", "stage": "", "pct": 0, "done": 0, "total": 0, "active": False, "t": 0.0}


def prog(task=None, stage=None, pct=None, done=None, total=None, active=True):
    if task is not None:                       # новая операция: прежние счётчики не показываем
        PROG.update(done=0, total=0, pct=0, n=PROG.get("n", 0) + 1)
    for k, v in (("task", task), ("stage", stage), ("pct", pct), ("done", done), ("total", total)):
        if v is not None:
            PROG[k] = v
    PROG["active"], PROG["t"] = active, time.time()


def _copy_progress(r, f, h, limit, span):
    """Читает ответ r в файл f; span=(начало, конец) — какую часть полосы занимает скачивание."""
    try:
        total = int(r.headers.get("Content-Length") or 0)
    except (TypeError, ValueError, AttributeError):
        total = 0
    size = 0
    prog(done=0, total=total)
    while True:
        chunk = r.read(1 << 16)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise ValueError("файл больше допустимого размера")
        h.update(chunk)
        f.write(chunk)
        PROG["done"] = size
        if total:
            PROG["pct"] = int(span[0] + (span[1] - span[0]) * min(size, total) / total)
        PROG["t"] = time.time()
    return size


def _download(url, dest, limit=300 * 1024 * 1024, span=(0, 80)):
    req = urllib.request.Request(url, headers={"User-Agent": "singbox-panel"})
    h = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
        size = _copy_progress(r, f, h, limit, span)
    return h.hexdigest(), size


def fetch_releases():
    arch = ARCHES.get(platform.machine().lower())
    if not arch:
        raise ValueError(f"архитектура {platform.machine()} не поддерживается обновлением из панели")
    req = urllib.request.Request(REL_URL, headers={"User-Agent": "singbox-panel",
                                                    "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
    suffix, out = f"-linux-{arch}.tar.gz", []
    for rel in data:
        if rel.get("draft"):
            continue
        asset = next((a for a in rel.get("assets", [])
                      if a.get("name", "").startswith("sing-box-") and a["name"].endswith(suffix)), None)
        if not asset:
            continue
        tag = rel.get("tag_name", "")
        out.append({"tag": tag, "prerelease": bool(rel.get("prerelease")), "published": (rel.get("published_at") or "")[:10],
                    "url": asset.get("browser_download_url", ""), "size": asset.get("size"),
                    "digest": asset.get("digest") or "", "notes": (rel.get("body") or "")[:8000]})
    return out


def get_releases(refresh=False):
    if refresh or not _rel["data"] or time.time() - _rel["t"] > 600:
        _rel["data"], _rel["t"] = fetch_releases(), time.time()
    return _rel["data"]


def stage_release(tag):
    """Скачивает релиз из списка GitHub, сверяет sha256 (если GitHub её отдаёт), достаёт бинарник."""
    rel = next((r for r in get_releases() if r["tag"] == tag), None)
    if not rel:
        raise ValueError("релиз не найден в списке — обновите список")
    if not rel["url"].startswith(DL_PREFIX):
        raise ValueError("недопустимый адрес загрузки")
    shutil.rmtree(UPD_DIR, ignore_errors=True)
    wd = os.path.join(UPD_DIR, re.sub(r"[^\w.\-]", "_", tag))
    os.makedirs(wd)
    pkg, staged = os.path.join(wd, "pkg.tar.gz"), os.path.join(wd, "sing-box")
    prog("prepare", "Скачивание " + tag, 0)
    sha, size = _download(rel["url"], pkg)
    prog(stage="Проверка контрольной суммы и распаковка", pct=82)
    want = rel["digest"].split(":", 1)[1].lower() if rel["digest"].startswith("sha256:") else ""
    if want and want != sha:
        shutil.rmtree(UPD_DIR, ignore_errors=True)
        raise ValueError("контрольная сумма архива не совпала с указанной GitHub — файл повреждён или подменён")
    with tarfile.open(pkg, "r:gz") as tf:
        for m in tf:
            if m.isfile() and os.path.basename(m.name) == "sing-box":
                with open(staged, "wb") as f:
                    shutil.copyfileobj(tf.extractfile(m), f)
                break
        else:
            raise ValueError("в архиве нет файла sing-box")
    os.remove(pkg)
    os.chmod(staged, 0o755)
    return wd, staged, {"size": size, "verified": bool(want)}


def _wait_active():
    prog(stage="Ждём, что служба sing-box поднялась", pct=max(PROG["pct"], 75))
    time.sleep(SETTLE[0])
    if not _active():
        return False
    prog(pct=88)
    time.sleep(SETTLE[1])
    return _active()


def install_binary(src, label):
    """Подменяет бинарник службы, перезапускает; если служба не поднялась — возвращает прежний."""
    target = service_binary()
    if not target:
        return {"ok": False, "error": "Не удалось определить путь к бинарнику sing-box"}
    target = os.path.realpath(target)
    old_line = (run([target, "version"])[1].splitlines() or ["?"])[0]
    old_v = parse_ver(old_line)
    os.makedirs(BIN_BACKUPS, exist_ok=True)
    bk = os.path.join(BIN_BACKUPS, f"sing-box-{_fv(old_v) if old_v else 'unknown'}-{datetime.now():%Y%m%d-%H%M%S}")
    tmp = target + ".panel-new"

    def put(path):
        shutil.copy2(path, tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, target)               # атомарно; запущенный процесс продолжает работать со старым inode

    try:
        shutil.copy2(target, bk)
        if os.path.isfile(CONFIG):            # конфиг на момент замены — пара к этой копии бинарника
            shutil.copy2(CONFIG, bk + ".config.json")
        prog(stage="Замена бинарника (прежний сохранён в резервной копии)", pct=40)
        put(src)
    except OSError as e:
        return {"ok": False, "error": f"Не удалось заменить {target}: {e}"}
    prog(stage="Перезапуск службы sing-box", pct=60)
    rc, out = run(["systemctl", "restart", SERVICE], timeout=60)
    if rc == 0 and _wait_active():
        keep = sorted((os.path.join(BIN_BACKUPS, n) for n in os.listdir(BIN_BACKUPS)
                       if not n.endswith(".config.json")), key=os.path.getmtime)
        for old in keep[:-BIN_KEEP]:
            for f in (old, old + ".config.json"):
                try:
                    os.remove(f)
                except OSError:
                    pass
        _version["v"] = ""
        new_line = (run([target, "version"])[1].splitlines() or ["?"])[0]
        nv = parse_ver(new_line)
        return {"ok": True, "backup": os.path.basename(bk),
                "message": f"sing-box {_fv(old_v) if old_v else '?'} → {_fv(nv) if nv else new_line}. Резервная копия: {os.path.basename(bk)}"}
    tail = run(["journalctl", "-u", SERVICE, "-n", "15", "--no-pager"])[1]
    put(bk)
    run(["systemctl", "restart", SERVICE], timeout=60)
    return {"ok": False, "error": f"Служба не запустилась с версией {label}, возвращён прежний бинарник.\n\n{tail}"}


FRESH_BIN = "/usr/local/bin/sing-box"
MIN_CONFIG = {"log": {"level": "info", "timestamp": True},
              "outbounds": [{"type": "direct", "tag": "direct"}],
              "route": {"final": "direct"}}


def unit_exists():
    return os.path.isfile(os.path.join(SYSTEMD_DIR, SERVICE + ".service")) or \
        run(["systemctl", "cat", SERVICE + ".service"])[0] == 0


def unit_text(binary):
    return f"""[Unit]
Description=sing-box service (installed by singbox-panel)
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
User=root
WorkingDirectory=/var/lib/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
ExecStart={binary} -D /var/lib/sing-box -c {CONFIG} run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"""


def _own_workdir(path):
    """Служба работает от root с урезанными capabilities (без CAP_DAC_OVERRIDE): каталог и cache.db,
    оставшиеся от прежней установки под другим пользователем (например, sing-box), дали бы «permission denied»."""
    try:
        os.chown(path, 0, 0)
        os.chmod(path, 0o755)
        for n in os.listdir(path):
            p = os.path.join(path, n)
            if not os.path.islink(p):
                os.chown(p, 0, 0)
    except (OSError, AttributeError):
        pass


def _old_name(path):
    return f"{path}.old-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


def _undo_moves(moved):
    for src, dst in reversed(moved):
        try:
            os.replace(dst, src)
        except OSError:
            pass


def install_fresh(staged, label, target, need_unit):
    """Первая установка: бинарник, (при необходимости) systemd-юнит, запуск. При неудаче всё созданное убирается."""
    global BINARY
    target = target or FRESH_BIN
    made = []
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.makedirs("/var/lib/sing-box", exist_ok=True)
        if need_unit:
            _own_workdir("/var/lib/sing-box")
        if not os.path.exists(target):
            made.append(target)
        prog(stage="Копирование бинарника в " + target, pct=40)
        tmp = target + ".panel-new"
        shutil.copy2(staged, tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, target)
        if need_unit:
            upath = os.path.join(SYSTEMD_DIR, SERVICE + ".service")
            os.makedirs(SYSTEMD_DIR, exist_ok=True)
            with open(upath, "w") as f:
                f.write(unit_text(target))
            made.append(upath)
            run(["systemctl", "daemon-reload"])
        prog(stage="Создание и запуск службы " + SERVICE, pct=60)
        rc, out = run(["systemctl", "enable", "--now", SERVICE], timeout=60)
    except OSError as e:
        rc, out = 1, str(e)
    if rc == 0 and _wait_active():
        BINARY = target
        _version["v"] = ""
        return {"ok": True, "message": f"{label} установлен ({target}), служба {SERVICE} включена и запущена"}
    tail = run(["journalctl", "-u", SERVICE, "-n", "15", "--no-pager"])[1]
    run(["systemctl", "disable", "--now", SERVICE])
    for f in made:
        try:
            os.remove(f)
        except OSError:
            pass
    if need_unit:
        run(["systemctl", "daemon-reload"])
    return {"ok": False, "error": f"Служба не запустилась, установка отменена (бинарник и юнит убраны).\n\n{out}\n{tail}"}


def ensure_config(staged):
    """Если конфига нет — создаёт минимальный (проверенный устанавливаемой версией). Возвращает True, если создал."""
    if os.path.isfile(CONFIG):
        return False
    cdir = os.path.dirname(os.path.abspath(CONFIG))
    os.makedirs(cdir, exist_ok=True)
    mc = json.loads(json.dumps(MIN_CONFIG))
    mc["experimental"] = {"clash_api": {"external_controller": CLASH_DEFAULT, "secret": secrets.token_hex(16)},
                          "cache_file": {"enabled": True}}      # выбор сервера из панели и его сохранение после перезапуска
    text = json.dumps(mc, indent=2) + "\n"
    tmp = os.path.join(cdir, ".panel-min.json")
    with open(tmp, "w") as f:
        f.write(text)
    try:
        rc, out = run([staged, "check", "-c", tmp], cwd=cdir)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    if rc != 0:
        raise ValueError("Минимальный конфиг не прошёл проверку:\n" + out[-800:])
    _write_bytes(CONFIG, text.encode())
    return True


@app.get("/api/update/info")
def update_info(refresh: int = 0, user: str = Depends(auth)):
    raw = sb_version()
    cur, err, rels = parse_ver(raw), "", []
    try:
        for r in get_releases(bool(refresh)):
            v = parse_ver(r["tag"])
            rels.append({"tag": r["tag"], "prerelease": r["prerelease"], "published": r["published"], "notes": r.get("notes", ""),
                         "size": r["size"], "verified": r["digest"].startswith("sha256:"),
                         "newer": bool(cur and v and v > cur), "current": bool(cur and v == cur)})
    except (OSError, ValueError) as e:        # URLError — подкласс OSError
        err = f"Список релизов не получен (GitHub недоступен с сервера?): {e}"
    target = service_binary()
    pkg = bool(target and shutil.which("dpkg") and run(["dpkg", "-S", os.path.realpath(target)])[0] == 0)
    backups = []
    if os.path.isdir(BIN_BACKUPS):
        names = [n for n in os.listdir(BIN_BACKUPS) if not n.endswith(".config.json")]
        for n in sorted(names, key=lambda n: os.path.getmtime(os.path.join(BIN_BACKUPS, n)), reverse=True):
            p = os.path.join(BIN_BACKUPS, n)
            backups.append({"name": n, "size": os.path.getsize(p), "has_config": os.path.isfile(p + ".config.json"),
                            "time": datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")})
    return {"ok": True, "version": raw, "binary": target, "arch": platform.machine(), "dpkg": pkg,
            "fresh": not target, "no_config": not os.path.isfile(CONFIG), "no_unit": not unit_exists(),
            "releases": rels, "error": err, "backups": backups}


@app.get("/api/progress")
def progress_get(user: str = Depends(auth)):
    return {"ok": True, **PROG}


@app.post("/api/update/prepare")
def update_prepare(body: dict, user: str = Depends(auth)):
    tag = str(body.get("tag", ""))
    if not UPDATE_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "Другое обновление уже выполняется"}
    try:
        try:
            wd, staged, info = stage_release(tag)
        except (OSError, ValueError, tarfile.TarError) as e:
            return {"ok": False, "error": f"Не удалось подготовить {tag}: {e}"}
        prog(stage="Пробный запуск скачанного бинарника", pct=88)
        rc, out = run([staged, "version"], timeout=20)
        if rc != 0:
            return {"ok": False, "error": "Скачанный бинарник не запускается на этой системе:\n" + out}
        prog(stage="Проверка конфига новой версией", pct=94)
        cdir = os.path.dirname(os.path.abspath(CONFIG))
        no_config = not os.path.isfile(CONFIG)
        fresh = not service_binary()
        replace = fresh and not no_config        # первая установка, а конфиг остался от прежнего sing-box: заменим
        crc, cout = (0, "") if (no_config or replace) else run([staged, "check", "-c", CONFIG], cwd=cdir)
        try:
            comp = [f for f in compat_report(_cfg_read(), parse_ver(tag))["findings"] if f["level"] in ("error", "warn")]
        except (OSError, ValueError):
            comp = []
        meta = {"tag": tag, "sha256": _sha256_file(staged), "version": out.splitlines()[0]}
        with open(os.path.join(wd, "meta.json"), "w") as f:
            json.dump(meta, f)
        prog(stage="Готово к установке", pct=100, active=False)
        return {"ok": True, "tag": tag, "version": meta["version"], "size": info["size"], "verified": info["verified"],
                "check_ok": crc == 0, "check_output": cout[-1500:] if crc != 0 else "", "compat": comp,
                "no_config": no_config, "fresh": fresh, "no_unit": not unit_exists(), "replace_config": replace,
                "old_name": os.path.basename(_old_name(CONFIG)) if replace else ""}
    finally:
        PROG["active"] = False
        UPDATE_LOCK.release()


@app.post("/api/update/install")
def update_install(body: dict, user: str = Depends(auth)):
    tag = str(body.get("tag", ""))
    if not UPDATE_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "Другое обновление уже выполняется"}
    try:
        wd = os.path.join(UPD_DIR, re.sub(r"[^\w.\-]", "_", tag))
        staged = os.path.join(wd, "sing-box")
        try:
            with open(os.path.join(wd, "meta.json")) as f:
                meta = json.load(f)
        except (OSError, ValueError):
            return {"ok": False, "error": "Сначала нажмите «Скачать и проверить» для этой версии"}
        if meta.get("tag") != tag or not os.path.isfile(staged) or _sha256_file(staged) != meta.get("sha256"):
            return {"ok": False, "error": "Подготовленный файл изменился или пропал — подготовьте версию заново"}
        fresh = not service_binary()
        prog("install", "Проверка подготовленного файла и конфига", 10)
        if os.path.isfile(CONFIG) and not fresh:
            crc, cout = run([staged, "check", "-c", CONFIG], cwd=os.path.dirname(os.path.abspath(CONFIG)))
            if crc != 0:                      # конфиг мог измениться после подготовки
                return {"ok": False, "error": "Новая версия не принимает текущий конфиг:\n" + cout[-1500:]}
        with LOCK:
            target, need_unit = service_binary(), not unit_exists()
            moved = []                        # (старое имя, новое имя): вернуть при неудаче
            notes = []
            if fresh:
                # первая установка: остатки прежнего sing-box (конфиг, юнит без бинарника) переименовываем, а не используем
                if os.path.isfile(CONFIG):
                    dst = _old_name(CONFIG)
                    os.replace(CONFIG, dst)
                    moved.append((CONFIG, dst))
                    notes.append(f"Найден конфиг от прежней установки sing-box — переименован в {dst} и создан новый: "
                                 "старые порты, пути и поля могли помешать запуску новой версии. Нужные настройки можно перенести "
                                 "вручную на вкладке «Настройки → Конфиг»")
                upath = os.path.join(SYSTEMD_DIR, SERVICE + ".service")
                if os.path.isfile(upath):
                    try:
                        with open(upath) as f:
                            ours = "installed by singbox-panel" in f.read()
                    except OSError:
                        ours = False
                    if not ours:
                        dst = _old_name(upath)
                        os.replace(upath, dst)
                        moved.append((upath, dst))
                        notes.append(f"Найдена служба {SERVICE}.service от прежней установки (её бинарника нет) — переименована в {dst}, создана новая")
                need_unit = True
            created = False
            prog(stage="Подготовка конфига", pct=25)
            try:
                created = ensure_config(staged)
            except (OSError, ValueError) as e:
                _undo_moves(moved)
                return {"ok": False, "error": f"Не удалось создать конфиг: {e}"}
            if target and not need_unit:
                res = install_binary(staged, meta["version"])
            else:
                res = install_fresh(staged, meta["version"], target, need_unit)
                if not res["ok"] and created:
                    try:
                        os.remove(CONFIG)
                    except OSError:
                        pass
                if not res["ok"]:
                    _undo_moves(moved)
                    run(["systemctl", "daemon-reload"])
            if res["ok"] and created:
                res["message"] += f". Создан минимальный конфиг {CONFIG} (выход direct, Clash API для выбора серверов) — добавьте подписку на вкладке «Подписка»"
            if res["ok"] and notes:
                res["message"] += ".\n\n" + "\n".join("ℹ " + n for n in notes)
        if res["ok"]:
            shutil.rmtree(UPD_DIR, ignore_errors=True)
        return res
    finally:
        PROG["active"] = False
        UPDATE_LOCK.release()


@app.post("/api/update/rollback")
def update_rollback(body: dict, user: str = Depends(auth)):
    name = os.path.basename(str(body.get("name", "")))
    path = os.path.join(BIN_BACKUPS, name)
    snap = path + ".config.json"
    if not name or name.endswith(".config.json") or not os.path.isfile(path):
        return {"ok": False, "error": "Резервная копия не найдена"}
    with_cfg = bool(body.get("restore_config")) and os.path.isfile(snap)
    # старая версия должна принять тот конфиг, с которым ей предстоит работать
    rc, out = run([path, "check", "-c", snap if with_cfg else CONFIG], cwd=os.path.dirname(os.path.abspath(CONFIG)))
    if rc != 0:
        hint = "" if with_cfg or not os.path.isfile(snap) else \
            "\n\nМожно откатиться вместе с конфигом, который был при установке (кнопка «с конфигом»)."
        return {"ok": False, "error": f"Эта версия не принимает {'сохранённый' if with_cfg else 'текущий'} конфиг:\n"
                                      f"{out[-1200:]}{hint}"}
    if not UPDATE_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "Другое обновление уже выполняется"}
    try:
        with LOCK:
            old_cfg = None
            if with_cfg:
                with open(CONFIG, "rb") as f:
                    old_cfg = f.read()
                os.makedirs(BACKUPS, exist_ok=True)       # текущий конфиг сохраняется, откат отката возможен
                shutil.copy2(CONFIG, os.path.join(BACKUPS, datetime.now().strftime("config-%Y%m%d-%H%M%S-before-rollback.json")))
                _write_bytes(CONFIG, open(snap, "rb").read())
            res = install_binary(path, name)
            if with_cfg and res["ok"]:
                res["message"] += ". Конфиг возвращён к состоянию на момент установки."
            elif with_cfg:
                _write_bytes(CONFIG, old_cfg)
                run(["systemctl", "restart", SERVICE], timeout=60)
                res["error"] += "\n\nКонфиг возвращён к состоянию до отката."
            return res
    finally:
        PROG["active"] = False
        UPDATE_LOCK.release()


def _write_bytes(path, data):
    mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o600
    tmp = path + ".panel-new"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ------------------------------------------------ проверка окружения: бинарник / служба / конфиг
CONFIG_CANDIDATES = ["/etc/sing-box/config.json", "/etc/singbox/config.json",
                     "/usr/local/etc/sing-box/config.json", "/opt/sing-box/config.json"]


def _exec_argv():
    """Аргументы запуска из ExecStart юнита: ['/usr/bin/sing-box', '-D', '/var/lib/sing-box', '-C', '/etc/sing-box', 'run']."""
    out = run(["systemctl", "show", SERVICE, "-p", "ExecStart"])[1]
    m = re.search(r"argv\[\]=(.*?)\s;\s", out)
    try:
        return shlex.split(m.group(1)) if m else []
    except ValueError:
        return []


def _argv_config(argv):
    """(файлы -c, каталоги -C) из аргументов службы; относительные пути считаются от -D."""
    files, dirs, workdir = [], [], ""
    for i, a_ in enumerate(argv):
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if a_ in ("-D", "--directory"):
            workdir = nxt
        elif a_ in ("-c", "--config") and nxt:
            files.append(nxt)
        elif a_ in ("-C", "--config-directory") and nxt:
            dirs.append(nxt)
        elif a_.startswith("--config="):
            files.append(a_.split("=", 1)[1])
        elif a_.startswith("--config-directory="):
            dirs.append(a_.split("=", 1)[1])
    fix = lambda p: p if os.path.isabs(p) or not workdir else os.path.join(workdir, p)
    return [fix(p) for p in files], [fix(p) for p in dirs]


def health_report():
    checks = []

    def add(id_, level, title, detail="", fix=""):
        checks.append({"id": id_, "level": level, "title": title, "detail": detail, "fix": fix})

    # --- systemd и служба
    rc, out = run(["systemctl", "show", SERVICE, "-p", "LoadState,UnitFileState,FragmentPath,ActiveState"])
    d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    loaded = False
    if rc != 0 or "LoadState" not in d:
        add("systemd", "error", "systemd недоступен", out[:300], "Панель управляет службой через systemctl")
    elif d["LoadState"] == "not-found":
        lst = run(["systemctl", "list-unit-files", "--no-legend", "sing*box*.service"])[1]
        names = [l.split()[0] for l in lst.splitlines() if l.split() and l.split()[0].endswith(".service")]
        add("unit", "error", f"Служба {SERVICE}.service не найдена в systemd",
            ("Найдены похожие юниты: " + ", ".join(names)) if names else "Юнит sing-box в системе не установлен.",
            "Если служба называется иначе, задайте SBP_SERVICE в /etc/default/singbox-panel и перезапустите панель"
            if names else "Установите sing-box (в пакете есть юнит) или создайте свой юнит")
    elif d["LoadState"] == "masked":
        add("unit", "error", f"Служба {SERVICE}.service замаскирована (masked)", d.get("FragmentPath", ""),
            f"systemctl unmask {SERVICE}")
    else:
        loaded = True
        ufs = d.get("UnitFileState", "")
        if ufs == "disabled":
            add("unit", "warn", f"Служба {SERVICE}.service найдена, но не включена в автозапуск",
                d.get("FragmentPath", ""), f"systemctl enable {SERVICE}")
        else:
            add("unit", "ok", f"Служба {SERVICE}.service найдена в systemd",
                f"{d.get('FragmentPath', '')} · автозапуск: {ufs or '—'}")

    # --- бинарник
    path = service_binary()
    if not path:
        add("binary", "error", "Бинарник sing-box не найден",
            "Нет ни в ExecStart службы, ни в PATH", "Установите sing-box или задайте SBP_BINARY в /etc/default/singbox-panel")
    else:
        rc, out = run([path, "version"], timeout=10)
        if rc != 0:
            add("binary", "error", "Бинарник найден, но не запускается", f"{path}: {out[:200]}")
        else:
            add("binary", "ok", f"Бинарник: {path}", out.splitlines()[0] if out else "")
        mine = shutil.which(BINARY)
        if mine and os.path.realpath(mine) != os.path.realpath(path):
            add("binary-mismatch", "warn", "Панель и служба используют разные бинарники",
                f"панель: {mine}; служба: {path}", "Уберите SBP_BINARY из /etc/default/singbox-panel")

    # --- конфиг
    argv = _exec_argv() if loaded else []
    files, dirs = _argv_config(argv)
    if not os.path.exists(CONFIG):
        others = [p for p in dict.fromkeys(CONFIG_CANDIDATES + files) if os.path.isfile(p) and p != CONFIG]
        add("config", "error", f"Конфиг {CONFIG} не найден",
            ("Найдены другие файлы: " + ", ".join(others)) if others else "Файла нет, в типичных местах /etc/… тоже.",
            "Укажите верный путь в SBP_CONFIG (/etc/default/singbox-panel) и перезапустите панель" if others
            else "Создайте конфиг sing-box или укажите путь в SBP_CONFIG")
    elif os.path.isdir(CONFIG):
        add("config", "error", f"{CONFIG} — каталог, а не файл", "", "Укажите в SBP_CONFIG путь к JSON-файлу")
    elif not os.access(CONFIG, os.R_OK):
        add("config", "error", f"Конфиг {CONFIG} нельзя прочитать", "Недостаточно прав", "Панель должна работать от root")
    else:
        try:
            cfg = _cfg_read()
            if not isinstance(cfg, dict):
                raise ValueError("корень должен быть объектом {…}")
        except ValueError as e:
            add("config", "error", f"Конфиг {CONFIG} не разобран как JSON", str(e)[:200],
                "Панель не поддерживает комментарии в JSON. Исправьте файл вручную или восстановите бэкап")
        else:
            ni, no = len(cfg.get("inbounds") or []), len(cfg.get("outbounds") or [])
            add("config", "warn" if not (ni or no) else "ok", f"Конфиг: {CONFIG}",
                f"inbounds: {ni}, outbounds: {no}" + ("; конфиг пустой" if not (ni or no) else ""))

    # --- тот ли файл читает служба
    if argv:
        if files:
            if os.path.realpath(files[0]) != os.path.realpath(CONFIG):
                add("config-match", "warn", "Служба читает не тот файл, что правит панель",
                    f"служба: -c {files[0]}; панель: {CONFIG}", "Задайте SBP_CONFIG=" + files[0])
            else:
                add("config-match", "ok", "Служба читает тот же файл, что и панель")
        elif dirs:
            inside = os.path.realpath(os.path.dirname(os.path.abspath(CONFIG))) == os.path.realpath(dirs[0])
            add("config-match", "warn" if not inside else "info",
                f"Служба запускается с каталогом конфигов (-C {dirs[0]})",
                "Панель редактирует один файл и не видит остальные файлы каталога" +
                ("" if inside else f"; ваш {CONFIG} вообще не в этом каталоге"),
                "" if inside else f"Задайте SBP_CONFIG на файл внутри {dirs[0]}")
    order = {"error": 0, "warn": 1, "info": 2, "ok": 3}
    checks.sort(key=lambda c: order[c["level"]])
    return checks


@app.get("/api/health")
def health(user: str = Depends(auth)):
    checks = health_report()
    return {"ok": True, "checks": checks, "errors": sum(c["level"] == "error" for c in checks),
            "warns": sum(c["level"] == "warn" for c in checks)}


# ================================================ шлюз / прокси-сервер / доступ
# Всё здесь выполняется только по кнопке и полностью обратимо.
PROC_SYS = os.environ.get("SBP_PROC_SYS", "/proc/sys")
GW_DIR = os.path.join(DATA, "gateway")
GW_UNIT = "singbox-panel-gateway"
PANEL_UNIT = os.environ.get("SBP_PANEL_UNIT", "singbox-panel")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")


def _read_sys(rel):
    try:
        with open(os.path.join(PROC_SYS, rel)) as f:
            return f.read().strip()
    except OSError:
        return None


def _write_sys(rel, val):
    try:
        with open(os.path.join(PROC_SYS, rel), "w") as f:
            f.write(str(val))
        return True
    except OSError:
        return False


def net_ifaces():
    rc, out = run(["ip", "-j", "-4", "addr", "show"])
    try:
        data = json.loads(out) if rc == 0 else []
    except ValueError:
        data = []
    res = []
    for d in data:
        name = d.get("ifname", "")
        if not name or name == "lo":
            continue
        addrs = [f"{a['local']}/{a['prefixlen']}" for a in d.get("addr_info", [])
                 if a.get("family") == "inet" and "local" in a]
        res.append({"name": name, "addrs": addrs, "state": d.get("operstate", "")})
    return res


def _is_tunlike(name, tun):
    return name == tun or name.startswith(("tun", "sing", "utun", "docker", "br-", "veth", "wg"))


def default_route_if(tun):
    rc, out = run(["ip", "-j", "-4", "route", "show", "default"])
    try:
        routes = json.loads(out) if rc == 0 else []
    except ValueError:
        routes = []
    routes = [r for r in routes if r.get("dev") and not _is_tunlike(r["dev"], tun)]
    routes.sort(key=lambda r: r.get("metric", 0))
    return routes[0]["dev"] if routes else ""


def iface_network(ifaces, name):
    import ipaddress
    for i in ifaces:
        if i["name"] == name and i["addrs"]:
            return str(ipaddress.ip_interface(i["addrs"][0]).network)
    return ""


def gateway_status():
    st = load_state().get("gateway") or {}
    ifaces = net_ifaces()
    tun = tun_name([i["name"] for i in ifaces])
    wan = default_route_if(tun)
    ipt = shutil.which("iptables")
    rc, out = run(["systemctl", "is-active", GW_UNIT])
    rules = bool(ipt) and run([ipt, "-w", "-t", "nat", "-S", "SBP-GW"])[0] == 0
    return {"ok": True, "enabled": bool(st.get("enabled")), "params": st.get("params") or {},
            "unit_active": out.strip() == "active", "rules_present": rules,
            "ip_forward": _read_sys("net/ipv4/ip_forward") == "1",
            "iptables": bool(ipt), "tun": tun,
            "ifaces": [i for i in ifaces if not _is_tunlike(i["name"], tun)],
            "detected": {"wan": wan, "lan": wan,
                         "subnet": iface_network(ifaces, wan)}}


def _gw_sysctl_paths(lan):
    paths = ["net/ipv4/ip_forward"]
    for k in ("all", "default", lan):
        paths += [f"net/ipv4/conf/{k}/send_redirects", f"net/ipv4/conf/{k}/rp_filter"]
    return paths


def gw_scripts(p, prev):
    ipt = shutil.which("iptables") or "iptables"
    hdr = f'#!/bin/sh\n# Создано singbox-panel (режим шлюза). Не редактируйте вручную.\nIPT="{ipt} -w"\n'
    clean = """\
for spec in "nat POSTROUTING SBP-GW" "filter FORWARD SBP-GW-FWD" "mangle FORWARD SBP-GW-MSS"; do
  set -- $spec
  while $IPT -t $1 -D $2 -j $3 2>/dev/null; do :; done
  $IPT -t $1 -F $3 2>/dev/null
  $IPT -t $1 -X $3 2>/dev/null
done
"""
    restore = "".join(f"echo {shlex.quote(str(v))} > /proc/sys/{k} 2>/dev/null\n" for k, v in prev.items()
                      if v is not None).replace("/proc/sys", PROC_SYS)
    setv = f"echo 1 > {PROC_SYS}/net/ipv4/ip_forward || true\n"
    for k in ("all", "default", p["lan_if"]):
        setv += (f"echo 0 > {PROC_SYS}/net/ipv4/conf/{k}/send_redirects 2>/dev/null || true\n"
                 f"echo 2 > {PROC_SYS}/net/ipv4/conf/{k}/rp_filter 2>/dev/null || true\n")
    sub, wan = shlex.quote(p["subnet"]), shlex.quote(p["wan_if"])
    rules = f"""\
$IPT -t nat -N SBP-GW
$IPT -t nat -A SBP-GW -s {sub} -o {wan} -j MASQUERADE
$IPT -t nat -I POSTROUTING 1 -j SBP-GW
$IPT -N SBP-GW-FWD
$IPT -A SBP-GW-FWD -s {sub} -j ACCEPT
$IPT -A SBP-GW-FWD -d {sub} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$IPT -I FORWARD 1 -j SBP-GW-FWD
$IPT -t mangle -N SBP-GW-MSS
$IPT -t mangle -A SBP-GW-MSS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
$IPT -t mangle -I FORWARD 1 -j SBP-GW-MSS
"""
    up = hdr + clean + "set -e\n" + setv + rules
    down = hdr + clean + restore + "exit 0\n"
    return up, down


def gw_unit_text():
    return f"""[Unit]
Description=singbox-panel: правила шлюза (NAT/forward)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh {GW_DIR}/up.sh
ExecStop=/bin/sh {GW_DIR}/down.sh

[Install]
WantedBy=multi-user.target
"""


def gateway_enable(body):
    with LOCK:
        if not shutil.which("iptables"):
            rc, out = run(["apt-get", "install", "-y", "-qq", "iptables"], timeout=300)
            if rc != 0 or not shutil.which("iptables"):
                return {"ok": False, "error": "Не удалось установить iptables:\n" + out[-400:]}
        info = gateway_status()
        names = {i["name"] for i in info["ifaces"]}
        lan = str(body.get("lan_if") or info["detected"]["lan"]).strip()
        wan = str(body.get("wan_if") or info["detected"]["wan"] or lan).strip()
        if not IFACE_RE.match(lan) or lan not in names:
            return {"ok": False, "error": f"Интерфейс локальной сети «{lan}» не найден"}
        if not IFACE_RE.match(wan) or wan not in names:
            return {"ok": False, "error": f"Выходной интерфейс «{wan}» не найден"}
        import ipaddress
        sub = str(body.get("subnet") or iface_network(net_ifaces(), lan)).strip()
        try:
            sub = str(ipaddress.ip_network(sub, strict=False))
        except ValueError:
            return {"ok": False, "error": f"Неверная подсеть «{sub}»"}
        p = {"lan_if": lan, "wan_if": wan, "subnet": sub}
        st = load_state()
        gw = st.get("gateway") or {}
        prev = gw.get("prev")
        if not gw.get("enabled") or not prev:       # исходные значения запоминаем один раз
            prev = {k: _read_sys(k) for k in _gw_sysctl_paths(lan)}
        up, down = gw_scripts(p, prev)
        os.makedirs(GW_DIR, exist_ok=True)
        for name, text in (("up.sh", up), ("down.sh", down)):
            with open(os.path.join(GW_DIR, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(GW_DIR, name), 0o755)
        with open(os.path.join(SYSTEMD_DIR, GW_UNIT + ".service"), "w") as f:
            f.write(gw_unit_text())
        run(["systemctl", "daemon-reload"])
        rc, out = run(["systemctl", "enable", GW_UNIT])
        rc2, out2 = run(["systemctl", "restart", GW_UNIT], timeout=60)
        if rc2 != 0:
            run(["sh", os.path.join(GW_DIR, "down.sh")])
            return {"ok": False, "error": "Не удалось применить правила:\n" + (out2 or out)[-500:]}
        st["gateway"] = {"enabled": True, "params": p, "prev": prev, "since": int(time.time())}
        save_state(st)
        return {"ok": True, "message": f"Режим шлюза включён: {sub} → NAT через {wan}", **gateway_status()}


def gateway_disable():
    with LOCK:
        run(["systemctl", "disable", "--now", GW_UNIT], timeout=60)
        down = os.path.join(GW_DIR, "down.sh")
        if os.path.exists(down):
            run(["sh", down])                       # на случай, если ExecStop не отработал
        for f in (os.path.join(SYSTEMD_DIR, GW_UNIT + ".service"), os.path.join(GW_DIR, "up.sh"), down):
            try:
                os.remove(f)
            except OSError:
                pass
        run(["systemctl", "daemon-reload"])
        st = load_state()
        st.pop("gateway", None)
        save_state(st)
        return {"ok": True, "message": "Режим шлюза выключен, настройки ядра возвращены как были", **gateway_status()}


@app.get("/api/gateway")
def get_gateway(user: str = Depends(auth)):
    return gateway_status()


@app.post("/api/gateway")
def set_gateway(body: dict, user: str = Depends(auth)):
    act = body.get("action")
    if act == "enable":
        return gateway_enable(body)
    if act == "disable":
        return gateway_disable()
    raise HTTPException(400, "Недопустимое действие")


RESET_WORD = "УДАЛИТЬ"


def _rm(path, log):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        log.append("удалено: " + path)
    except FileNotFoundError:
        pass
    except OSError as e:
        log.append(f"не удалось удалить {path}: {e}")


@app.post("/api/reset")
def reset_all(body: dict, user: str = Depends(auth)):
    """Возврат к состоянию «до панели»: шлюз, служба и конфиг sing-box, подписки, бэкапы, настройки панели.
    Бинарник и юнит удаляются, только если их поставила панель. Сама панель остаётся работать."""
    if str(body.get("confirm", "")).strip().upper() not in (RESET_WORD, "DELETE"):     # DELETE — в английском интерфейсе
        return {"ok": False, "error": f"Для подтверждения введите слово {RESET_WORD}"}
    log = []
    with LOCK:
        gateway_disable()
        log.append("режим шлюза выключен")
        run(["systemctl", "disable", "--now", SERVICE + ".service"], timeout=60)
        log.append("служба sing-box остановлена и отключена")
        upath = os.path.join(SYSTEMD_DIR, SERVICE + ".service")
        ours = False
        try:
            with open(upath) as f:
                ours = "installed by singbox-panel" in f.read()
        except OSError:
            pass
        _rm(limits_path(), log)
        try:
            os.rmdir(os.path.dirname(limits_path()))
        except OSError:
            pass
        if ours:
            binary = service_binary()
            _rm(upath, log)
            if binary and os.path.abspath(binary) == os.path.abspath(FRESH_BIN):
                _rm(binary, log)
            _rm("/var/lib/sing-box", log)
        else:
            log.append("бинарник и служба sing-box остались: их поставили не через панель (удалите пакетом: apt remove sing-box)")
        run(["systemctl", "daemon-reload"])
        _rm(CONFIG, log)
        for d in (BACKUPS, BIN_BACKUPS, UPD_DIR, GW_DIR, STATE_FILE, TRAFFIC_FILE, PRESETS_FILE):
            _rm(d, log)
        _traffic.update(loaded=False, since=0, rx=0, tx=0, last=None)
        _version["v"] = ""
    return {"ok": True, "message": "Всё удалено, панель вернулась к первоначальному состоянию", "log": log}


def busy_ports():
    rc, out = run(["ss", "-H", "-ltn"])
    ports = set()
    for line in out.splitlines() if rc == 0 else []:
        cols = line.split()
        if len(cols) >= 4 and cols[3].rsplit(":", 1)[-1].isdigit():
            ports.add(int(cols[3].rsplit(":", 1)[-1]))
    return ports


# ------------------------------------- обновление самой панели со своего файлового сервера
# Источники обновлений панели (зашиты в пакет, из интерфейса не меняются), по порядку: основной — релизы GitHub,
# резервный — общая папка Google Drive. latest.json и пакет берутся из одного и того же источника.
PANEL_UPDATE_SOURCES = [
    ("GitHub", "https://github.com/maxhoney920/singbox-panel/releases/latest/download"),
    ("Google Drive", "https://drive.google.com/drive/folders/1nJ-5Imc3A7f5x_yVYk_vYEMUxWz4J4vU"),
]
PANEL_UPDATE_URL = ""          # для тестов/отладки: если задан, используется вместо списка выше
PU_INTERVAL = 2 * 3600                                               # проверка новых версий раз в 2 часа; ставится только по кнопке
PANEL_DEBS = os.path.join(DATA, "panel-debs")
PKG_NAME = "singbox-panel"
FILE_RE = re.compile(r"^singbox-panel_[0-9][0-9A-Za-z.+~-]*_all\.deb$")
_pu = {"latest": None, "checked": 0, "error": ""}


def _verkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4])


GD_RE = re.compile(r"^https://drive\.google\.com/drive/(?:u/\d+/)?folders/([A-Za-z0-9_-]+)")
_gd = {"t": 0.0, "id": "", "files": {}}


def gd_parse(html):
    """Имена и id файлов из страницы embeddedfolderview общей папки Google Drive."""
    import html as _h
    out = {}
    for fid, name in re.findall(r'id="entry-([A-Za-z0-9_-]+)".*?class="flip-entry-title">([^<]+)<', html, re.S):
        out.setdefault(_h.unescape(name).strip(), fid)
    return out


def _pu_sources():
    return [("", PANEL_UPDATE_URL)] if PANEL_UPDATE_URL else list(PANEL_UPDATE_SOURCES)


def _pu_urls(name, opener=None, base=None):
    """Адреса, по которым можно скачать файл из источника обновлений.
    Обычный каталог (и релизы GitHub): <url>/<имя>. Общая папка Google Drive: находим id файла по списку папки."""
    u = (base or PANEL_UPDATE_URL or PANEL_UPDATE_SOURCES[0][1]).rstrip("/")
    m = GD_RE.match(u)
    if not m:
        return [u + "/" + urllib.parse.quote(name)]
    folder = m.group(1)
    if _gd["id"] != folder or time.time() - _gd["t"] > 600 or name not in _gd["files"]:
        with opener.open(f"https://drive.google.com/embeddedfolderview?id={folder}", timeout=30) as r:
            _gd.update(id=folder, t=time.time(), files=gd_parse(r.read(2_000_000).decode("utf-8", "replace")))
    fid = _gd["files"].get(name)
    if not fid:
        raise OSError(f"файла {name} нет в папке (проверьте, что доступ открыт «всем, у кого есть ссылка», и файл лежит в корне папки)")
    return [f"https://drive.usercontent.google.com/download?id={fid}&export=download&confirm=t",
            f"https://drive.google.com/uc?export=download&id={fid}&confirm=t"]


def pu_open(name, prefer=None):
    """Открывает файл обновления: по очереди из источников (сначала prefer — откуда взят latest.json).
    Возвращает ответ; название источника — в _pu["src"]."""
    srcs = _pu_sources()
    srcs.sort(key=lambda s: s[0] != prefer)
    errs = []
    for label, base in srcs:
        try:
            r = _pu_open_one(name, base)
            _pu["src"] = label
            return r
        except OSError as e:
            errs.append(f"{label}: {e}" if label else str(e))
    raise OSError("; ".join(errs))


def _pu_open_one(name, base):
    import http.cookiejar
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    op.addheaders = [("User-Agent", "Mozilla/5.0 (X11; Linux) singbox-panel/" + APP_VERSION)]
    errs = []
    try:
        urls = _pu_urls(name, op, base)
    except urllib.error.HTTPError as e:
        raise OSError(f"список папки: HTTP {e.code}")
    for url in urls:
        try:
            r = op.open(url, timeout=30)
            if "text/html" in (r.headers.get("Content-Type") or "").lower():
                errs.append("ответ HTML (не файл)")
                r.close()
                continue
            return r
        except urllib.error.HTTPError as e:
            errs.append(f"HTTP {e.code}")
        except OSError as e:
            errs.append(str(getattr(e, "reason", e)))
    raise OSError("; ".join(dict.fromkeys(errs)) or "нет ответа")


def pu_installed_by_dpkg():
    return bool(shutil.which("dpkg")) and run(["dpkg", "-s", PKG_NAME])[0] == 0


def pu_debs():
    out = []
    if os.path.isdir(PANEL_DEBS):
        for n in sorted(os.listdir(PANEL_DEBS), key=lambda n: _verkey(n), reverse=True):
            if FILE_RE.match(n):
                out.append({"name": n, "size": os.path.getsize(os.path.join(PANEL_DEBS, n))})
    return out


def pu_check():
    """Скачивает latest.json и запоминает, есть ли версия новее. Ничего не устанавливает."""
    try:
        with pu_open("latest.json") as r:                  # всегда сначала основной источник (GitHub)
            m = json.loads(r.read(100000).decode("utf-8", "replace"))
        ver, fn, sha = str(m["version"]), str(m["file"]), str(m["sha256"]).lower()
        if not FILE_RE.match(fn) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("в latest.json неверное имя файла или sha256")
        notes = []
        for e in (m.get("changelog") or [])[:20]:
            if isinstance(e, dict) and isinstance(e.get("changes"), list):
                v = str(e.get("version", ""))[:20]
                if APP_VERSION != "dev" and _verkey(v) > _verkey(APP_VERSION):     # только то, чего у вас ещё нет
                    notes.append({"version": v, "changes": [str(c)[:300] for c in e["changes"][:15]]})
        _pu["latest"] = {"version": ver, "file": fn, "sha256": sha, "notes": notes, "source": _pu.get("src", ""),
                         "newer": APP_VERSION != "dev" and _verkey(ver) > _verkey(APP_VERSION)}
        _pu["error"] = ""
    except (OSError, ValueError, KeyError, TypeError) as e:
        _pu["error"] = f"Не удалось получить latest.json: {e}"
    _pu["checked"] = time.time()
    with LOCK:
        st = load_state()
        st["pu"] = {"checked": _pu["checked"], "latest": _pu["latest"], "error": _pu["error"]}
        save_state(st)
    return _pu["error"] == ""


def pu_fresh(lt):
    """Сохранённый ответ мог быть получен прежней версией панели: «новее ли» пересчитываем относительно текущей."""
    if not lt:
        return lt
    cur = _verkey(APP_VERSION)
    return {**lt, "newer": APP_VERSION != "dev" and _verkey(lt.get("version", "")) > cur,
            "notes": [n for n in lt.get("notes") or [] if APP_VERSION != "dev" and _verkey(n.get("version", "")) > cur]}


def pu_loop():
    saved = load_state().get("pu") or {}
    _pu.update(latest=pu_fresh(saved.get("latest")), checked=saved.get("checked", 0), error=saved.get("error", ""))
    time.sleep(random.randint(30, 300))
    while True:
        if time.time() - _pu["checked"] >= PU_INTERVAL:
            pu_check()
        time.sleep(max(60, PU_INTERVAL - (time.time() - _pu["checked"])))


def _pu_view():
    return {"ok": True, "version": APP_VERSION, "dpkg": pu_installed_by_dpkg(), "can": bool(shutil.which("dpkg")), "latest": pu_fresh(_pu["latest"]),
            "checked": _pu["checked"], "error": _pu["error"], "debs": pu_debs()}


def pu_start_install(path):
    """dpkg -i в отдельном процессе: перезапуск панели пакетом не должен убить саму установку."""
    cmd = ["dpkg", "-i", path]
    if shutil.which("systemd-run") and "INVOCATION_ID" in os.environ:
        rc, out = run(["systemd-run", "--no-block", "--unit=singbox-panel-upgrade", "--collect",
                       "--setenv=DEBIAN_FRONTEND=noninteractive"] + cmd)
        return (True, "") if rc == 0 else (False, out)
    try:
        subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, ""
    except OSError as e:
        return False, str(e)


@app.get("/api/panelupdate")
def panelupdate_get(user: str = Depends(auth)):
    return _pu_view()


@app.post("/api/panelupdate")
def panelupdate_set(body: dict, user: str = Depends(auth)):
    act = body.get("action")
    if act == "check":
        ok = pu_check()
        v = _pu_view()
        if not ok:
            return {**v, "ok": False, "error": _pu["error"]}
        return {**v, "message": ("Доступна версия " + _pu["latest"]["version"]) if _pu["latest"]["newer"] else "Установлена последняя версия"}
    if act in ("install", "rollback"):
        if not shutil.which("dpkg"):
            return {"ok": False, "error": "В системе нет dpkg — обновите панель вручную тем же способом, которым ставили"}
        if act == "install":
            lt = _pu["latest"]
            if not lt or not lt.get("newer"):
                return {"ok": False, "error": "Нет новой версии — нажмите «Проверить»"}
            os.makedirs(PANEL_DEBS, exist_ok=True)
            path = os.path.join(PANEL_DEBS, lt["file"])
            tmp = path + ".part"
            try:
                h = hashlib.sha256()
                prog("panel", "Скачивание singbox-panel " + lt["version"], 0)
                with pu_open(lt["file"], prefer=lt.get("source")) as r, open(tmp, "wb") as f:
                    _copy_progress(r, f, h, 50 * 1024 * 1024, (0, 85))
                prog(stage="Проверка контрольной суммы и пакета", pct=90)
                if h.hexdigest() != lt["sha256"]:
                    raise ValueError("контрольная сумма не совпала с latest.json — файл повреждён или подменён")
                rc, info = run(["dpkg-deb", "-f", tmp, "Package", "Version", "Architecture"])
                f_ = dict(l.split(": ", 1) for l in info.splitlines() if ": " in l)
                if rc != 0 or f_.get("Package") != PKG_NAME or f_.get("Version") != lt["version"] or f_.get("Architecture") not in ("all", run(["dpkg", "--print-architecture"])[1]):
                    raise ValueError(f"это не пакет {PKG_NAME} {lt['version']} для этой системы")
                os.replace(tmp, path)
            except (OSError, ValueError) as e:
                PROG["active"] = False
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                return {"ok": False, "error": f"Не удалось подготовить обновление: {e}"}
            ver = lt["version"]
            for old in pu_debs()[3:]:                    # хранятся три последних пакета — для отката
                try:
                    os.remove(os.path.join(PANEL_DEBS, old["name"]))
                except OSError:
                    pass
        else:
            name = os.path.basename(str(body.get("name", "")))
            path = os.path.join(PANEL_DEBS, name)
            if not FILE_RE.match(name) or not os.path.isfile(path):
                return {"ok": False, "error": "Такой копии нет"}
            ver = name.split("_")[1]
        prog("panel", "Установка пакета, затем перезапуск панели", 95, active=False)
        ok, err = pu_start_install(path)
        if not ok:
            return {"ok": False, "error": f"Не удалось запустить установку: {err}"}
        return {"ok": True, "installing": ver, "message": f"Устанавливается версия {ver}, панель перезапустится на несколько секунд"}
    raise HTTPException(400, "Недопустимое действие")


# ------------------------------------- DNS внутри sing-box (для шлюза и TUN)
DNS_TAGS = ("panel-dns-direct", "panel-dns-remote")
DNS_IN = "panel-dns-in"
RU_ZONES = ["ru", "su", "xn--p1ai"]


def dns_port_taken():
    """Порт 53 занят на внешнем адресе (systemd-resolved на 127.0.0.53 не мешает)."""
    rc, out = run(["ss", "-H", "-lnu"])
    rc2, out2 = run(["ss", "-H", "-lnt"])
    for line in (out + "\n" + out2).splitlines():
        cols = line.split()
        if len(cols) >= 4 and cols[3].rsplit(":", 1)[-1] == "53" and not cols[3].startswith("127."):
            return True
    return False


def dns_state(cfg):
    ours = [x for x in (cfg.get("dns") or {}).get("servers", []) if x.get("tag") in DNS_TAGS]
    return {"enabled": bool(ours), "listener": any(i.get("tag") == DNS_IN for i in cfg.get("inbounds", []) or [])}


@app.get("/api/dns")
def dns_get(user: str = Depends(auth)):
    try:
        cfg = _cfg_read()
    except (OSError, ValueError):
        cfg = {}
    ifs = net_ifaces()
    tun = tun_name([i["name"] for i in ifs])
    ips = [a.split("/")[0] for i in ifs if not _is_tunlike(i["name"], tun) for a in i["addrs"] if ":" not in a]
    return {"ok": True, **dns_state(cfg), "ips": ips, "port53_busy": dns_port_taken(),
            "foreign": bool([x for x in (cfg.get("dns") or {}).get("servers", []) if x.get("tag") not in DNS_TAGS])}


@app.post("/api/dns")
def dns_set(body: dict, user: str = Depends(auth)):
    """Включает/выключает DNS в sing-box: перехват DNS-запросов (в т. ч. от клиентов шлюза) и приём их на :53."""
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"Не удалось прочитать конфиг: {e}"}
        dns = cfg.setdefault("dns", {})
        route = cfg.setdefault("route", {})
        rules = route.setdefault("rules", [])
        ibs = cfg.setdefault("inbounds", [])
        # сначала всегда убираем своё
        dns["servers"] = [x for x in dns.get("servers", []) if x.get("tag") not in DNS_TAGS]
        dns["rules"] = [r for r in dns.get("rules", []) if r.get("server") not in DNS_TAGS]
        if dns.get("final") in DNS_TAGS:
            dns.pop("final")
        ibs[:] = [i for i in ibs if i.get("tag") != DNS_IN]
        rules[:] = [r for r in rules if not (isinstance(r, dict) and (r.get("inbound") == [DNS_IN] or r.get("_panel_dns")))
                    and not (isinstance(r, dict) and r.get("protocol") == "dns" and r.get("action") == "hijack-dns")]
        if route.get("default_domain_resolver") == DNS_TAGS[0]:
            route.pop("default_domain_resolver")
        if body.get("enable"):
            if dns["servers"]:
                return {"ok": False, "error": "В конфиге уже есть своя секция dns. Панель не меняет чужие настройки DNS — отредактируйте её в редакторе конфига."}
            ver = parse_ver(sb_version()) or (1, 12, 0)
            if ver < (1, 11, 0):
                return {"ok": False, "error": "Для встроенного DNS нужен sing-box 1.11 или новее (обновите на вкладке «Обновление»)."}
            direct = next((o["tag"] for o in cfg.get("outbounds", []) if o.get("type") == "direct" and o.get("tag")), "direct")
            if not any(o.get("tag") == direct for o in cfg.get("outbounds", [])):
                cfg.setdefault("outbounds", []).append({"type": "direct", "tag": direct})
            remote_detour = route.get("final") if route.get("final") and route.get("final") != direct else None
            if ver >= (1, 12, 0):
                srv = [{"type": "udp", "tag": DNS_TAGS[0], "server": body.get("direct_dns") or "77.88.8.8"},
                       {"type": "https", "tag": DNS_TAGS[1], "server": "1.1.1.1", **({"detour": remote_detour} if remote_detour else {})}]
                route.setdefault("default_domain_resolver", DNS_TAGS[0])
            else:
                srv = [{"tag": DNS_TAGS[0], "address": body.get("direct_dns") or "77.88.8.8", "detour": direct},
                       {"tag": DNS_TAGS[1], "address": "https://1.1.1.1/dns-query", **({"detour": remote_detour} if remote_detour else {})}]
            dns["servers"] = srv
            dns["rules"] = [{"domain_suffix": RU_ZONES, "server": DNS_TAGS[0]}] + dns.get("rules", [])
            dns["final"] = DNS_TAGS[1]
            idx = 0
            if not any(isinstance(r, dict) and r.get("action") == "sniff" for r in rules):
                rules.insert(0, {"action": "sniff"})
            while idx < len(rules) and isinstance(rules[idx], dict) and rules[idx].get("action") == "sniff":
                idx += 1
            new = [{"protocol": "dns", "action": "hijack-dns"}]
            if body.get("listen", True) and not dns_port_taken():
                ibs.append({"type": "direct", "tag": DNS_IN, "listen": "0.0.0.0", "listen_port": 53})
                new.insert(0, {"inbound": [DNS_IN], "action": "hijack-dns"})
            rules[idx:idx] = new
        if not dns.get("servers"):
            for k in ("servers", "rules", "final"):
                if not dns.get(k):
                    dns.pop(k, None)
            if not dns:
                cfg.pop("dns", None)
        return apply_config(json.dumps(cfg), "apply")


# ------------------------------------- SOCKS5/HTTP-прокси внутри sing-box
SBP_TAGS = ("panel-socks", "panel-http")


def sbproxy_status():
    try:
        ibs = _cfg_read().get("inbounds", []) or []
    except (OSError, ValueError):
        ibs = []
    mine = {i.get("tag"): i for i in ibs if i.get("tag") in SBP_TAGS}
    ifs = net_ifaces()
    tun = tun_name([i["name"] for i in ifs])
    ips = [a.split("/")[0] for i in ifs if not _is_tunlike(i["name"], tun) for a in i["addrs"]]
    return {"ok": True, "enabled": bool(mine), "socks_port": (mine.get("panel-socks") or {}).get("listen_port", 1080),
            "http_port": (mine.get("panel-http") or {}).get("listen_port", 1081),
            "listen": (next(iter(mine.values()), {}) or {}).get("listen", "0.0.0.0"),
            "ips": ips, "busy": sorted(busy_ports() & {1080, 1081})}


@app.get("/api/sbproxy")
def sbproxy_get(user: str = Depends(auth)):
    return sbproxy_status()


@app.post("/api/sbproxy")
def sbproxy_set(body: dict, user: str = Depends(auth)):
    """Включает SOCKS5 и HTTP-прокси внутри sing-box: трафик не делает крюк через TUN."""
    with LOCK:
        try:
            cfg = _cfg_read()
        except (OSError, ValueError) as e:
            return {"ok": False, "error": f"Не удалось прочитать конфиг: {e}"}
        ibs = cfg.setdefault("inbounds", [])
        own = {i.get("listen_port") for i in ibs if i.get("tag") in SBP_TAGS}      # свои порты не считаются занятыми
        ibs[:] = [i for i in ibs if i.get("tag") not in SBP_TAGS]
        if body.get("enable"):
            try:
                sp, hp = int(body.get("socks_port") or 1080), int(body.get("http_port") or 1081)
            except (TypeError, ValueError):
                return {"ok": False, "error": "Порты — числа"}
            if not (1 <= sp <= 65535 and 1 <= hp <= 65535) or sp == hp:
                return {"ok": False, "error": "Порты должны быть разными, 1–65535"}
            busy = (busy_ports() & {sp, hp}) - own
            if busy:
                return {"ok": False, "error": f"Порт(ы) {', '.join(map(str, sorted(busy)))} уже заняты. "
                                              "Если это старый контейнер 3proxy: docker rm -f singbox-panel-3proxy"}
            listen = "127.0.0.1" if body.get("local_only") else "0.0.0.0"
            ibs += [{"type": "socks", "tag": "panel-socks", "listen": listen, "listen_port": sp},
                    {"type": "http", "tag": "panel-http", "listen": listen, "listen_port": hp}]
        res = apply_config(json.dumps(cfg), "apply")
        return res


# ------------------------------------------------ доступ к самой панели (LAN)
def effective_host():
    return HOST if load_state().get("web_lan", True) else "127.0.0.1"


def schedule_self_restart():
    if "INVOCATION_ID" not in os.environ:
        return False
    threading.Timer(1.5, lambda: run(["systemctl", "--no-block", "restart", PANEL_UNIT])).start()
    return True


@app.get("/api/webaccess")
def get_webaccess(user: str = Depends(auth)):
    return {"ok": True, "lan": load_state().get("web_lan", True), "host": effective_host(),
            "configured_host": HOST, "port": PORT, "systemd": "INVOCATION_ID" in os.environ}


@app.post("/api/webaccess")
def set_webaccess(body: dict, user: str = Depends(auth)):
    lan = bool(body.get("lan"))
    st = load_state()
    st["web_lan"] = lan
    save_state(st)
    restarted = schedule_self_restart()
    return {"ok": True, "lan": lan, "restarting": restarted,
            "message": ("Применяю: панель перезапускается…" if restarted else "Сохранено. Перезапустите панель вручную: systemctl restart " + PANEL_UNIT)}


def cli(args):
    """singbox-panel lan on|off|status  /  p2p on|off|status  /  gateway off — запасной выход из консоли."""
    if args[:1] == ["lan"] and args[1:2] in (["on"], ["off"], ["status"]):
        st = load_state()
        if args[1] == "status":
            print("Доступ из локальной сети:", "разрешён" if st.get("web_lan", True) else "запрещён (только localhost)")
            return 0
        st["web_lan"] = args[1] == "on"
        save_state(st)
        print("Доступ из локальной сети:", "разрешён" if st["web_lan"] else "запрещён (только localhost)")
        rc, _ = run(["systemctl", "try-restart", PANEL_UNIT], timeout=30)
        print("Панель перезапущена" if rc == 0 else f"Перезапустите панель: systemctl restart {PANEL_UNIT}")
        return 0
    if args[:1] == ["p2p"] and args[1:2] in (["on"], ["off"], ["status"]):
        global SERVICE, BINARY
        if "SBP_SERVICE" not in os.environ:
            SERVICE = detect_service() or SERVICE
        if "SBP_BINARY" not in os.environ:
            BINARY = service_binary() or BINARY
        print("Конфиг:", CONFIG, "| служба:", SERVICE)
        try:
            on = any(_is_p2p(r) for r in (_cfg_read().get("route") or {}).get("rules", []) or [])
        except (OSError, ValueError) as e:
            print("Конфиг не прочитан:", e)
            return 1
        if args[1] == "status":
            print("BitTorrent напрямую:", "включено" if on else "выключено")
            return 0
        res = p2p_toggle({"enable": args[1] == "on"}, "cli")
        print(res.get("message") or res.get("error"))
        return 0 if res.get("ok") else 1
    if args[:2] == ["gateway", "off"]:
        print(gateway_disable()["message"])
        return 0
    print(cli.__doc__)
    return 2


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(cli(sys.argv[1:]))
    app.run(effective_host(), PORT)
