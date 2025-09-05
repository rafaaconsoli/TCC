#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, re, json, base64, subprocess
import ssl as _ssl
from urllib import request as _urlreq, parse as _urlparse
import types

# ========================== #
#     Bootstrap requests     #
# ========================== #

_DEPS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pydeps")
if _DEPS_DIR not in sys.path:
    sys.path.insert(0, _DEPS_DIR)

def _install_with_pip(pkg: str) -> bool:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade",
                               "--no-cache-dir", "--target", _DEPS_DIR, pkg],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        try:
            import ensurepip
            subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade",
                                   "--no-cache-dir", "--target", _DEPS_DIR, pkg],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

def _build_requests_stub():
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    class _Resp:
        def __init__(self, httpresp):
            self.status_code = getattr(httpresp, "status", getattr(httpresp, "code", 0))
            self.headers = dict(getattr(httpresp, "headers", {}))
            self.content = httpresp.read()
            try: self.text = self.content.decode("utf-8", "ignore")
            except Exception: self.text = ""
        def json(self): return json.loads(self.text or "{}")

    class _Session:
        def __init__(self):
            self.headers = {}
            self._cookie_processor = _urlreq.HTTPCookieProcessor()
            self._opener = _urlreq.build_opener(self._cookie_processor, _urlreq.HTTPSHandler(context=ctx))
        def post(self, url, data=None, json=None, headers=None, verify=False, timeout=25):
            h = dict(self.headers); h.update(headers or {})
            if json is not None:
                h.setdefault("Content-Type", "application/json-rpc")
                payload = json.dumps(json).encode("utf-8")
            else:
                h.setdefault("Content-Type", "application/x-www-form-urlencoded")
                payload = _urlparse.urlencode(data or {}).encode("utf-8")
            req = _urlreq.Request(url, data=payload, method="POST", headers=h)
            return _Resp(self._opener.open(req, timeout=timeout))
        def get(self, url, params=None, headers=None, verify=False, timeout=25):
            h = dict(self.headers); h.update(headers or {})
            if params:
                qs = _urlparse.urlencode(params)
                url = f"{url}{'&' if '?' in url else '?'}{qs}"
            req = _urlreq.Request(url, method="GET", headers=h)
            return _Resp(self._opener.open(req, timeout=timeout))

    mod = types.ModuleType("requests")
    mod.Session = _Session
    sys.modules["requests"] = mod
    return mod

try:
    import requests
except Exception:
    if not os.path.isdir(_DEPS_DIR):
        os.makedirs(_DEPS_DIR, exist_ok=True)
    if _install_with_pip("requests>=2.31.0"):
        import requests
    else:
        requests = _build_requests_stub()

# ========================== #
#      ENV e constantes      #
# ========================== #

ZBX_FROM   = os.getenv("ZBX_FROM", "now-6h")
ZBX_TO     = os.getenv("ZBX_TO", "now")
ZBX_WIDTH  = os.getenv("ZBX_WIDTH", "1024")
ZBX_HEIGHT = os.getenv("ZBX_HEIGHT", "220")
ZBX_COLOR  = os.getenv("ZBX_COLOR", "18A558").lstrip("#").upper()
ZBX_EXTRA  = os.getenv("ZBX_EXTRA_ITEMS", "").strip()

HEX6_RE = re.compile(r"^[0-9A-Fa-f]{6}$")
PALETTE = [
    "FF0000","00C800","FFA500","00BFFF","8B00FF","FFD700","FF1493","00FFFF","6B8E23","FF7F50",
    "4169E1","7FFF00","DC143C","00CED1","FF69B4","2E8B57","20B2AA","B22222","40E0D0","9ACD32"
]
JSONRPC_CT = {"Content-Type":"application/json-rpc"}

def fail(msg, code=1):
    print(msg); sys.exit(code)

def parse_args(argv):
    if len(argv) != 11:
        fail(
            f"Uso: {argv[0]} <URLZBX> <USERZBX> <PWDZBX> <ITEMIDZBX> <URLAPI> <APIKEY> <INSTANCE> <TO> <SUBJECT> <MSG>\n"
            f"Ex.: {argv[0]} https://zbx.example.com Admin Senha 48061 https://evo.example.com APIKEY inst01 1203...@g.us 'Assunto' 'Mensagem'\n"
        )
    zbx_url = argv[1].rstrip("/")
    zbx_user = argv[2]; zbx_pwd  = argv[3]
    itemid   = argv[4].strip()
    wa_url   = argv[5].rstrip("/"); wa_key = argv[6]; wa_inst = argv[7]
    wa_to    = argv[8]; subject = argv[9]; message = argv[10]
    if not (zbx_url.startswith("http://") or zbx_url.startswith("https://")): fail("URLZBX deve começar com http:// ou https://")
    if not itemid.isdigit(): fail("ITEMIDZBX deve ser numérico.")
    if not (wa_url.startswith("http://") or wa_url.startswith("https://")): fail("URLAPI deve começar com http:// ou https://")
    if not subject or not message: fail("SUBJECT e MSG não podem estar vazios.")
    return zbx_url, zbx_user, zbx_pwd, itemid, wa_url, wa_key, wa_inst, wa_to, subject, message

# ========================== #
#     Zabbix API helpers     #
# ========================== #

def ver_ge(a: str, b: str) -> bool:
    def parse(v): return [int(x) for x in re.findall(r"\d+", v)[:3]] or [0]
    A, B = parse(a), parse(b)
    A += [0]*(3-len(A)); B += [0]*(3-len(B))
    return A >= B

def zbx_version(session, base):
    r = session.post(f"{base}/api_jsonrpc.php",
                     json={"jsonrpc":"2.0","method":"apiinfo.version","params":{}, "id":1},
                     headers=JSONRPC_CT, verify=False, timeout=15)
    try: return r.json().get("result","0.0")
    except Exception: return "0.0"

def zbx_login(session, base, user, pwd):
    ver = zbx_version(session, base)
    key = "username" if ver_ge(ver, "6.4") else "user"
    r = session.post(f"{base}/api_jsonrpc.php",
                     json={"jsonrpc":"2.0","method":"user.login","params":{key:user,"password":pwd},"id":1},
                     headers=JSONRPC_CT, verify=False, timeout=20)
    data = r.json()
    if "error" in data: fail(f"Zabbix API user.login: {data['error']}")
    token = data["result"]
    if ver_ge(ver, "7.2"):
        session.headers.update({"Authorization": f"Bearer {token}"})
    return token, ver

def zbx_call(session, base, method, params, token, ver):
    payload = {"jsonrpc":"2.0","method":method,"params":params,"id":1}
    headers = dict(JSONRPC_CT)
    if not ver_ge(ver, "7.2"):
        payload["auth"] = token
    r = session.post(f"{base}/api_jsonrpc.php", json=payload, headers=headers, verify=False, timeout=25)
    data = r.json()
    if "error" in data and "unexpected parameter \"auth\"" in str(data["error"]).lower():
        payload.pop("auth", None)
        headers["Authorization"] = f"Bearer {token}"
        r = session.post(f"{base}/api_jsonrpc.php", json=payload, headers=headers, verify=False, timeout=25)
        data = r.json()
    if "error" in data: fail(f"Zabbix API {method}: {data['error']}")
    return data["result"]

def zbx_item_and_host(session, base, token, ver, itemid):
    res = zbx_call(session, base, "item.get",
                   {"itemids": itemid, "output":["name"], "selectHosts":["name"]},
                   token, ver)
    if not res: fail("Item não encontrado ou sem permissão.")
    item_name = res[0]["name"]
    host_name = (res[0].get("hosts") or [{}])[0].get("name","(host)")
    return item_name, host_name

# ====================== #
#     Frontend login     #
# ====================== #

def fe_login(session, base, user, pwd):
    session.post(f"{base}/index.php",
                 data={"name":user,"password":pwd,"enter":"Sign in","autologin":1},
                 verify=False, timeout=15)
    session.post(f"{base}/index.php?login=1",
                 data={"name":user,"password":pwd,"enter":"Sign in"},
                 verify=False, timeout=15)

def build_chart3_params(title, itemids):
    first = ZBX_COLOR if HEX6_RE.match(ZBX_COLOR) else "18A558"
    colors = [first] + [PALETTE[(i % len(PALETTE))] for i in range(len(itemids)-1)]
    p = {"from":ZBX_FROM, "to":ZBX_TO, "width":ZBX_WIDTH, "height":ZBX_HEIGHT, "name":title}
    for i, iid in enumerate(itemids):
        p[f"items[{i}][itemid]"]   = iid
        p[f"items[{i}][drawtype]"] = "5"
        p[f"items[{i}][color]"]    = colors[i]
    return p

def get_chart3_png(session, base, title, itemids):
    r = session.get(f"{base}/chart3.php",
                    params=build_chart3_params(title, itemids),
                    headers={"Accept":"image/png","Referer":base},
                    verify=False, timeout=45)
    ct = (r.headers.get("Content-Type","") or "").lower()
    if r.status_code == 200 and "image/png" in ct: return r.content
    raise RuntimeError(f"chart3.php falhou. HTTP={r.status_code} CT={ct} SNIPPET={getattr(r,'text','')[:200]}")

def get_chart_php_png(session, base, first_itemid, title):
    r = session.get(f"{base}/chart.php",
                    params={"from":ZBX_FROM,"to":ZBX_TO,"type":"0","profileIdx":"web.item.graph.filter",
                            "width":ZBX_WIDTH,"height":ZBX_HEIGHT,"itemids[0]":first_itemid,"name":title},
                    headers={"Accept":"image/png","Referer":base},
                    verify=False, timeout=45)
    ct = (r.headers.get("Content-Type","") or "").lower()
    if r.status_code == 200 and "image/png" in ct: return r.content
    raise RuntimeError(f"chart.php falhou. HTTP={r.status_code} CT={ct} SNIPPET={getattr(r,'text','')[:200]}")

# ===================== #
#     Evolution API     #
# ===================== #

def evo_send(wa_url, wa_key, wa_inst, to, subject, message, png_bytes):
    b64 = base64.b64encode(png_bytes).decode("utf-8")
    payload = {"number":to,"mediatype":"image","mimetype":"image/png",
               "caption":f"{subject}\n{message}","media":b64,"fileName":"chart.png","delay":1200}
    r = session.post(f"{wa_url}/message/sendMedia/{wa_inst}",
                     json=payload, headers={"Content-Type":"application/json","apikey":wa_key},
                     verify=False, timeout=30)
    print(f"Evolution API HTTP={r.status_code} body={getattr(r,'text','')[:300]}")
    if r.status_code not in (200,201): fail("Falha ao enviar mensagem e gráfico via Evolution.")

# ============ #
#     Main     #
# ============ #

def main():
    global session
    (zbx_url, zbx_user, zbx_pwd, itemid, wa_url, wa_key, wa_inst, wa_to, subject, message) = parse_args(sys.argv)

    # Monta lista de itens
    itemids = [itemid]
    if ZBX_EXTRA:
        itemids += [x.strip() for x in ZBX_EXTRA.split(",") if x.strip().isdigit()]

    # Sessão
    session = requests.Session()
    try: session.headers.update({"User-Agent":"curl/8","Accept":"text/html,application/xhtml+xml"})
    except Exception: pass

    # API login ZBX
    token, ver = zbx_login(session, zbx_url, zbx_user, zbx_pwd)
    # item.name & host.name
    item_name, host_name = zbx_item_and_host(session, zbx_url, token, ver, itemid)
    title = f"{host_name}: {item_name}"

    # frontend login
    fe_login(session, zbx_url, zbx_user, zbx_pwd)

    try:
        png = get_chart3_png(session, zbx_url, title, itemids)
    except Exception as e:
        print(f"Aviso: {e} — fallback chart.php (sem gradient).")
        png = get_chart_php_png(session, zbx_url, itemids[0], title)

    # Envia para a API
    evo_send(wa_url, wa_key, wa_inst, wa_to, subject, message, png)
    print("Mensagem e gráfico enviados com sucesso")

if __name__ == "__main__":
    main()
