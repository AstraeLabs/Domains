#!/usr/bin/env python3

import json
import os
import random
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

from curl_cffi import requests as cffi
from curl_cffi import CurlOpt

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

TIMEOUT_S         = 20
TRANSLATE_TIMEOUT = 40
DELAY_BETWEEN     = 1.5
MAX_REDIRECTS     = 10
GOOGLE_DOH        = "https://dns.google/resolve"
SSL_TIMEOUT_S     = 7
HISTORY_CAP       = 50
DIRECT_RETRY_LIMIT    = 3
TRANSLATE_RETRY_LIMIT = 2
RETRY_DELAY_S         = 2.0

IMPERSONATE_POOL = [
    "chrome146", "chrome145", "chrome142", "chrome136",
    "firefox147", "safari184", "edge101",
]


def pick_impersonate() -> str:
    return random.choice(IMPERSONATE_POOL)


DOMAINS_FILE = os.environ.get("DOMAINS_FILE", "domains.json")
# Versione ridotta letta dai client (VibraVid): solo nome sito -> full_url, la
# stessa forma che restituiva GET /get del Worker, cosi' e' un sostituto diretto.
# domains.json completo e' ~50 KB (history, response_ms, ssl_expiry), questo ~1 KB.
SLIM_FILE = os.environ.get("DOMAINS_SLIM_FILE", "domains_s.json")


INTERSTITIAL_MARKERS = ("disablevpn", "disable-vpn", "vpncheck", "vpn-check", "blockvpn")


def is_interstitial(u: str) -> bool:
    host = (urlparse(u).hostname or "").lower()
    return any(m in host for m in INTERSTITIAL_MARKERS)


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


_dns_cache: dict[str, str | None] = {}


def resolve_google(host: str) -> str | None:
    if host in _dns_cache:
        return _dns_cache[host]
    ip = None
    try:
        r = cffi.get(
            GOOGLE_DOH,
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=10,
            impersonate="chrome",
        )
        answers = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
        ip = answers[0] if answers else None
    except Exception as e:
        print(f"  ⚠️  DoH fallita per {host}: {e}")
        ip = None
    _dns_cache[host] = ip
    return ip


def apply_google_dns(session: cffi.Session, url: str) -> None:
    host = urlparse(url).hostname
    if not host:
        return
    ip = resolve_google(host)
    if not ip:
        return
    entries = [f"{host}:443:{ip}".encode(), f"{host}:80:{ip}".encode()]
    try:
        session.curl.setopt(CurlOpt.RESOLVE, entries)
    except Exception as e:
        print(f"  ⚠️  RESOLVE setopt fallito per {host}: {e}")


def get_ssl_expiry(url: str) -> str | None:
    host = urlparse(url).hostname
    if not host:
        return None
    ip = resolve_google(host) or host
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=SSL_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        if not cert or "notAfter" not in cert:
            return None
        na = str(cert["notAfter"])
        dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return dt.date().isoformat()
    except Exception as e:
        print(f"  ⚠️  SSL non leggibile per {host}: {e}")
        return None


def direct_check(session: cffi.Session, url: str, imp: str) -> dict:
    current_url = url
    visited = []
    response_ms = None

    for _ in range(MAX_REDIRECTS):
        apply_google_dns(session, current_url)
        try:
            t0 = time.perf_counter()
            res = session.get(
                current_url,
                allow_redirects=False,
                timeout=TIMEOUT_S,
                impersonate=imp,
            )
            response_ms = round((time.perf_counter() - t0) * 1000)
            status_code = res.status_code
            location = res.headers.get("location", "")

            visited.append({"url": current_url, "status": status_code})

            if status_code in (301, 302, 303, 307, 308):
                if not location:
                    break
                if location.startswith("/"):
                    p = urlparse(current_url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                elif not location.startswith("http"):
                    location = "https://" + location
                current_url = location
            else:
                break
        except Exception as e:
            return {"status": -1, "error": str(e), "final_url": current_url, "response_ms": None}

    final_status = visited[-1]["status"] if visited else -1
    try:
        p = urlparse(current_url)
        final_url = f"{p.scheme}://{p.netloc}/"
    except Exception:
        final_url = current_url

    return {"status": final_status, "final_url": final_url, "response_ms": response_ms}


def extract_new_url(html: str, original_url: str) -> str | None:
    m = re.search(r'<base[^>]+href=["\']([^"\']+)["\']', html, re.I)
    if m:
        href = m.group(1)
        if not href.startswith("http"):
            href = "https://" + href
        try:
            p = urlparse(href)
            return f"{p.scheme}://{p.netloc}/"
        except Exception:
            pass

    m = re.search(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']',
        html, re.I,
    )
    if m:
        redirect = m.group(1)
        if not redirect.startswith("http"):
            base = urlparse(original_url)
            redirect = f"{base.scheme}://{base.netloc}{redirect}"
        try:
            p = urlparse(redirect)
            return f"{p.scheme}://{p.netloc}/"
        except Exception:
            pass

    return None


def google_translate_proxy(session: cffi.Session, url: str, imp: str) -> dict:
    base_url = "https://translate.google.com/translate?hl=it&sl=en&tl=it&u="
    proxy_url = base_url + quote(url, safe="")
    try:
        apply_google_dns(session, proxy_url)
        res = session.get(
            proxy_url,
            allow_redirects=True,
            timeout=TRANSLATE_TIMEOUT,
            impersonate="chrome",
            headers={
                "User-Agent": "android",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3",
                "Accept-Charset": "UTF-8",
                "Accept-Encoding": "gzip",
            },
        )
        if res.status_code != 200:
            return {"success": False, "error": f"translate status {res.status_code}"}
        html = res.text
        if "<title>Google Traduttore" in html:
            proxy_base = "https://translate.googleusercontent.com/translate_p?hl=it&sl=en&tl=it&u="
            m = re.search(r'(?:href="|src="|value=")(https?://translate[^"]+)', html)
            if m and url in m.group(1):
                url_request = m.group(1).replace("&amp;", "&")
                res2 = session.get(
                    url_request,
                    allow_redirects=True,
                    timeout=TRANSLATE_TIMEOUT,
                    impersonate="chrome",
                    headers={
                        "User-Agent": "android",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3",
                        "Accept-Charset": "UTF-8",
                        "Accept-Encoding": "gzip",
                    },
                )

                if res2.status_code == 200:
                    html = res2.text
                    while "Sto traducendo" in html:
                        time.sleep(0.5)
                        res2 = session.get(
                            url_request,
                            allow_redirects=True,
                            timeout=TRANSLATE_TIMEOUT,
                            impersonate="chrome",
                            headers={
                                "User-Agent": "android",
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                                "Accept-Language": "it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3",
                                "Accept-Charset": "UTF-8",
                                "Accept-Encoding": "gzip",
                            },
                        )
                        if res2.status_code == 200:
                            html = res2.text
                        else:
                            break

        html = re.sub(r'\s(\w+)=(?!")([^<>\s]+)', r' \1="\2"', html)
        html = re.sub(r"https://translate\.googleusercontent\.com/.*?u=(.*?)&amp;usg=[A-Za-z0-9_-]+", r"\1", html)
        p = urlparse(url)
        domain = p.hostname or ""
        if domain:
            d = domain.replace(".", "-")
            html = re.sub(r"https?://[a-zA-Z0-9-]*" + re.escape(d) + r"\.translate\.goog(/[a-zA-Z0-9#/-]+)", "https://" + domain + r"\1", html)

        html = re.sub(r"https://translate\.google\.com/website\?[^ ]+u=", "", html)
        html = re.sub(r"\s+<", "<", html)
        html = html.replace("&amp;", "&").replace("https://translate.google.com/website?sl=en&tl=it&ajax=1&u=", "")
        new_url = extract_new_url(html, url)
        if new_url and new_url != url:
            return {"success": True, "final_url": new_url}
        
        m = re.search(r'href="(https?://[^"]+)"', html)
        if m:
            candidate = m.group(1)
            cp = urlparse(candidate)
            if cp.hostname and cp.hostname != (urlparse(url).hostname or ""):
                return {"success": True, "final_url": f"{cp.scheme}://{cp.netloc}/"}
        return {"success": False, "error": "nessun nuovo dominio trovato"}
    except Exception as e:
        return {"success": False, "error": str(e)}


_peer_cache: dict[str, str] = {}
HOST_RE = re.compile(r"https?://((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def brand_label(host: str) -> str:
    parts = host.lower().split(".")
    return parts[-2] if len(parts) >= 2 else host.lower()


def fetch_peer_html(session: cffi.Session, url: str) -> str:
    if url in _peer_cache:
        return _peer_cache[url]
    html = ""
    try:
        apply_google_dns(session, url)
        res = session.get(url, allow_redirects=True, timeout=TIMEOUT_S, impersonate="chrome")
        if res.status_code == 200:
            html = res.text
    except Exception as e:
        print(f"  ⚠️  Peer {url} non leggibile: {e}")
    _peer_cache[url] = html
    return html


def find_from_peers(session: cffi.Session, url: str, peers: list[str]) -> str | None:
    """Dominio morto (DNS/connessione): cerca nelle pagine degli altri siti un link
    con lo stesso nome (es. streamingcommunityz.*) ma TLD diverso, e lo verifica."""
    old_host = (urlparse(url).hostname or "").lower()
    brand = brand_label(old_host)
    tried = set()
    for peer in peers:
        for m in HOST_RE.finditer(fetch_peer_html(session, peer)):
            host = m.group(1).lower()
            if host == old_host or host in tried or brand_label(host) != brand:
                continue
            tried.add(host)
            candidate = f"https://{host}/"
            res = direct_check(session, candidate, "chrome")
            if res["status"] == 200:
                p = urlparse(res["final_url"])
                if brand_label(p.hostname or "") == brand:
                    return f"{p.scheme}://{p.netloc}/"
    return None


def make_update(config: dict, *, status: int, checked: str, response_ms,
                ssl_exp, full_url=None, status_changed: bool, url_changed: bool) -> dict:
    new = dict(config)
    if full_url is not None:
        new["full_url"] = full_url
    new["last_status"] = status
    new["last_check"] = checked
    if response_ms is not None:
        new["response_ms"] = response_ms
    if ssl_exp is not None:
        new["ssl_expiry"] = ssl_exp
    if status_changed or url_changed:
        new["time_change"] = now_str()
    if status_changed:
        hist = list(config.get("history", []))
        hist.append({"t": checked, "status": status})
        new["history"] = hist[-HISTORY_CAP:]
    return new


def process_site(session: cffi.Session, name: str, config: dict, peers: list[str] | None = None) -> dict | None:
    url = config.get("full_url", "")
    if not url:
        return None

    imp = pick_impersonate()
    print(f"[{name}] CHECK -> {url}  ({imp})")
    result = direct_check(session, url, imp)
    status = result["status"]

    attempts = 1
    while status in (403, 503, 429, -1) and attempts < DIRECT_RETRY_LIMIT:
        time.sleep(RETRY_DELAY_S)
        imp = pick_impersonate()
        print(f"  🔁 Retry diretto ({attempts + 1}/{DIRECT_RETRY_LIMIT}) con {imp}")
        result = direct_check(session, url, imp)
        status = result["status"]
        attempts += 1

    final_url = result.get("final_url", url)
    response_ms = result.get("response_ms")
    checked = now_iso()

    target_url = url
    url_changed = False

    if is_interstitial(final_url):
        print(f"  🛡️  Pagina anti-VPN ({final_url}) → mantengo {url}")
    elif final_url != url and status == 200:
        print(f"  ↳ Redirect a: {final_url}")
        target_url, url_changed = final_url, True
    elif status == 200:
        pass
    elif status in (403, 503, 429, -1):
        print(f"  ⚠️  Blocco (status {status}), provo Google Translate...")
        bypass = {"success": False, "error": "n/a"}
        for t_attempt in range(TRANSLATE_RETRY_LIMIT):
            t_imp = pick_impersonate()
            bypass = google_translate_proxy(session, url, t_imp)
            if bypass["success"]:
                break
            if t_attempt < TRANSLATE_RETRY_LIMIT - 1:
                print(f"  🔁 Retry Google Translate ({t_attempt + 2}/{TRANSLATE_RETRY_LIMIT})")
                time.sleep(RETRY_DELAY_S)
        if bypass["success"]:
            new_url = bypass["final_url"]
            print(f"  ✅ Nuovo dominio: {new_url}")
            target_url, url_changed, status = new_url, (new_url != url), 200
        else:
            print(f"  ❌ Bypass fallito: {bypass['error']}")
            if status == -1 and peers:
                print("  🔎 Dominio non raggiungibile, cerco nei siti collegati...")
                new_url = find_from_peers(session, url, [p for p in peers if p != url])
                if new_url and new_url != url:
                    print(f"  ✅ Nuovo dominio (da peer): {new_url}")
                    target_url, url_changed, status = new_url, True, 200

    ssl_exp = None if status == -1 else get_ssl_expiry(target_url)

    status_changed = config.get("last_status") != status
    ssl_changed = ssl_exp is not None and ssl_exp != config.get("ssl_expiry")

    if status_changed or url_changed or ssl_changed:
        return make_update(
            config,
            status=status,
            checked=checked,
            response_ms=response_ms,
            ssl_exp=ssl_exp,
            full_url=(target_url if url_changed else None),
            status_changed=status_changed,
            url_changed=url_changed,
        )

    return None


def main():
    if not os.path.exists(DOMAINS_FILE):
        print(f"❌ File non trovato: {DOMAINS_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(DOMAINS_FILE, encoding="utf-8") as f:
        all_domains: dict = json.load(f)

    print(f"🔍 Avvio controllo di {len(all_domains)} domini (curl_cffi + Google DNS)\n")

    updated_count = 0
    session = cffi.Session()
    try:
        for name, config in all_domains.items():
            try:
                peers = [c.get("full_url", "") for c in all_domains.values() if c.get("last_status") == 200]
                updated = process_site(session, name, config, peers)
            except Exception as e:
                print(f"  ❌ Errore su {name}: {e}")
                updated = None
            if updated:
                all_domains[name] = updated
                updated_count += 1
            time.sleep(DELAY_BETWEEN)
    finally:
        session.close()

    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_domains, f, indent=2, ensure_ascii=False)

    slim = {name: {"full_url": config.get("full_url")} for name, config in all_domains.items()}
    with open(SLIM_FILE, "w", encoding="utf-8") as f:
        json.dump(slim, f, indent=2, ensure_ascii=False)

    print(f"\n✅ {updated_count} domini aggiornati → {DOMAINS_FILE} (+ {SLIM_FILE})")

    print("\n--- Riepilogo ---")
    for name, config in all_domains.items():
        mark = "⚠️ " if config.get("last_status") not in (200, None) else "   "
        status = str(config.get("last_status", "?")).rjust(4)
        print(f"{mark}{name:<25} {status}  {config.get('full_url', '')}")


if __name__ == "__main__":
    main()
