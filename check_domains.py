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

IMPERSONATE_POOL = [
    "chrome146", "chrome145", "chrome142", "chrome136",
    "firefox147", "safari184", "edge101",
]


def pick_impersonate() -> str:
    return random.choice(IMPERSONATE_POOL)


DOMAINS_FILE = os.environ.get("DOMAINS_FILE", "domains.json")


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
    proxy_url = f"https://translate.google.com/translate?sl=auto&tl=en&u={quote(url, safe='')}"
    try:
        apply_google_dns(session, proxy_url)
        res = session.get(
            proxy_url,
            allow_redirects=True,
            timeout=TRANSLATE_TIMEOUT,
            impersonate=imp,
        )
        if res.status_code != 200:
            return {"success": False, "error": f"translate status {res.status_code}"}
        new_url = extract_new_url(res.text, url)
        if new_url and new_url != url:
            return {"success": True, "final_url": new_url}
        return {"success": False, "error": "nessun nuovo dominio trovato"}
    except Exception as e:
        return {"success": False, "error": str(e)}


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


def process_site(session: cffi.Session, name: str, config: dict) -> dict | None:
    url = config.get("full_url", "")
    if not url:
        return None

    imp = pick_impersonate()
    print(f"[{name}] CHECK -> {url}  ({imp})")
    result = direct_check(session, url, imp)
    status = result["status"]
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
        bypass = google_translate_proxy(session, url, imp)
        if bypass["success"]:
            new_url = bypass["final_url"]
            print(f"  ✅ Nuovo dominio: {new_url}")
            target_url, url_changed, status = new_url, (new_url != url), 200
        else:
            print(f"  ❌ Bypass fallito: {bypass['error']}")

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
                updated = process_site(session, name, config)
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

    print(f"\n✅ {updated_count} domini aggiornati → {DOMAINS_FILE}")

    print("\n--- Riepilogo ---")
    for name, config in all_domains.items():
        mark = "⚠️ " if config.get("last_status") not in (200, None) else "   "
        status = str(config.get("last_status", "?")).rjust(4)
        print(f"{mark}{name:<25} {status}  {config.get('full_url', '')}")


if __name__ == "__main__":
    main()
