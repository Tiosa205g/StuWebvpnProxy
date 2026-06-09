#!/usr/bin/env python3
"""
WebVPN HTTP Reverse Proxy with Cookie Injection

Forwards requests matching *.webvpn.stu.edu.cn:8118, rejects all others.
Injects configured cookies into upstream requests and strips matching
Set-Cookie from upstream responses to prevent leakage.
"""

import asyncio
import json
import os
import re
import logging
from pathlib import Path
from typing import Dict, Optional

from aiohttp import web, ClientSession, ClientTimeout
from multidict import CIMultiDict

# ── Configuration (file + env overrides) ───────────────────────────────────
_CONFIG_PATH = Path(os.getenv('CONFIG_PATH', 'config.json'))

_CONFIG_DEFAULTS = {
    'listen_host': '0.0.0.0',
    'listen_port': 8118,
    'allowed_regex': r'^.+\.webvpn\.stu\.edu\.cn$',
    'inject_cookies': {},
    'upstream_timeout': 30,
    'log_level': 'INFO',
}

_config = dict(_CONFIG_DEFAULTS)
if _CONFIG_PATH.exists():
    try:
        with open(_CONFIG_PATH, encoding='utf-8') as f:
            _config.update(json.load(f))
    except Exception as exc:
        print(f'[proxy] Warning: failed to load {_CONFIG_PATH}: {exc}')

# Env overrides (env wins over config file)
_config['listen_host'] = os.getenv('PROXY_HOST', _config['listen_host'])
_config['listen_port'] = int(os.getenv('PROXY_PORT', _config['listen_port']))
_config['allowed_regex'] = os.getenv('ALLOWED_REGEX', _config['allowed_regex'])
_config['upstream_timeout'] = int(os.getenv('UPSTREAM_TIMEOUT', _config['upstream_timeout']))
_config['log_level'] = os.getenv('LOG_LEVEL', _config['log_level']).upper()

LISTEN_HOST: str = _config['listen_host']
LISTEN_PORT: int = _config['listen_port']
ALLOWED_REGEX: str = _config['allowed_regex']
INJECT_COOKIES: Dict[str, str] = _config['inject_cookies']
UPSTREAM_TIMEOUT: int = _config['upstream_timeout']
LOG_LEVEL: str = _config['log_level']

# Hostname pattern for webvpn to extract real upstream.
# e.g. www-bilibili-com-s.webvpn.stu.edu.cn → www.bilibili.com
# NOTE: Not used for forwarding (keeps traffic through webvpn for 免流).
# Used only for HTML URL rewriting.
WEBVPN_HOST_RE = re.compile(r'^(.+)-s\.webvpn\.stu\.edu\.cn$')

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger('webvpn-proxy')

_ALLOWED_RE = re.compile(ALLOWED_REGEX)
_INJECTED_NAMES: set = set(INJECT_COOKIES.keys())
_SESSION: Optional[ClientSession] = None

# Runtime cookie store: captures Set-Cookie from webvpn upstream and
# re-injects them on every request.  Fixes same‑site / domain‑scoping
# issues where the browser doesn't send the webvpn session cookie for
# cross‑subdomain sub‑resource requests (fonts, JS chunks, etc.).
_WEBVPN_COOKIE_STORE: Dict[str, str] = {}


def _host_allowed(host: str) -> bool:
    hostname = host.split(':')[0] if ':' in host else host
    return bool(_ALLOWED_RE.match(hostname))


def _merge_cookie(existing: str) -> str:
    parts = [f'{k}={v}' for k, v in INJECT_COOKIES.items()]
    if not parts:
        return existing
    suffix = '; '.join(parts)
    return f'{existing}; {suffix}' if existing else suffix


async def _get_session() -> ClientSession:
    global _SESSION
    if _SESSION is None:
        _SESSION = ClientSession(auto_decompress=False)
    return _SESSION


def _extract_upstream(host: str) -> Optional[str]:
    hostname = host.split(':')[0] if ':' in host else host
    m = WEBVPN_HOST_RE.match(hostname)
    if not m:
        return None
    return m.group(1).replace('-', '.')


_BI_DOMAINS = re.compile(
    r'(https?://|//)([a-z0-9_-]+\.(?:bilibili\.com|hdslb\.com|bilicdn1\.com))'
    r'(?=[/\"\'\?\&\#\s;])',
    re.IGNORECASE,
)


def _rewrite_html(html: str, proxy_host: str) -> str:
    proxy_hostname = proxy_host.split(':')[0] if ':' in proxy_host else proxy_host

    def _replacer(m: re.Match) -> str:
        scheme = m.group(1)
        domain = m.group(2)
        webvpn_domain = domain.replace('.', '-') + '-s.webvpn.stu.edu.cn'
        return f'{scheme}{webvpn_domain}:8118'

    return _BI_DOMAINS.sub(_replacer, html)


def _cors_headers(origin: str) -> dict:
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD',
        'Access-Control-Max-Age': '86400',
    }


async def handle(request: web.Request) -> web.Response:
    host = request.host
    if not _host_allowed(host):
        log.warning('REJECT %s %s', request.method, host)
        return web.Response(status=403, text='Forbidden')

    upstream = f'http://{host}{request.path_qs}'
    real_host = _extract_upstream(host)
    log.info('PROXY %s %s  (real=%s)', request.method, upstream, real_host or '-')

    # Handle CORS preflight directly (no upstream forwarding)
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '*')
        hdrs = _cors_headers(origin)
        req_hdrs = request.headers.get('Access-Control-Request-Headers')
        if req_hdrs:
            hdrs['Access-Control-Allow-Headers'] = req_hdrs
        return web.Response(status=204, headers=hdrs)

    hdrs: CIMultiDict[str] = CIMultiDict()
    skip_req = {'host', 'connection', 'transfer-encoding', 'proxy-connection',
                'keep-alive', 'upgrade', 'te', 'trailer'}
    for k, v in request.headers.items():
        if k.lower() not in skip_req:
            hdrs.add(k, v)

    cookie = request.headers.get('Cookie', '')
    # Capture webvpn session cookie from the browser request and stash it
    # for re‑injection.  The browser sets TWFID on the portal domain but
    # may not send it to sub‑domains for sub‑resource requests.
    for part in cookie.split(';'):
        part = part.strip()
        if '=' not in part:
            continue
        k, v = part.split('=', 1)
        if k.upper() in ('TWFID', 'JSESSIONID', 'SESSION', 'TOKEN', 'AUTH'):
            if k not in _WEBVPN_COOKIE_STORE:
                _WEBVPN_COOKIE_STORE[k] = v
                log.debug('Captured webvpn cookie %s from browser', k)
    # Inject runtime‑captured cookies the browser didn't send.
    for k, v in _WEBVPN_COOKIE_STORE.items():
        if k not in cookie:
            cookie = f'{cookie}; {k}={v}' if cookie else f'{k}={v}'
            log.debug('Injected stored cookie %s for %s', k, host)
    hdrs['Cookie'] = _merge_cookie(cookie)

    body = await request.read()

    try:
        session = await _get_session()
        async with session.request(
            method=request.method,
            url=upstream,
            headers=hdrs,
            data=body,
            timeout=ClientTimeout(total=UPSTREAM_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            resp_body = await resp.read()

            if real_host and resp_body:
                ct = resp.headers.get('Content-Type', '')
                if 'text/html' in ct:
                    body_str = resp_body.decode('utf-8', errors='replace')
                    body_str = _rewrite_html(body_str, host)
                    resp_body = body_str.encode('utf-8')
                    log.debug('Rewrote HTML URLs (%d bytes)', len(resp_body))

            out_hdrs: CIMultiDict[str] = CIMultiDict()
            skip_rsp = {'transfer-encoding', 'connection'}
            strip_rsp = skip_rsp | {
                'content-security-policy',
                'content-security-policy-report-only',
                'access-control-allow-origin',
                'access-control-allow-credentials',
                'access-control-allow-methods',
                'access-control-allow-headers',
                'access-control-expose-headers',
                'access-control-max-age',
            }
            for k, v in resp.headers.items():
                kl = k.lower()
                if kl in strip_rsp or kl == 'set-cookie':
                    continue
                out_hdrs.add(k, v)

            # Add CORS headers — proxy consolidates multiple upstream
            # subdomains under one origin, so the browser sees cross-origin
            # requests that the upstream never expected.
            origin = request.headers.get('Origin', '*')
            out_hdrs.update(_cors_headers(origin))

            # Capture webvpn session cookies from upstream and re‑inject
            # them on subsequent requests (handles cross‑subdomain cookie
            # scoping that the browser can't do).
            for sc in resp.headers.getall('set-cookie', []):
                name = sc.split('=', 1)[0].strip()
                if name in _INJECTED_NAMES:
                    continue
                out_hdrs.add('Set-Cookie', sc)
                # Only store cookies that look like auth tokens (short, no
                # sub‑domain indicator) for re‑injection.
                if name.upper() in ('TWFID', 'JSESSIONID', 'SESSION', 'TOKEN', 'AUTH'):
                    val = sc.split(';', 1)[0].split('=', 1)[1] if '=' in sc else ''
                    _WEBVPN_COOKIE_STORE[name] = val
                    log.debug('Stored webvpn cookie %s for re‑injection', name)

            return web.Response(
                status=resp.status,
                body=resp_body,
                headers=out_hdrs,
            )
    except asyncio.TimeoutError:
        log.error('TIMEOUT %s', upstream)
        return web.Response(status=504, text='Gateway Timeout')
    except Exception as e:
        log.exception('UPSTREAM_ERR %s', upstream)
        return web.Response(status=502, text=f'Bad Gateway: {e}')


async def cleanup(app: web.Application) -> None:
    global _SESSION
    if _SESSION:
        await _SESSION.close()
        _SESSION = None


def main() -> None:
    app = web.Application()
    app.on_shutdown.append(cleanup)
    app.router.add_route('*', '/{path:.*}', handle)

    log.info('Listening on %s:%s', LISTEN_HOST, LISTEN_PORT)
    log.info('Allowed pattern: %s', ALLOWED_REGEX)
    log.info('Injected cookies: %s', list(_INJECTED_NAMES) or '(none)')

    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT, max_line_size=65536)


if __name__ == '__main__':
    main()
