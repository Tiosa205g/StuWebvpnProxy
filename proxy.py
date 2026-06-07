#!/usr/bin/env python3
"""
WebVPN HTTP Reverse Proxy with Cookie Injection

Forwards requests matching *.webvpn.stu.edu.cn:8118, rejects all others.
Injects configured cookies into upstream requests and strips matching
Set-Cookie from upstream responses to prevent leakage.
"""

import asyncio
import os
import re
import logging
from typing import Dict, Optional

from aiohttp import web, ClientSession, ClientTimeout
from multidict import CIMultiDict

# ── Configuration ──────────────────────────────────────────────────────────
LISTEN_HOST = os.getenv('PROXY_HOST', '0.0.0.0')
LISTEN_PORT = int(os.getenv('PROXY_PORT', '8118'))

ALLOWED_REGEX = os.getenv('ALLOWED_REGEX', r'^.+\.webvpn\.stu\.edu\.cn$')

INJECT_COOKIES: Dict[str, str] = {
    # 'SESSION': 'abc123',
}

UPSTREAM_TIMEOUT = int(os.getenv('UPSTREAM_TIMEOUT', '30'))

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger('webvpn-proxy')

_ALLOWED_RE = re.compile(ALLOWED_REGEX)
_INJECTED_NAMES: set = set(INJECT_COOKIES.keys())
_SESSION: Optional[ClientSession] = None


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


async def handle(request: web.Request) -> web.Response:
    host = request.host
    if not _host_allowed(host):
        log.warning('REJECT %s %s', request.method, host)
        return web.Response(status=403, text='Forbidden')

    upstream = f'http://{host}{request.path_qs}'
    log.info('PROXY %s %s', request.method, upstream)

    hdrs: CIMultiDict[str] = CIMultiDict()
    skip_req = {'host', 'connection', 'transfer-encoding', 'proxy-connection',
                'keep-alive', 'upgrade', 'te', 'trailer'}
    for k, v in request.headers.items():
        if k.lower() not in skip_req:
            hdrs.add(k, v)

    hdrs['Cookie'] = _merge_cookie(request.headers.get('Cookie', ''))

    body = await request.read()

    try:
        session = await _get_session()
        async with session.request(
            method=request.method,
            url=upstream,
            headers=hdrs,
            data=body,
            timeout=ClientTimeout(total=UPSTREAM_TIMEOUT),
            allow_redirects=False,
        ) as resp:
            resp_body = await resp.read()

            out_hdrs: CIMultiDict[str] = CIMultiDict()
            skip_rsp = {'transfer-encoding', 'connection'}
            for k, v in resp.headers.items():
                kl = k.lower()
                if kl in skip_rsp or kl == 'set-cookie':
                    continue
                out_hdrs.add(k, v)

            injected = set(INJECT_COOKIES.keys())
            for sc in resp.headers.getall('set-cookie', []):
                if sc.split('=', 1)[0].strip() not in injected:
                    out_hdrs.add('Set-Cookie', sc)

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

    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT)


if __name__ == '__main__':
    main()
