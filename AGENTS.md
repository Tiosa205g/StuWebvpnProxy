# wifis

Single-file aiohttp reverse proxy (`proxy.py`) that forwards HTTP requests matching `*.webvpn.stu.edu.cn:8118` with cookie injection/Set-Cookie stripping.

## Commands

```bash
uv sync            # install deps (creates .venv)
uv run python proxy.py          # start proxy on 0.0.0.0:8118
```

No test/lint/typecheck tooling configured. No codegen, migrations, or build step.

## Configuration

Edit `proxy.py` top section or set env vars:

| Env var | Default | |
|---|---|---|
| `PROXY_HOST` | `0.0.0.0` | |
| `PROXY_PORT` | `8118` | |
| `ALLOWED_REGEX` | `^.+\.webvpn\.stu\.edu\.cn$` | |
| `UPSTREAM_TIMEOUT` | `30` | |
| `LOG_LEVEL` | `INFO` | |
| `INJECT_COOKIES` | dict in code | Cookie key=value pairs to inject |

## Architecture

- `proxy.py:handle` — route handler, validates host, forwards via shared `ClientSession`
- Avoids DNS loopback: upstream uses `http://{host}{path_qs}` — must resolve via `/etc/hosts` or `UPSTREAM_MAP`
- Set-Cookie stripping: drops upstream cookies whose names match injected keys
- CORS: since the proxy consolidates multiple upstream subdomains under one origin (browser sees cross-origin requests), the proxy handles OPTIONS preflight directly and adds `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials` to every response
- `pyproject.toml` deps: `aiohttp>=3.9`, `multidict>=6.0`

## Layout

```
proxy.py            # single-file app (~150 lines)
pyproject.toml      # uv-managed, Python >= 3.10
README.md           # full docs in Chinese
```
