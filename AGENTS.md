# wifis

Single-file aiohttp reverse proxy (`proxy.py`) that forwards HTTP requests matching `*.webvpn.stu.edu.cn:8118` with cookie injection/Set-Cookie stripping.

## Commands

```bash
uv sync            # install deps (creates .venv)
uv run python proxy.py          # start proxy on 0.0.0.0:8118
```

No test/lint/typecheck tooling configured. No codegen, migrations, or build step.

## Configuration

Edit `config.json` (or set env vars which override the file):

| Key (config.json) | Env var | Default | |
|---|---|---|---|
| `listen_host` | `PROXY_HOST` | `0.0.0.0` | |
| `listen_port` | `PROXY_PORT` | `8118` | |
| `allowed_regex` | `ALLOWED_REGEX` | `^.+\.webvpn\.stu\.edu\.cn$` | |
| `inject_cookies` | — | `{}` | Object of cookie key=value pairs |
| `upstream_timeout` | `UPSTREAM_TIMEOUT` | `30` | seconds |
| `log_level` | `LOG_LEVEL` | `INFO` | |

The proxy looks for `config.json` in the working directory. A different path can be set via the `CONFIG_PATH` env var.

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
