# WebVPN HTTP 反向代理（Cookie 注入）

将匹配 `*.webvpn.stu.edu.cn:8118` 的 HTTP 请求反向代理到上游服务器，自动注入指定 Cookie，并在返回响应时剔除同名 Set-Cookie 以防止注入值泄露。不匹配的请求直接返回 403。

***注意：这个项目需要运行在汕大有线网络环境（推荐主机接网线），用于将wifi到webvpn的链路转移到有线网络中，实现免流还需要本地[Technitium DNS Server](https://technitium.com/dns/)将* *.webvpn.stu.edu.cn解析到192.168.13.71上，然后自己电脑上再用[Acrylic DNS Proxy](https://mayakron.altervista.org/support/acrylic/Home.htm)本地部署dns服务器，将 *.webvpn.stu.edu.cn 解析到 主机的ip地址，将webvpn.stu.edu.cn 解析到 192.168.13.71，将wifi以及以太网的dns服务器设置成127.0.0.1上即可**

## 工作原理

```
                        DNS 解析 *.webvpn.stu.edu.cn → 代理服务器 IP
┌─────────┐   Host: foo.webvpn.stu.edu.cn:8118    ┌────────────────┐   Cookie 注入后转发    ┌──────────────┐
│ 客户端   │ ──────────────────────────────────────→ │ 代理 (8118 端口) │ ─────────────────────→ │ 上游真实服务器 │
│ (浏览器) │ ←────────────────────────────────────── │                │ ←───────────────────── │              │
└─────────┘   返回前剔除被注入的同名 Set-Cookie    └────────────────┘   原始响应              └──────────────┘
```

1. 客户端 DNS 将 `*.webvpn.stu.edu.cn` 解析到部署代理的服务器 IP
2. 客户端发起 HTTP 请求（Host 头包含完整域名+端口）
3. 代理校验 Host 是否匹配 `^.+\.webvpn\.stu\.edu\.cn$`
4. 匹配则将请求原封不动转发到 `http://{host}{path_qs}`
5. 转发前自动在 Cookie 头尾部追加注入的 Cookie 键值对
6. 上游响应返回后，遍历所有 `Set-Cookie`，剔除与被注入 Cookie 同名的条目
7. 过滤后的响应返回给客户端

**关于 DNS 回环**：由于 DNS 已将域名指向代理自身，代理转发时必须通过其他方式解析上游真实 IP，否则会死循环。推荐方案：

- **/etc/hosts** — 在代理服务器上将 `xxx.webvpn.stu.edu.cn` 指向真实上游 IP
- **本地 DNS 服务器** — 配置内部 DNS 返回真实 IP
- **UPSTREAM_MAP 硬编码**（可选，见下方进阶）

## 快速开始

### 前置要求

- Python >= 3.10
- [uv](https://docs.astral.sh/uv/)（推荐）或 pip

### 安装

```bash
# 进入项目目录
cd wifis

# 使用 uv 自动创建虚拟环境并安装依赖
uv sync

# 激活虚拟环境（Windows PowerShell）
.venv\Scripts\Activate.ps1
# 或 Linux/macOS
source .venv/bin/activate
```

### 配置要注入的 Cookie

编辑 `proxy.py`，修改 `INJECT_COOKIES` 字典：

```python
INJECT_COOKIES: Dict[str, str] = {
    'CASTGC': 'TGT-xxxxx-xxxxx',
    'SESSION': 'abc123',
    # 添加更多 Cookie...
}
```

### 运行

```bash
uv run python proxy.py
```

启动日志示例：

```
2026-06-07 12:00:00 [INFO] Listening on 0.0.0.0:8118
2026-06-07 12:00:00 [INFO] Allowed pattern: ^.+\.webvpn\.stu\.edu\.cn$
2026-06-07 12:00:00 [INFO] Injected cookies: ['CASTGC', 'SESSION']
```

## 配置方式

### 1. 环境变量

| 变量                 | 默认值                         | 说明                                       |
| -------------------- | ------------------------------ | ------------------------------------------ |
| `PROXY_HOST`       | `0.0.0.0`                    | 监听地址                                   |
| `PROXY_PORT`       | `8118`                       | 监听端口                                   |
| `ALLOWED_REGEX`    | `^.+\.webvpn\.stu\.edu\.cn$` | 允许转发的主机名正则                       |
| `UPSTREAM_TIMEOUT` | `30`                         | 上游请求超时秒数                           |
| `LOG_LEVEL`        | `INFO`                       | 日志级别（DEBUG / INFO / WARNING / ERROR） |

示例：

```bash
$env:PROXY_PORT = "8080"; $env:LOG_LEVEL = "DEBUG"; uv run python proxy.py
```

### 2. 直接修改 proxy.py

`INJECT_COOKIES` 字典和环境变量的默认值都可以在文件顶部直接修改。

## Cookie 注入与剥离机制

### 注入

请求转发前，在原始 `Cookie` 头末尾追加：

```
Cookie: <客户端原有cookie>; <注入key1>=<注入value1>; <注入key2>=<注入value2>
```

如果客户端没有 Cookie，则直接设置为注入值。

### 剥离

上游响应返回时，遍历所有 `Set-Cookie` 头，若 Cookie 名称（`=` 左侧）与 `INJECT_COOKIES` 中任意 key 相同，则**丢弃该 Set-Cookie 条目**，不回传给客户端。

这样做有两个目的：

1. **防泄露** — 注入的 Cookie 值不会暴露给客户端
2. **防覆盖** — 上游服务器若返回同名 Set-Cookie（如刷新令牌），不会污染客户端的本地 Cookie 存储

## 进阶：硬编码上游地址（避免 DNS 回环）

如果不想配置 `/etc/hosts`，可直接在转发时替换上游地址。修改 `proxy.py` 中 `handle` 函数：

```python
UPSTREAM_MAP = {
    'foo.webvpn.stu.edu.cn': '192.168.1.100',
    'bar.webvpn.stu.edu.cn': '192.168.1.101',
}

async def handle(request: web.Request) -> web.Response:
    host = request.host
    if not _host_allowed(host):
        return web.Response(status=403, text='Forbidden')

    hostname = host.split(':')[0] if ':' in host else host
    upstream_host = UPSTREAM_MAP.get(hostname, hostname)
    upstream = f'http://{upstream_host}:8118{request.path_qs}'
    # ... 后续不变
```

## 日志字段说明

```
2026-06-07 12:00:01 [INFO] PROXY GET http://foo.webvpn.stu.edu.cn:8118/some/path
2026-06-07 12:00:01 [WARNING] REJECT GET unauthorized.example.com
2026-06-07 12:00:02 [ERROR] TIMEOUT http://foo.webvpn.stu.edu.cn:8118/some/path
2026-06-07 12:00:03 [ERROR] UPSTREAM_ERR http://foo.webvpn.stu.edu.cn:8118/some/path
```

- `PROXY` — 请求已匹配并正在转发
- `REJECT` — 请求被拒绝（返回 403）
- `TIMEOUT` — 上游超时（返回 504）
- `UPSTREAM_ERR` — 上游连接失败（返回 502）

## 技术栈

- **Python >= 3.10** — 异步支持
- **aiohttp >= 3.9** — 异步 HTTP 服务器 + 客户端
- **multidict** — 多值 HTTP 头处理（保留多个 Set-Cookie）
- **uv** — Python 包管理器与虚拟环境

## 项目结构

```
wifis/
├── pyproject.toml      # 项目定义与依赖声明
├── proxy.py            # 反向代理主程序
├── README.md           # 本文件
└── .venv/              # 虚拟环境（uv sync 创建）
```
