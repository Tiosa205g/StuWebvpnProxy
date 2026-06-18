# WebVPN HTTP 反向代理（Cookie 注入 + HTML 重写）

将匹配 `*.webvpn.stu.edu.cn:8118` 的 HTTP 请求反向代理到上游服务器，自动注入指定 Cookie、运行时捕获并回注入浏览器未发送的跨子域 Cookie，重写 HTML 中 B 站相关域名使其继续通过代理转发，并在返回响应时剔除同名 Set-Cookie 及上游 CSP/CORS 头。

***注意：这个项目需要运行在汕大有线网络环境（推荐主机接网线），用于将wifi到webvpn的链路转移到有线网络中，实现免流还需要本地[Technitium DNS Server](https://technitium.com/dns/)将* *.webvpn.stu.edu.cn解析到192.168.13.71上，然后自己电脑上再用[Acrylic DNS Proxy](https://mayakron.altervista.org/support/acrylic/Home.htm)本地部署dns服务器，将 *.webvpn.stu.edu.cn 解析到 主机的ip地址，将webvpn.stu.edu.cn 解析到 192.168.13.71，将wifi以及以太网的dns服务器设置成127.0.0.1上即可**

## 工作原理

```
                        DNS 解析 *.webvpn.stu.edu.cn → 代理服务器 IP
┌─────────┐   Host: foo.webvpn.stu.edu.cn:8118    ┌────────────────┐   Cookie 注入后转发    ┌──────────────┐
│ 客户端   │ ──────────────────────────────────────→ │ 代理 (8118 端口) │ ─────────────────────→ │ 上游真实服务器 │
│ (浏览器) │ ←────────────────────────────────────── │                │ ←───────────────────── │              │
└─────────┘   返回前剔除被注入的同名 Set-Cookie    └────────────────┘   原始响应              └──────────────┘
                                              │
                                              ├─ 运行时捕获浏览器未发送的跨子域 Cookie 并回注入
                                              ├─ 重写 HTML 中 B 站域名 → webvpn 代理域名
                                              └─ 剥离上游 CSP / CORS 头，替换为代理自身 CORS
```

1. 客户端 DNS 将 `*.webvpn.stu.edu.cn` 解析到部署代理的服务器 IP
2. 客户端发起 HTTP 请求（Host 头包含完整域名+端口）
3. 代理校验 Host 是否匹配 `^.+\.webvpn\.stu\.edu\.cn$`
4. 匹配则将请求原封不动转发到 `http://{host}{path_qs}`
5. 转发前自动在 Cookie 头尾部追加注入的 Cookie 键值对
6. **运行时 Cookie 捕获** — 从浏览器请求中提取 `TWFID`/`JSESSIONID`/`SESSION`/`TOKEN`/`AUTH`，若浏览器未发送（跨子域场景），则自动补回
7. 收到上游响应后：剔除与被注入 Cookie 同名的 `Set-Cookie`；剥离 `Content-Security-Policy`、`Access-Control-Allow-*` 等头；若为 HTML 且上游为 B 站相关域名，重写其中 URL 使其继续通过代理
8. 添加代理自身的 CORS 头（`Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials`），将上游 Set-Cookie 中 `TWFID`/`JSESSIONID`/`SESSION`/`TOKEN`/`AUTH` 存入运行时存储供后续回注入
9. 过滤后的响应返回给客户端

**关于 DNS 回环**：由于 DNS 已将域名指向代理自身，代理转发时必须通过其他方式解析上游真实 IP，否则会死循环。推荐方案：

- **/etc/hosts** — 在代理服务器上将 `xxx.webvpn.stu.edu.cn` 指向真实上游 IP
- **本地 DNS 服务器** — 配置内部 DNS 返回真实 IP

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

编辑 `config.json`：

```json
{
    "inject_cookies": {
        "CASTGC": "TGT-xxxxx-xxxxx",
        "SESSION": "abc123"
    }
}
```

### 运行

```bash
uv run python proxy.py
```

启动日志示例：

```
2026-06-18 12:00:00 [INFO] [STARTUP] Listening on 0.0.0.0:8118
2026-06-18 12:00:00 [INFO] [STARTUP] Allowed pattern: ^.+\.webvpn\.stu\.edu\.cn$
2026-06-18 12:00:00 [INFO] [STARTUP] Injected cookies: ['CASTGC', 'SESSION']
2026-06-18 12:00:00 [INFO] [STARTUP] Log level: INFO
```

## 配置方式

### 1. config.json（首选）

| 键               | 类型     | 默认值                         | 说明                                       |
| ---------------- | -------- | ------------------------------ | ------------------------------------------ |
| `listen_host`    | string   | `0.0.0.0`                    | 监听地址                                   |
| `listen_port`    | integer  | `8118`                       | 监听端口                                   |
| `allowed_regex`  | string   | `^.+\.webvpn\.stu\.edu\.cn$` | 允许转发的主机名正则                       |
| `inject_cookies` | object   | `{}`                         | Cookie 键值对映射                          |
| `upstream_timeout` | integer | `30`                         | 上游请求超时秒数                           |
| `log_level`     | string   | `INFO`                       | 日志级别（DEBUG / INFO / WARNING / ERROR） |

### 2. 环境变量（覆盖 config.json）

| 环境变量           | 对应键             | 默认值                         |
| ------------------ | ------------------ | ------------------------------ |
| `PROXY_HOST`     | `listen_host`    | `0.0.0.0`                    |
| `PROXY_PORT`     | `listen_port`    | `8118`                       |
| `ALLOWED_REGEX`  | `allowed_regex`  | `^.+\.webvpn\.stu\.edu\.cn$` |
| `UPSTREAM_TIMEOUT` | `upstream_timeout` | `30`                         |
| `LOG_LEVEL`      | `log_level`      | `INFO`                       |

`inject_cookies` 不支持环境变量，必须通过 `config.json` 配置。

示例：

```bash
$env:PROXY_PORT = "8080"; $env:LOG_LEVEL = "DEBUG"; uv run python proxy.py
```

配置文件默认从工作目录的 `config.json` 读取，可通过 `CONFIG_PATH` 环境变量指定其他路径。

## 运行时 Cookie 存储与回注入

浏览器同源策略限制了跨子域的 Cookie 发送。例如用户在 `www.webvpn.stu.edu.cn` 登录后拿到 `TWFID`，但当页面请求 `static.webvpn.stu.edu.cn` 或经过 webvpn 代理的 B 站资源时，该 Cookie 不会被发送，导致上游无法识别会话。

代理通过 **运行时 Cookie 存储**（`_WEBVPN_COOKIE_STORE`，进程内 Dict）解决这一问题：

1. **捕获阶段**：从每个浏览器请求的 `Cookie` 头中提取 `TWFID`/`JSESSIONID`/`SESSION`/`TOKEN`/`AUTH`，存入内存
2. **回注入阶段**：对后续请求，若浏览器未发送上述 Cookie，自动从内存中补回
3. **上游同步**：从上游响应的 `Set-Cookie` 中同步更新存储的值

这样即使浏览器因 Domain 作用域限制未发送会话 Cookie，代理也会代为注入，保证跨子域资源请求的上游认证始终有效。

## HTML URL 重写

当上游返回 `text/html` 且请求的 hostname 匹配 webvpn 格式（如 `www-bilibili-com-s.webvpn.stu.edu.cn`）时，代理自动重写响应 HTML 中 B 站相关域名（`bilibili.com`、`hdslb.com`、`bilicdn1.com`）的 URL，将其指向 webvpn 代理域名：

```
原始 HTML:  src="//static.hdslb.com/js/bundle.js"
重写后:     src="//static-hdslb-com-s.webvpn.stu.edu.cn:8118/js/bundle.js"
```

这确保浏览器加载的子资源仍通过代理转发，避免直连上游被拦截。

## Cookie 注入与剥离机制

### 注入

请求转发前，在原始 `Cookie` 头末尾追加：

```
Cookie: <客户端原有cookie>; <注入key1>=<注入value1>; <注入key2>=<注入value2>
```

如果客户端没有 Cookie，则直接设置为注入值。

### 剥离

上游响应返回时，遍历所有 `Set-Cookie` 头：

- 若 Cookie 名称与 `inject_cookies` 中任意 key 相同 → **丢弃**（防止注入值被覆盖或泄露）
- 若名称是 `TWFID`/`JSESSIONID`/`SESSION`/`TOKEN`/`AUTH` → 存入运行时存储，同时保留在响应中回传给客户端

## 上游 CORS / CSP 头处理

代理完全接管跨域策略，上游响应中的以下头部被**移除**并由代理自身 CORS 头替代：

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Expose-Headers`
- `Access-Control-Max-Age`
- `Content-Security-Policy`
- `Content-Security-Policy-Report-Only`

同时，代理直接处理 `OPTIONS` 预检请求（返回 204），无需转发到上游。

## 日志系统

### 日志等级

| 等级 | 含义 | 典型使用场景 |
|------|------|-------------|
| **DEBUG** | 调试细节，仅排查问题时开启 | Cookie 捕获/注入、Range 探测、Content-Length 修复、HTML 重写、客户端断开 |
| **INFO** | 正常运行状态 | 每个请求转发记录、启动配置 |
| **WARNING** | 意外但可恢复 | 请求被拒绝（403）、配置加载失败 |
| **ERROR** | 需要关注的错误 | 上游超时（504）、上游连接失败（502） |

### 日志类别

所有日志都带有 `[CATEGORY]` 前缀，方便 grep 过滤：

| 类别 | 级别 | 说明 |
|------|------|------|
| `[STARTUP]` | INFO | 启动时的配置信息 |
| `[PROXY]` | INFO | 每个请求的转发记录 |
| `[REJECT]` | WARNING | 请求被拒绝（返回 403） |
| `[CONFIG]` | WARNING | 配置文件加载失败 |
| `[TIMEOUT]` | ERROR | 上游超时（返回 504） |
| `[ERROR]` | ERROR | 上游连接失败（返回 502） |
| `[PROBE]` | DEBUG | 文件大小探测细节（Range/HEAD probe） |
| `[RANGE]` | DEBUG | 请求/响应的 Range 头信息 |
| `[FIX]` | DEBUG | Content-Length 自动修复细节 |
| `[COOKIE]` | DEBUG | Cookie 捕获/注入/存储细节 |
| `[REWRITE]` | DEBUG | HTML URL 重写细节 |
| `[DISCONNECT]` | DEBUG | 客户端正常断开（非错误） |

### 日志示例

```
# INFO - 正常请求
2026-06-18 12:00:01 [INFO] [PROXY] GET http://foo.webvpn.stu.edu.cn:8118/some/path  (real=www.bilibili.com)

# WARNING - 被拒绝的请求
2026-06-18 12:00:01 [WARNING] [REJECT] GET unauthorized.example.com

# ERROR - 超时
2026-06-18 12:00:02 [ERROR] [TIMEOUT] http://foo.webvpn.stu.edu.cn:8118/some/path

# ERROR - 上游错误
2026-06-18 12:00:03 [ERROR] [ERROR] UPSTREAM_ERR http://foo.webvpn.stu.edu.cn:8118/some/path

# DEBUG - 需要设置 LOG_LEVEL=DEBUG 才会显示
2026-06-18 12:00:01 [DEBUG] [COOKIE] Captured webvpn cookie TWFID from browser
2026-06-18 12:00:01 [DEBUG] [PROBE] Range probe: total file size = 2506198781 bytes for http://...
```

### 日志过滤

```bash
# 只看请求转发
grep '\[PROXY\]' proxy.log

# 只看错误
grep '\[ERROR\]\|\[TIMEOUT\]' proxy.log

# 只看被拒绝的请求
grep '\[REJECT\]' proxy.log

# 只看 Cookie 相关
grep '\[COOKIE\]' proxy.log

# 开启调试模式查看所有细节
LOG_LEVEL=DEBUG uv run python proxy.py
```

## 技术栈

- **Python >= 3.10** — 异步支持
- **aiohttp >= 3.9** — 异步 HTTP 服务器 + 客户端
- **multidict** — 多值 HTTP 头处理（保留多个 Set-Cookie）
- **uv** — Python 包管理器与虚拟环境

## 项目结构

```
wifis/
├── config.json          # 配置文件（Cookie 注入、监听端口等）
├── pyproject.toml       # 项目定义与依赖声明
├── proxy.py             # 反向代理主程序
├── README.md            # 本文件
├── AGENTS.md            # AI 辅助配置文件
├── .codegraph/          # Codegraph 索引（IDE 代码导航）
└── .venv/               # 虚拟环境（uv sync 创建）
```
