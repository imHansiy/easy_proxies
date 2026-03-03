# Easy Proxies

[English](README.md) | 简体中文

基于 [sing-box](https://github.com/SagerNet/sing-box) 的代理节点池管理工具，支持多协议、多节点自动故障转移和负载均衡。

## 特性

### 核心功能
- **多协议支持**: VMess、VLESS、Hysteria2 (hy2://)、Shadowsocks、Trojan
- **多种传输层**: TCP、WebSocket、HTTP/2、gRPC、HTTPUpgrade
- **订阅链接支持**: 自动从订阅链接获取节点，支持 Base64、Clash YAML 等格式
- **订阅定时刷新**: 自动定时刷新订阅，支持 WebUI 手动触发（⚠️ 刷新会导致连接中断）
- **节点池模式**: 自动故障转移、负载均衡
- **命名业务池（隔离）**: 通过 `named_pools` 为不同业务分配独立入口端口，同一节点在不同池的黑名单/冷却状态互不影响
  - **GeoIP 地域路由** ⭐（可选功能）: 通过 URL 路径访问特定地域的节点池
    - 支持路径：`/jp`、`/kr`、`/us`、`/hk`、`/tw`、`/sg`、`/de`、`/gb`、`/ca`、`/au`、`/other`
    - 首次启动自动下载 GeoIP 数据库
    - 自动定期更新（可配置间隔，默认 24 小时）
    - 热重载，无需服务中断
    - 当前限制：GeoIP 地域路由仅在单池入口场景下启用
- **多端口模式**: 每个节点独立监听端口
- **混合模式**: 同时启用节点池 + 多端口（多端口与主业务池共享状态）

### 管理与监控
- **Web 监控面板**: 现代化 SPA 界面（Vue 3 + Element Plus），实时查看节点状态、延迟探测、一键导出节点
- **WebUI 设置**: 无需编辑配置文件即可修改 external_ip、probe_target 和代理认证
- **自动健康检查**: 启动时自动检测所有节点可用性，定期（5分钟）检查节点状态
- **智能节点过滤**: 自动过滤不可用节点，WebUI 和导出按延迟排序
- **域名级黑名单**: 按节点记录不可访问域名（如 CF 盾牌），支持查看黑名单列表与后台定时复查自动恢复
- **主动封控 API**: 第三方业务可调用 `POST /api/nodes/ban`，仅封禁指定业务池中的节点
- **业务池管理 UI/API**: 命名业务池可独立管理（`/api/pools` + WebUI 独立页签）
- **端口保留**: 添加/更新节点时，已有节点保持原有端口不变

### 安全与性能（新增！）
- **增强会话管理**: 安全的会话令牌，自动过期和清理机制
- **时序攻击防护**: 恒定时间密码比较，防止暴力破解攻击
- **并发控制**: 基于信号量的 goroutine 限制，防止资源耗尽
- **文件锁定**: 使用 syscall.Flock 确保配置文件并发写入安全
- **解析优化**: 订阅内容解析速度提升 50-70%
- **HTTP 连接池**: 高效的连接复用，减少 TIME_WAIT 连接
- **优雅关闭**: 正确的连接排空机制，可配置超时时间

### 部署
- **灵活配置**: 支持配置文件、节点文件、订阅链接多种方式
- **数据库持久化**: 基于 GORM 支持 PostgreSQL / MySQL / SQLite，节点、订阅、运行时配置与状态可持久化
- **数据库优先配置**: 除数据库连接信息外，其他运行配置可在 WebUI 通过数据库读写与管理
- **前后端分离**: 前端 SPA 可独立开发运行，也可构建后由后端托管 dist
- **环境变量配置**: 支持 `DB_DRIVER`、`DB_DSN`、`DATABASE_URL` 等
- **多架构支持**: Docker 镜像同时支持 AMD64 和 ARM64
- **密码保护**: WebUI 支持密码认证，安全的会话管理

## 快速开始

### 1. 配置

`config.yaml` 已不再必需。使用环境变量（或 `.env`）作为唯一配置来源。

仅环境变量启动示例（`.env`）：

```env
DB_DRIVER=postgres
DATABASE_URL=postgres://user:pass@host:5432/dbname?sslmode=require
DB_AUTO_MIGRATE=true

MANAGEMENT_LISTEN=0.0.0.0:9090
LISTENER_ADDRESS=0.0.0.0
LISTENER_PORT=2323
LISTENER_USERNAME=username
LISTENER_PASSWORD=password
SUBSCRIPTION_REFRESH_ENABLED=true
```

### 2. 运行

**Docker 方式（推荐）：**

```bash
./start.sh
```

或手动执行：

```bash
docker compose up -d
```

**本地编译运行：**

```bash
# 推荐：直接使用脚本（默认包含 with_quic 等完整标签）
./run.sh

# 或手动构建后运行
go build -tags "with_utls with_quic with_grpc with_wireguard with_gvisor" -o easy-proxies ./cmd/easy_proxies
./easy-proxies
```

**前端独立开发（前后端分离）：**

```bash
cd web
npm install
VITE_PROXY_TARGET=http://127.0.0.1:9090 npm run dev
```

构建前端产物（供后端托管）：

```bash
cd web
npm run build
```

说明：
- 后端会从 `management.frontend_dist`（默认 `web/dist`）托管 SPA。
- 若 dist 不存在，后端会返回 `503` 并提示先构建前端。

## 配置说明

### 基础配置

```yaml
mode: pool                    # 运行模式: pool (节点池)、multi-port (多端口) 或 hybrid (混合)
log_level: info               # 日志级别: debug, info, warn, error
external_ip: ""               # 外部 IP 地址，用于导出时替换 0.0.0.0（Docker 部署时建议配置）

# 订阅链接（可选，支持多个）
subscriptions:
  - "https://example.com/subscribe"

# 管理接口
management:
  enabled: true
  listen: 0.0.0.0:9090        # Web 监控面板地址
  probe_target: www.apple.com:80  # 延迟探测目标
  password: ""                # WebUI 访问密码，为空则不需要密码（可选）
  frontend_dist: ./web/dist   # SPA 前端构建目录（可选）
  # allowed_origins:
  #   - http://localhost:5173

# 数据库持久化（可选，Render 部署推荐 PostgreSQL）
storage:
  driver: "postgres" # 可选: postgres / mysql / sqlite
  dsn: "postgres://user:password@host:5432/dbname?sslmode=require"
  auto_migrate: true

# 统一入口监听
listener:
  address: 0.0.0.0
  port: 2323
  username: username
  password: password

# 多业务命名池（可选）：一个端口对应一个业务池
# named_pools:
#   - name: openai
#     listener:
#       address: 0.0.0.0
#       port: 2323
#       username: username
#       password: password
#     pool:
#       mode: sequential
#       failure_threshold: 2
#       blacklist_duration: 2h
#   - name: tiktok
#     listener:
#       address: 0.0.0.0
#       port: 2324
#       username: username
#       password: password
#     pool:
#       mode: random
#       failure_threshold: 5
#       blacklist_duration: 30m

# 节点池配置
pool:
  mode: sequential            # sequential (顺序) 或 random (随机)
  failure_threshold: 3        # 失败阈值，超过后拉黑节点
  blacklist_duration: 24h     # 拉黑时长
  domain_failure_threshold: 2   # 同一节点同一域名失败阈值
  domain_blacklist_duration: 12h # 域名级黑名单时长
  domain_recheck_interval: 10m   # 后台复查黑名单域名（成功自动移出）
  domain_recheck_timeout: 10s    # 复查超时

# 多端口模式
multi_port:
  address: 0.0.0.0
  base_port: 24000            # 起始端口，节点依次递增
  username: mpuser
  password: mppass
```

说明：
- 若未配置 `named_pools`，程序会自动基于 `listener + pool` 生成 `default` 池（完全兼容旧配置）。
- `LISTENER_*` 环境变量仍用于控制默认/主业务池。
- 业务隔离通过监听端口 / `pool_name` 完成，不依赖代理用户名。

### 运行模式详解

#### Pool 模式（单入口或命名多入口）

Pool 模式支持：
- 传统单入口（`listener`）
- 命名多入口（`named_pools`）用于业务隔离

单入口示例：

```yaml
mode: pool

listener:
  address: 0.0.0.0
  port: 2323
  username: user
  password: pass

pool:
  mode: sequential  # sequential (顺序) 或 random (随机)
  failure_threshold: 3
  blacklist_duration: 24h
  domain_failure_threshold: 2
  domain_blacklist_duration: 12h
  domain_recheck_interval: 10m
  domain_recheck_timeout: 10s
```

命名池示例：

```yaml
mode: pool

named_pools:
  - name: openai
    listener:
      address: 0.0.0.0
      port: 2323
      username: user
      password: pass
    pool:
      mode: sequential
      failure_threshold: 2
      blacklist_duration: 2h

  - name: tiktok
    listener:
      address: 0.0.0.0
      port: 2324
      username: user
      password: pass
    pool:
      mode: random
      failure_threshold: 5
      blacklist_duration: 30m
```

**适用场景：** 自动故障转移、负载均衡、跨业务风控隔离

**使用方式：** 按业务池使用对应端口，例如 `openai -> 2323`，`tiktok -> 2324`

命名池补充说明：
- 所有命名池默认共享同一份底层节点列表（节点资源可在不同业务中复用）
- 节点黑名单、手动封禁、冷却状态按 `pool_name + node` 隔离
- 业务隔离只看入口端口 / `pool_name`，不依赖代理用户名

#### Multi-Port 模式（多端口）

每个节点独立监听一个端口，精确控制使用哪个节点：

**配置格式：** 支持两种写法

```yaml
mode: multi-port  # 推荐：连字符格式
# 或
mode: multi_port  # 兼容：下划线格式
```

**完整配置示例：**

```yaml
mode: multi-port

multi_port:
  address: 0.0.0.0
  base_port: 24000  # 端口从这里开始自动递增
  username: user
  password: pass

# 使用 nodes_file 简化配置
nodes_file: nodes.txt
```

**启动时输出：**

```
📡 Proxy Links:
═══════════════════════════════════════════════════════════════
🔌 Multi-Port Mode (3 nodes):

   [24000] 台湾节点
       http://user:pass@0.0.0.0:24000
   [24001] 香港节点
       http://user:pass@0.0.0.0:24001
   [24002] 美国节点
       http://user:pass@0.0.0.0:24002
═══════════════════════════════════════════════════════════════
```

**适用场景：** 需要指定特定节点、测试节点性能

**使用方式：** 每个节点有独立的代理地址，可精确选择

#### Hybrid 模式（混合模式）

同时启用节点池和多端口模式：多端口与主业务池共享状态，不同命名池之间保持隔离。

```yaml
mode: hybrid

listener:
  address: 0.0.0.0
  port: 2323           # 节点池入口
  username: user
  password: pass

multi_port:
  address: 0.0.0.0
  base_port: 24000     # 多端口起始端口
  username: mpuser
  password: mppass

pool:
  mode: balance        # sequential (顺序)、random (随机) 或 balance (负载均衡)
  failure_threshold: 3
  blacklist_duration: 24h
```

**启动时输出：**

```
📡 Proxy Links:
═══════════════════════════════════════════════════════════════
🌐 Pool Entry Point:
   http://user:pass@0.0.0.0:2323

   Nodes in pool (3):
   • 台湾节点
   • 香港节点
   • 美国节点

🔌 Multi-Port Entry Points (3 nodes):

   [24000] 台湾节点
       http://mpuser:mppass@0.0.0.0:24000
   [24001] 香港节点
       http://mpuser:mppass@0.0.0.0:24001
   [24002] 美国节点
       http://mpuser:mppass@0.0.0.0:24002
═══════════════════════════════════════════════════════════════
```

**核心特性：**

- **主池状态共享**: Hybrid 下多端口与主业务池（`named_pools[0]` 或旧 `listener`）共享节点状态
- **命名池状态隔离**: 不同业务池的节点黑名单/封禁状态互不影响
- **端口自动重分配**: 如果端口被占用，自动分配下一个可用端口
- **灵活访问**: 节点池用于负载均衡，多端口用于直连特定节点

**适用场景：** 既需要自动故障转移，又需要直连特定节点

### 节点配置

**方式 1: 使用订阅链接（推荐）**

支持从订阅链接自动获取节点，支持多种格式：

```yaml
subscriptions:
  - "https://example.com/subscribe/v2ray"
  - "https://example.com/subscribe/clash"
```

支持的订阅格式：
- **Base64 编码**: V2Ray 标准订阅格式
- **Clash YAML**: Clash 配置文件格式
- **纯文本**: 每行一个节点 URI

**方式 2: 使用节点文件**

通过环境变量指定：

```env
NODES_FILE=nodes.txt
```

`nodes.txt` 每行一个节点 URI：

```
vless://uuid@server:443?security=reality&sni=example.com#节点名称
hysteria2://password@server:443?sni=example.com#HY2节点
ss://base64@server:8388#SS节点
trojan://password@server:443?sni=example.com#Trojan节点
vmess://base64...#VMess节点
```

**方式 3: 直接在配置文件中**

```yaml
nodes:
  - uri: "vless://uuid@server:443#节点1"
  - name: custom-name
    uri: "ss://base64@server:8388"
    port: 24001  # 可选，手动指定端口
```

> **提示**: 可以同时使用多种方式，节点会自动合并。

## 支持的协议

| 协议 | URI 格式 | 特性 |
|------|----------|------|
| VMess | `vmess://` | WebSocket、HTTP/2、gRPC、TLS |
| VLESS | `vless://` | Reality、XTLS-Vision、多传输层 |
| Hysteria2 | `hysteria2://` 或 `hy2://` | 带宽控制、混淆 |
| Shadowsocks | `ss://` | 多加密方式 |
| Trojan | `trojan://` | TLS、多传输层 |

### VMess 参数

VMess 支持两种 URI 格式：

**格式一：Base64 JSON（标准格式）**
```
vmess://base64({"v":"2","ps":"名称","add":"server","port":443,"id":"uuid","aid":0,"scy":"auto","net":"ws","type":"","host":"example.com","path":"/path","tls":"tls","sni":"example.com"})
```

**格式二：URL 格式**
```
vmess://uuid@server:port?encryption=auto&security=tls&sni=example.com&type=ws&host=example.com&path=/path#名称
```

- `net/type`: tcp, ws, h2, grpc
- `tls/security`: tls 或空
- `scy/encryption`: auto, aes-128-gcm, chacha20-poly1305 等

### VLESS 参数

```
vless://uuid@server:port?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=xxx&sid=xxx&type=tcp&flow=xtls-rprx-vision#名称
```

- `security`: none, tls, reality
- `type`: tcp, ws, http, grpc, httpupgrade
- `flow`: xtls-rprx-vision (仅 TCP)
- `fp`: 指纹 (chrome, firefox, safari 等)

### Hysteria2 参数

```
hysteria2://password@server:port?sni=example.com&insecure=0&obfs=salamander&obfs-password=xxx#名称
# 或使用简写
hy2://password@server:port?sni=example.com&insecure=0&obfs=salamander&obfs-password=xxx#名称
```

- `upMbps` / `downMbps`: 带宽限制
- `obfs`: 混淆类型
- `obfs-password`: 混淆密码

## Web 监控面板

访问 `http://localhost:9090` 查看：

- 节点状态（健康/警告/异常/拉黑）
- 实时延迟
- 活跃连接数
- 失败次数统计
- 手动探测延迟
- 解除节点拉黑
- **一键导出节点**: 导出所有可用节点的代理池 URI（格式：`http://user:pass@host:port`）
- **设置**: 点击齿轮图标修改 `external_ip` 和 `probe_target`（立即保存生效）

### WebUI 设置

点击页面顶部的 ⚙️ 齿轮图标进入设置：

| 设置项 | 说明 |
|--------|------|
| 外部 IP 地址 | 导出节点时使用的 IP 地址（替换 `0.0.0.0`） |
| 探测目标 | 健康检查目标地址（格式：`host:port`） |

启用数据库存储后，修改会立即保存到数据库，无需重启即可生效。

### 节点管理

Web UI 提供**节点管理** Tab 页，支持节点的增删改查操作：

- **添加节点**: 通过 URI 添加新节点（名称自动从 URI fragment 提取）
- **编辑节点**: 修改现有节点配置
- **删除节点**: 从配置中移除节点
- **重载配置**: 重启 sing-box 内核使更改生效（⚠️ 会中断现有连接）
- **端口保留**: 重载后已有节点保持原有端口不变

Multi-Port 模式下，端口从 `base_port` 自动分配。

**API 端点：**

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/docs` | Key-Value 极简 API 文档 |
| GET | `/api/nodes/config` | 获取所有配置节点 |
| POST | `/api/nodes/config` | 添加新节点 |
| PUT | `/api/nodes/config/:name` | 按名称更新节点 |
| DELETE | `/api/nodes/config/:name` | 按名称删除节点 |
| POST | `/api/reload` | 重载配置 |
| GET | `/api/settings` | 获取当前设置 |
| PUT | `/api/settings` | 更新设置（external_ip, probe_target） |
| GET | `/api/runtime-config` | 获取完整运行配置（数据库） |
| PUT | `/api/runtime-config` | 更新完整运行配置（数据库） |
| GET | `/api/pools` | 获取命名业务池列表 |
| POST | `/api/pools` | 创建业务池 |
| PUT | `/api/pools/:name` | 更新业务池 |
| DELETE | `/api/pools/:name` | 删除业务池 |
| POST | `/api/nodes/ban` | 按业务池主动封禁节点（`node_ip` 支持 IP 或正则） |
| GET | `/api/blacklist` | 获取节点域名黑名单列表 |

**请求示例：**

```bash
# 获取 Key-Value API 文档
curl http://localhost:9090/api/docs

# 添加节点
curl -X POST http://localhost:9090/api/nodes/config \
  -H "Content-Type: application/json" \
  -d '{"uri": "vless://uuid@server:443#节点名称"}'

# 删除节点
curl -X DELETE http://localhost:9090/api/nodes/config/节点名称

# 重载配置
curl -X POST http://localhost:9090/api/reload

# 业务池主动封禁（仅封禁指定 pool，不影响其他 pool）
curl -X POST http://localhost:9090/api/nodes/ban \
  -H "Content-Type: application/json" \
  -d '{"node_ip":"^1\\.2\\.3\\..*","pool_name":"openai","duration":"6h"}'

# 获取完整运行配置（数据库）
curl http://localhost:9090/api/runtime-config

# 获取业务池列表
curl http://localhost:9090/api/pools

# 新建业务池并立即重载
curl -X POST http://localhost:9090/api/pools \
  -H "Content-Type: application/json" \
  -d '{"pool":{"name":"openai","listener":{"address":"0.0.0.0","port":2324,"username":"user","password":"pass"},"pool":{"mode":"sequential","failure_threshold":2,"blacklist_duration":"2h","domain_failure_threshold":2,"domain_blacklist_duration":"12h","domain_recheck_interval":"10m","domain_recheck_timeout":"10s"}},"apply_now":true}'

# 更新运行配置并立即重载
curl -X PUT http://localhost:9090/api/runtime-config \
  -H "Content-Type: application/json" \
  -d '{"config":{"mode":"pool","listener":{"address":"0.0.0.0","port":2323},"named_pools":[{"name":"openai","listener":{"address":"0.0.0.0","port":2323},"pool":{"mode":"sequential","failure_threshold":2,"blacklist_duration":"2h"}}],"multi_port":{"address":"0.0.0.0","base_port":24000},"pool":{"mode":"sequential","failure_threshold":3,"blacklist_duration":"24h"},"management_enabled":true,"management_listen":"0.0.0.0:9090","management_password":"","subscription_refresh":{"enabled":true,"interval":"1h","timeout":"30s","health_check_timeout":"60s","drain_timeout":"30s","min_available_nodes":1},"geoip":{"enabled":false,"database_path":"GeoLite2-Country.mmdb","auto_update_enabled":true,"auto_update_interval":"24h"},"nodes_file":"nodes.txt","log_level":"info"},"apply_now":true}'
```

`/api/nodes/ban` 参数说明：
- `node_ip`: 可传精确 IP 或正则表达式
- `pool_name`: 目标业务池名称
- `duration`: 封禁时长，例如 `30m`、`2h`、`24h`

说明：
- 该接口受现有 Web 管理认证保护（与其他 API 相同）
- 仅封禁目标业务池中的命中节点，不影响其他业务池

`/api/runtime-config` 说明：
- 该接口用于数据库化运行配置（不包含数据库连接地址）
- `PUT` 成功后默认仅保存到数据库，设置 `apply_now=true` 可立即触发重载
- 推荐在 WebUI「节点管理」页的“运行配置（数据库）”面板直接编辑

`/api/pools` 说明：
- 业务池按 `pool_name + listener.port` 维度隔离
- `POST/PUT` 支持 `apply_now=true`
- 支持 `DELETE /api/pools/:name?apply_now=true`
- 时长字段同时支持字符串（如 `2h`、`30m`、`10s`）与纳秒整数

### 健康检查机制

程序启动时会自动对所有节点进行健康检查，之后定期检查：

- **初始检查**: 启动后立即检测所有节点的连通性
- **定期检查**: 每 5 分钟检查一次所有节点状态
- **智能过滤**: 不可用节点自动从 WebUI 和导出列表中隐藏
- **探测目标**: 通过 `management.probe_target` 配置（默认 `www.apple.com:80`）

```yaml
management:
  enabled: true
  listen: 0.0.0.0:9090
  probe_target: www.apple.com:80  # 健康检查探测目标
```

### 密码保护

为了保护节点信息安全，可以为 WebUI 设置访问密码：

```yaml
management:
  enabled: true
  listen: 0.0.0.0:9090
  password: "your_secure_password"  # 设置 WebUI 访问密码
```

- 如果 `password` 为空或不设置，则无需密码即可访问
- 设置密码后，首次访问会弹出登录界面
- 登录成功后，session 会保存 7 天

### 订阅定时刷新

支持定时自动刷新订阅链接，获取最新节点：

```yaml
subscription_refresh:
  enabled: true                 # 启用定时刷新
  interval: 1h                  # 刷新间隔（默认 1 小时）
  timeout: 30s                  # 获取订阅超时
  health_check_timeout: 60s     # 新节点健康检查超时
  drain_timeout: 30s            # 旧实例排空超时
  min_available_nodes: 1        # 最少可用节点数，低于此值不切换
```

> ⚠️ **重要提示：订阅刷新会导致连接中断**
>
> 订阅刷新时，程序会**重启 sing-box 内核**以加载新节点配置。这意味着：
>
> - **所有现有连接将被断开**
> - 正在进行的下载、流媒体播放等会中断
> - 客户端需要重新建立连接
>
> **建议：**
> - 将刷新间隔设置为较长时间（如 `1h` 或更长）
> - 避免在业务高峰期手动触发刷新
> - 如果对连接稳定性要求极高，建议关闭此功能（`enabled: false`）

**WebUI 和 API 支持：**

- WebUI 显示订阅状态（节点数、上次刷新时间、错误信息）
- WebUI 显示订阅状态（节点数、上次刷新时间、**下次自动刷新时间**、错误信息）
- 支持手动触发刷新按钮
- 订阅节点在首次加载/刷新后会自动探测可用性：失败会临时拉黑，后续探测成功会自动解除拉黑
- API 端点：
  - `GET /api/subscription/status` - 获取订阅状态
  - `POST /api/subscription/refresh` - 手动触发刷新
  - `GET /api/subscriptions` - 获取订阅列表
  - `POST /api/subscriptions` - 添加订阅
  - `PUT /api/subscriptions/:index` - 编辑订阅
  - `DELETE /api/subscriptions/:index` - 删除订阅
  - `POST /api/subscriptions/:index/refresh` - 仅刷新指定订阅
  - `GET /api/subscriptions/:index/logs` - 查看指定订阅更新日志

## 端口说明

| 端口 | 用途 |
|------|------|
| 2323（默认） | 未配置 `named_pools` 时的默认池入口 |
| `named_pools` 中配置的端口 | 业务隔离的节点池入口（pool/hybrid） |
| 9090 | Web 监控面板 |
| 24000+ | 每节点独立端口（多端口/混合模式） |

## Docker 部署

### Render + PostgreSQL（推荐）

Render 运行环境可能会重建容器，建议启用 `storage.driver + storage.dsn`。启用后会持久化：

- 配置节点（`/api/nodes/config`）
- 订阅列表（`/api/subscriptions`）
- 管理设置（`external_ip`、`probe_target`、`skip_cert_verify`）
- 运行参数（模式、监听、代理池、刷新策略、GeoIP 等）
- 运行时状态（失败计数、黑名单状态、探测可用性）

仓库已提供 Render Blueprint：`render.yaml`。

**快速部署步骤：**

1. 在 Render 里选择 **New +** -> **Blueprint**，指向本仓库
2. 保留 `render.yaml` 默认设置（会自动创建 Web Service + PostgreSQL）
3. 可选：首次导入节点可填写 `SUBSCRIPTIONS`
4. 部署完成后，访问 Render 分配的域名即可打开 WebUI

**Render 相关环境变量（已内置支持）：**

- `PORT`：Render 自动注入
- `RENDER_EXPOSE`：`management`（默认，绑定 WebUI/API 到 `PORT`）或 `proxy`
- `SUBSCRIPTIONS`：可选的初始化订阅链接（支持逗号或换行分隔）
- `DB_DRIVER` / `DB_DSN`：数据库配置
- `LISTENER_USERNAME` / `LISTENER_PASSWORD`：默认/主业务池代理认证
- `MANAGEMENT_PASSWORD`：管理面板登录密码
- `MANAGEMENT_FRONTEND_DIST` / `FRONTEND_DIST`：覆盖前端 dist 目录
- `MANAGEMENT_ALLOWED_ORIGINS` / `ALLOWED_ORIGINS`：`/api/*` 跨域允许来源（逗号或换行分隔）

> 注意：Render Web Service 只公开一个 HTTP 端口。默认推荐 `management` 暴露模式（便于健康检查和管理）。
> 若当前没有任何节点，服务会以仅管理模式启动。可在 WebUI/API 添加节点或订阅后再点击重载。

**方式一：主机网络模式（推荐）**

使用 `network_mode: host` 直接使用主机网络，无需手动映射端口：

```yaml
# docker-compose.yml
services:
  easy-proxies:
    image: ghcr.io/jasonwong1991/easy_proxies:latest
    container_name: easy-proxies
    restart: unless-stopped
    network_mode: host
    env_file:
      - ./.env
```

> **注意**: 如需文件方式引导节点，可挂载 `nodes.txt` 并设置 `NODES_FILE`。

> **优点**: 容器直接使用主机网络，所有端口自动对外开放。端口自动重分配功能可完美工作。

**方式二：端口映射模式**

手动指定需要映射的端口：

```yaml
# docker-compose.yml
services:
  easy-proxies:
    image: ghcr.io/jasonwong1991/easy_proxies:latest
    container_name: easy-proxies
    restart: unless-stopped
    env_file:
      - ./.env
    ports:
      - "2323:2323"       # 节点池/混合模式入口
      - "9091:9091"       # Web 监控面板
      - "24000-24200:24000-24200"  # 多端口/混合模式
```

> **注意**: 多端口和混合模式需要映射足够的端口范围，建议预留一些缓冲端口用于自动重分配。

## 构建

```bash
# 基础构建
go build -o easy-proxies ./cmd/easy_proxies

# 完整功能构建
go build -tags "with_utls with_quic with_grpc with_wireguard with_gvisor" -o easy-proxies ./cmd/easy_proxies
```

> 如果要使用 `hysteria2://` / `hy2://`，必须使用带 `with_quic` 的构建（推荐直接用 `./run.sh`）。

## 更新日志

### v1.1.0 (2026-02-02) - GeoIP、安全与性能版本

**🌍 GeoIP 功能（仅节点池模式）：**
- ⭐ **基于地域的节点池路由**（可选功能）
  - 通过 URL 路径访问特定地域的节点池：`/jp`、`/kr`、`/us`、`/hk`、`/tw`、`/sg`、`/de`、`/gb`、`/ca`、`/au`、`/other`
  - 节点池模式下自动识别所有节点的 IP 地理位置
  - Dashboard 显示各地域节点数量
- ⭐ **自动 GeoIP 数据库管理**
  - 首次启动自动从 GitHub 下载（约 9MB）
  - 定期自动更新（可配置间隔，默认 24 小时）
  - 热重载，无需服务中断
  - MMDB 格式验证和完整性检查
- ⭐ **hy2:// 协议支持**
  - 支持 Hysteria2 简写形式（hy2://）
  - 向后兼容 hysteria2://

**🔒 安全增强：**
- 增强的会话管理，支持自动过期（24小时 TTL）和每小时清理
- 恒定时间密码比较，防止时序攻击
- 基于信号量的并发控制（CPU×4 个 goroutine，最少 10 个）
- 文件锁定机制，确保配置文件并发写入安全

**⚡ 性能改进：**
- 订阅内容解析速度提升 50-70%，优化 base64 检测算法
- HTTP 连接池（最大空闲连接 100，每主机 10）减少 TIME_WAIT 连接
- 响应大小限制（10MB）防止内存耗尽
- 优雅关闭机制，30秒超时和2秒连接排空

**🔧 技术细节：**
- 新增自动 GeoIP 数据库下载和更新机制
- 实现 GeoIP 数据库热重载功能
- 新增 `golang.org/x/sync/semaphore` 用于并发控制
- 实现 `syscall.Flock` Unix 文件锁定
- 配置自定义 HTTP transport 和优化的超时设置
- 无破坏性变更 - 完全向后兼容

**📝 升级说明：**
- GeoIP 是节点池模式的可选功能（默认禁用）
- 启用后 GeoIP 数据库将自动下载
- 升级后现有会话将失效（用户需要重新登录）
- 无需修改配置文件
- 建议在低流量时段重启服务

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=jasonwong1991/easy_proxies&type=Date)](https://star-history.com/#jasonwong1991/easy_proxies&Date)

## 许可证

MIT License
