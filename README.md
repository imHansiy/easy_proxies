# Easy Proxies

English | [简体中文](README_ZH.md)

A proxy node pool management tool based on [sing-box](https://github.com/SagerNet/sing-box), supporting multiple protocols, automatic failover, and load balancing.

## Features

### Core Features
- **Multi-Protocol Support**: VMess, VLESS, Hysteria2 (hy2://), Shadowsocks, Trojan
- **Multiple Transports**: TCP, WebSocket, HTTP/2, gRPC, HTTPUpgrade
- **Subscription Support**: Auto-fetch nodes from subscription links (Base64, Clash YAML, etc.)
- **Subscription Auto-Refresh**: Automatic periodic refresh with WebUI manual trigger (⚠️ causes connection interruption)
- **Pool Mode**: Automatic failover and load balancing
- **Named Pools (Business Isolation)**: Multiple business entry pools by port (`named_pools`), each pool keeps independent blacklist/cooldown state for the same node
  - **GeoIP Region Routing** ⭐ (Optional): Access region-specific node pools via URL paths
    - `/jp` `/kr` `/us` `/hk` `/tw` `/sg` `/de` `/gb` `/ca` `/au` `/other`
    - Auto-download GeoIP database on first startup
    - Automatic periodic updates (configurable, default 24h)
    - Hot-reload without service interruption
    - Current limitation: GeoIP region routing is available when using a single pool entry
- **Multi-Port Mode**: Each node listens on independent port
- **Hybrid Mode**: Pool + Multi-Port simultaneously (`multi-port` shares state with the primary pool)

### Management & Monitoring
- **Web Dashboard**: Modern SPA dashboard (Vue 3 + Element Plus), real-time node status, latency probing, one-click export
- **WebUI Settings**: Modify external_ip, probe_target, and proxy auth without editing config files
- **Auto Health Check**: Initial check on startup, periodic checks every 5 minutes
- **Smart Node Filtering**: Auto-hide unavailable nodes, sort by latency
- **Domain-Level Blacklist**: Track blocked domains per node (e.g. Cloudflare-protected targets), with blacklist APIs and scheduled auto-recheck recovery
- **Active Ban API**: Business systems can call `POST /api/nodes/ban` to ban only one target pool without impacting other pools
- **Pool Manager UI/API**: Named business pools are managed independently (`/api/pools` + dedicated WebUI tab)
- **Port Preservation**: Existing nodes keep their ports when adding/updating nodes

### Security & Performance (New!)
- **Enhanced Session Management**: Secure session tokens with automatic expiration and cleanup
- **Timing Attack Protection**: Constant-time password comparison to prevent brute-force attacks
- **Concurrency Control**: Semaphore-based goroutine limiting prevents resource exhaustion
- **File Locking**: Safe concurrent configuration writes with syscall.Flock
- **Optimized Parsing**: 50-70% faster subscription content parsing
- **HTTP Connection Pooling**: Efficient connection reuse reduces TIME_WAIT connections
- **Graceful Shutdown**: Proper connection draining with configurable timeout

### Deployment
- **Flexible Configuration**: Config file, node file, subscription links
- **Database Persistence**: GORM-based storage with PostgreSQL / MySQL / SQLite for nodes, subscriptions, runtime settings, and runtime state
- **Database-First Runtime Config**: All runtime config (except DB connection settings) can be managed in WebUI and persisted in DB
- **Frontend/Backend Separation**: Vue SPA can run independently (dev server + API proxy) or be served by backend from dist
- **Environment Variables**: Supports `DB_DRIVER`, `DB_DSN`, `DATABASE_URL`, etc.
- **Multi-Architecture**: Docker images for both AMD64 and ARM64
- **Password Protection**: WebUI authentication with secure session management

## Quick Start

### 1. Configuration

`config.yaml` is no longer required. Use environment variables (or `.env`) as the source of truth.

Environment-only bootstrap example (`.env`):

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

### 2. Run

**Docker (Recommended):**

```bash
./start.sh
```

Or manually:

```bash
docker compose up -d
```

**Local Build:**

```bash
# Recommended: use helper script (includes full tags with QUIC by default)
./run.sh

# Or build manually
go build -tags "with_utls with_quic with_grpc with_wireguard with_gvisor" -o easy-proxies ./cmd/easy_proxies
./easy-proxies
```

**Frontend Development (Separated):**

```bash
cd web
npm install
VITE_PROXY_TARGET=http://127.0.0.1:9090 npm run dev
```

Build frontend assets for backend serving:

```bash
cd web
npm run build
```

Notes:
- Backend serves SPA from `management.frontend_dist` (default `web/dist`).
- If dist is missing, backend falls back to the embedded legacy page.

## Configuration

### Basic Config

```yaml
mode: pool                    # Mode: pool, multi-port, or hybrid
log_level: info               # Log level: debug, info, warn, error
external_ip: ""               # External IP for export (recommended for Docker)

# Subscription URLs (optional, multiple supported)
subscriptions:
  - "https://example.com/subscribe"

# Management Interface
management:
  enabled: true
  listen: 0.0.0.0:9090        # Web dashboard address
  probe_target: www.apple.com:80  # Latency probe target
  password: ""                # WebUI password (optional)
  frontend_dist: ./web/dist   # SPA dist directory (optional)
  # allowed_origins:
  #   - http://localhost:5173

# Unified Entry Listener
listener:
  address: 0.0.0.0
  port: 2323
  username: username
  password: password

# Named pools (optional): one port per business pool
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

# Pool Settings
pool:
  mode: sequential            # sequential or random
  failure_threshold: 3        # Failures before blacklist
  blacklist_duration: 24h     # Blacklist duration

# Multi-Port Mode
multi_port:
  address: 0.0.0.0
  base_port: 24000            # Starting port, auto-increment
  username: mpuser
  password: mppass
```

Notes:
- If `named_pools` is omitted, the app auto-creates a `default` pool from `listener` + `pool` (backward compatible).
- `LISTENER_*` environment variables still control the primary/default pool.
- Business segregation is done by listener port / `pool_name`, not by proxy username.

### Operating Modes

#### Pool Mode (Single or Named Pools)

Pool mode supports:
- Single entry pool (legacy `listener`)
- Multiple named entry pools (`named_pools`) for business isolation

Single entry example:

```yaml
mode: pool

listener:
  address: 0.0.0.0
  port: 2323
  username: user
  password: pass

pool:
  mode: sequential  # sequential or random
  failure_threshold: 3
  blacklist_duration: 24h
```

Named pools example:

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

**Use Case:** Automatic failover, load balancing, and cross-business risk isolation

**Usage:** Use the corresponding port per business pool, e.g. `http://user:pass@localhost:2323` for `openai` and `http://user:pass@localhost:2324` for `tiktok`

Named pool notes:
- All named pools share the same underlying node list by default
- Blacklist/manual ban/cooldown state is isolated by `pool_name + node`
- Business isolation is done by listener port / `pool_name`, not by proxy username

#### Multi-Port Mode

Each node listens on its own port for precise control:

**Config Format:** Two syntaxes supported

```yaml
mode: multi-port  # Recommended: hyphen format
# or
mode: multi_port  # Compatible: underscore format
```

**Full Example:**

```yaml
mode: multi-port

multi_port:
  address: 0.0.0.0
  base_port: 24000  # Ports auto-increment from here
  username: user
  password: pass

nodes_file: nodes.txt
```

**Startup Output:**

```
📡 Proxy Links:
═══════════════════════════════════════════════════════════════
🔌 Multi-Port Mode (3 nodes):

   [24000] Taiwan Node
       http://user:pass@0.0.0.0:24000
   [24001] Hong Kong Node
       http://user:pass@0.0.0.0:24001
   [24002] US Node
       http://user:pass@0.0.0.0:24002
═══════════════════════════════════════════════════════════════
```

**Use Case:** Specific node selection, performance testing

**Usage:** Each node has independent proxy address

#### Hybrid Mode

Combines Pool and Multi-Port modes: Multi-Port shares state with the primary pool, while named pools remain isolated from each other.

```yaml
mode: hybrid

listener:
  address: 0.0.0.0
  port: 2323           # Pool entry point
  username: user
  password: pass

multi_port:
  address: 0.0.0.0
  base_port: 24000     # Multi-port starting port
  username: mpuser
  password: mppass

pool:
  mode: balance        # sequential, random, or balance
  failure_threshold: 3
  blacklist_duration: 24h
```

**Startup Output:**

```
📡 Proxy Links:
═══════════════════════════════════════════════════════════════
🌐 Pool Entry Point:
   http://user:pass@0.0.0.0:2323

   Nodes in pool (3):
   • Taiwan Node
   • Hong Kong Node
   • US Node

🔌 Multi-Port Entry Points (3 nodes):

   [24000] Taiwan Node
       http://mpuser:mppass@0.0.0.0:24000
   [24001] Hong Kong Node
       http://mpuser:mppass@0.0.0.0:24001
   [24002] US Node
       http://mpuser:mppass@0.0.0.0:24002
═══════════════════════════════════════════════════════════════
```

**Key Features:**

- **Primary Pool Shared State**: In hybrid mode, Multi-Port shares state with the primary pool (`named_pools[0]` or legacy `listener`)
- **Named Pool Isolation**: Different named pools keep independent node blacklist/ban state
- **Auto Port Reassignment**: If a port is occupied, automatically assigns next available port
- **Flexible Access**: Use Pool for load balancing, Multi-Port for specific node access

**Use Case:** Need both automatic failover AND direct node access

### Node Configuration

**Method 1: Subscription Links (Recommended)**

Auto-fetch nodes from subscription URLs:

```yaml
subscriptions:
  - "https://example.com/subscribe/v2ray"
  - "https://example.com/subscribe/clash"
```

Supported formats:
- **Base64 Encoded**: V2Ray standard subscription
- **Clash YAML**: Clash config format
- **Plain Text**: One URI per line

**Method 2: Node File**

Specify via environment variable:

```env
NODES_FILE=nodes.txt
```

`nodes.txt` - one URI per line:

```
vless://uuid@server:443?security=reality&sni=example.com#NodeName
hysteria2://password@server:443?sni=example.com#HY2Node
ss://base64@server:8388#SSNode
trojan://password@server:443?sni=example.com#TrojanNode
vmess://base64...#VMessNode
```

**Method 3: Direct in Config**

```yaml
nodes:
  - uri: "vless://uuid@server:443#Node1"
  - name: custom-name
    uri: "ss://base64@server:8388"
    port: 24001  # Optional, manual port
```

> **Tip**: Multiple methods can be combined, nodes are merged automatically.

## Supported Protocols

| Protocol | URI Format | Features |
|----------|------------|----------|
| VMess | `vmess://` | WebSocket, HTTP/2, gRPC, TLS |
| VLESS | `vless://` | Reality, XTLS-Vision, multiple transports |
| Hysteria2 | `hysteria2://` or `hy2://` | Bandwidth control, obfuscation |
| Shadowsocks | `ss://` | Multiple ciphers |
| Trojan | `trojan://` | TLS, multiple transports |

### VMess Parameters

VMess supports two URI formats:

**Format 1: Base64 JSON (Standard)**
```
vmess://base64({"v":"2","ps":"Name","add":"server","port":443,"id":"uuid","aid":0,"scy":"auto","net":"ws","type":"","host":"example.com","path":"/path","tls":"tls","sni":"example.com"})
```

**Format 2: URL Format**
```
vmess://uuid@server:port?encryption=auto&security=tls&sni=example.com&type=ws&host=example.com&path=/path#Name
```

- `net/type`: tcp, ws, h2, grpc
- `tls/security`: tls or empty
- `scy/encryption`: auto, aes-128-gcm, chacha20-poly1305, etc.

### VLESS Parameters

```
vless://uuid@server:port?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=xxx&sid=xxx&type=tcp&flow=xtls-rprx-vision#Name
```

- `security`: none, tls, reality
- `type`: tcp, ws, http, grpc, httpupgrade
- `flow`: xtls-rprx-vision (TCP only)
- `fp`: fingerprint (chrome, firefox, safari, etc.)

### Hysteria2 Parameters

```
hysteria2://password@server:port?sni=example.com&insecure=0&obfs=salamander&obfs-password=xxx#Name
# Or use shorthand
hy2://password@server:port?sni=example.com&insecure=0&obfs=salamander&obfs-password=xxx#Name
```

- `upMbps` / `downMbps`: Bandwidth limits
- `obfs`: Obfuscation type
- `obfs-password`: Obfuscation password

## Web Dashboard

Access `http://localhost:9090` to view:

- Node status (Healthy/Warning/Error/Blacklisted)
- Real-time latency
- Active connections
- Failure count
- Manual latency probing
- Release blacklisted nodes
- **One-click Export**: Export all available nodes as proxy URIs (`http://user:pass@host:port`)
- **Settings**: Click the gear icon to modify `external_ip` and `probe_target` (changes saved immediately)

### WebUI Settings

Click the ⚙️ gear icon in the header to access settings:

| Setting | Description |
|---------|-------------|
| External IP | IP address used in exported proxy URIs (replaces `0.0.0.0`) |
| Probe Target | Health check target address (format: `host:port`) |

With DB storage enabled, changes are saved to the database immediately and take effect without restart.

### Node Management

The Web UI provides a **Node Management** tab for CRUD operations on proxy nodes:

- **Add Node**: Add new proxy nodes via URI (name auto-extracted from URI fragment)
- **Edit Node**: Modify existing node configuration
- **Delete Node**: Remove nodes from configuration
- **Reload Config**: Apply changes by restarting sing-box core (⚠️ interrupts connections)
- **Port Preservation**: Existing nodes keep their assigned ports after reload

In Multi-Port mode, ports are automatically allocated from `base_port`.

**API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/docs` | Minimal Key-Value API document |
| GET | `/api/nodes/config` | List all configured nodes |
| POST | `/api/nodes/config` | Add a new node |
| PUT | `/api/nodes/config/:name` | Update node by name |
| DELETE | `/api/nodes/config/:name` | Delete node by name |
| POST | `/api/reload` | Reload configuration |
| GET | `/api/settings` | Get current settings |
| PUT | `/api/settings` | Update settings (external_ip, probe_target) |
| GET | `/api/runtime-config` | Get full runtime config (database) |
| PUT | `/api/runtime-config` | Update full runtime config (database) |
| GET | `/api/pools` | List named business pools |
| POST | `/api/pools` | Create business pool |
| PUT | `/api/pools/:name` | Update business pool |
| DELETE | `/api/pools/:name` | Delete business pool |
| POST | `/api/nodes/ban` | Ban nodes in a specific pool (`node_ip` supports IP or regex) |
| GET | `/api/blacklist` | Get node domain blacklist list |

**Request/Response Example:**

```bash
# Minimal Key-Value API docs
curl http://localhost:9090/api/docs

# Add node
curl -X POST http://localhost:9090/api/nodes/config \
  -H "Content-Type: application/json" \
  -d '{"uri": "vless://uuid@server:443#NodeName"}'

# Delete node
curl -X DELETE http://localhost:9090/api/nodes/config/NodeName

# Reload config
curl -X POST http://localhost:9090/api/reload

# Active ban for a business pool (does not affect other pools)
curl -X POST http://localhost:9090/api/nodes/ban \
  -H "Content-Type: application/json" \
  -d '{"node_ip":"^1\\.2\\.3\\..*","pool_name":"openai","duration":"6h"}'

# Get full runtime config (database)
curl http://localhost:9090/api/runtime-config

# List named pools
curl http://localhost:9090/api/pools

# Create one pool and reload immediately
curl -X POST http://localhost:9090/api/pools \
  -H "Content-Type: application/json" \
  -d '{"pool":{"name":"openai","listener":{"address":"0.0.0.0","port":2324,"username":"user","password":"pass"},"pool":{"mode":"sequential","failure_threshold":2,"blacklist_duration":"2h","domain_failure_threshold":2,"domain_blacklist_duration":"12h","domain_recheck_interval":"10m","domain_recheck_timeout":"10s"}},"apply_now":true}'

# Update runtime config and reload immediately
curl -X PUT http://localhost:9090/api/runtime-config \
  -H "Content-Type: application/json" \
  -d '{"config":{"mode":"pool","listener":{"address":"0.0.0.0","port":2323},"named_pools":[{"name":"openai","listener":{"address":"0.0.0.0","port":2323},"pool":{"mode":"sequential","failure_threshold":2,"blacklist_duration":"2h"}}],"multi_port":{"address":"0.0.0.0","base_port":24000},"pool":{"mode":"sequential","failure_threshold":3,"blacklist_duration":"24h"},"management_enabled":true,"management_listen":"0.0.0.0:9090","management_password":"","subscription_refresh":{"enabled":true,"interval":"1h","timeout":"30s","health_check_timeout":"60s","drain_timeout":"30s","min_available_nodes":1},"geoip":{"enabled":false,"database_path":"GeoLite2-Country.mmdb","auto_update_enabled":true,"auto_update_interval":"24h"},"nodes_file":"nodes.txt","log_level":"info"},"apply_now":true}'
```

`/api/nodes/ban` fields:
- `node_ip`: exact IP or regular expression
- `pool_name`: target business pool name
- `duration`: ban duration, e.g. `30m`, `2h`, `24h`

Notes:
- This endpoint uses the same Web management authentication as other APIs
- It only bans matched nodes in the specified pool and does not affect other pools

`/api/runtime-config` notes:
- This endpoint manages database-backed runtime config (excluding DB connection settings)
- `PUT` saves to DB by default; set `apply_now=true` to trigger reload immediately
- You can edit it in WebUI under the manage tab: "Runtime Config (Database)"

`/api/pools` notes:
- Business pools are isolated by `pool_name + listener.port`
- `POST/PUT` supports `apply_now=true`
- `DELETE /api/pools/:name?apply_now=true` is supported
- Duration fields support both duration strings (`2h`, `30m`, `10s`) and integer nanoseconds

### Health Check Mechanism

Auto health check on startup, then periodic checks:

- **Initial Check**: Test all nodes immediately after startup
- **Periodic Check**: Every 5 minutes
- **Smart Filtering**: Hide unavailable nodes from WebUI and export
- **Probe Target**: Configure via `management.probe_target` (default `www.apple.com:80`)

```yaml
management:
  enabled: true
  listen: 0.0.0.0:9090
  probe_target: www.apple.com:80  # Health check target
```

### Password Protection

Protect node information with WebUI password:

```yaml
management:
  enabled: true
  listen: 0.0.0.0:9090
  password: "your_secure_password"
```

- Empty or unset `password` means no authentication required
- Login prompt appears on first access when password is set
- Session persists for 7 days after login

### Subscription Auto-Refresh

Automatic periodic subscription refresh:

```yaml
subscription_refresh:
  enabled: true                 # Enable auto-refresh
  interval: 1h                  # Refresh interval (default 1 hour)
  timeout: 30s                  # Fetch timeout
  health_check_timeout: 60s     # New node health check timeout
  drain_timeout: 30s            # Old instance drain timeout
  min_available_nodes: 1        # Minimum available nodes required
```

> ⚠️ **Important: Subscription refresh causes connection interruption**
>
> During subscription refresh, the program **restarts the sing-box core** to load new node configuration. This means:
>
> - **All existing connections will be disconnected**
> - Ongoing downloads, streaming, etc. will be interrupted
> - Clients need to reconnect
>
> **Recommendations:**
> - Set longer refresh intervals (e.g., `1h` or more)
> - Avoid manual refresh during peak usage
> - Disable if connection stability is critical (`enabled: false`)

**WebUI and API Support:**

- WebUI shows subscription status (node count, last refresh time, **next auto-refresh time**, errors)
- Manual refresh button available
- Subscription nodes are auto-probed on initial load/refresh: failed nodes are temporarily blacklisted and automatically unblacklisted after a successful probe
- API endpoints:
  - `GET /api/subscription/status` - Get subscription status
  - `POST /api/subscription/refresh` - Trigger manual refresh
  - `GET /api/subscriptions` - Get subscription list
  - `POST /api/subscriptions` - Add subscription
  - `PUT /api/subscriptions/:index` - Edit subscription
  - `DELETE /api/subscriptions/:index` - Delete subscription
  - `POST /api/subscriptions/:index/refresh` - Refresh one subscription only
  - `GET /api/subscriptions/:index/logs` - Get update logs for one subscription

## Ports

| Port | Purpose |
|------|---------|
| 2323 (default) | Default pool entry when `named_pools` is not configured |
| configured `named_pools` ports | Business-isolated pool entries (Pool/Hybrid mode) |
| 9090 | Web dashboard |
| 24000+ | Per-node ports (Multi-Port/Hybrid mode) |

## Docker Deployment

### Render + PostgreSQL (Recommended)

This repo includes a Render Blueprint at `render.yaml`.

With DB storage enabled, nodes, subscriptions, runtime settings, and runtime state are persisted in the database.

Quick steps:

1. In Render, choose **New +** -> **Blueprint** and connect this repository
2. Keep default blueprint resources (Web Service + PostgreSQL)
3. Optional bootstrap: set `SUBSCRIPTIONS` for first-time node import
4. Deploy and open the Render service URL for WebUI/API

Render-related env vars supported by the app:

- `PORT`: injected by Render
- `RENDER_EXPOSE`: `management` (default, binds WebUI/API to `PORT`) or `proxy`
- `SUBSCRIPTIONS`: optional bootstrap URLs (comma or newline separated)
- `DB_DRIVER` / `DB_DSN`: database persistence
- `LISTENER_USERNAME` / `LISTENER_PASSWORD`: proxy auth for the default/primary pool
- `MANAGEMENT_PASSWORD`: WebUI login password
- `MANAGEMENT_FRONTEND_DIST` / `FRONTEND_DIST`: override frontend dist directory
- `MANAGEMENT_ALLOWED_ORIGINS` / `ALLOWED_ORIGINS`: comma/newline separated CORS origins for `/api/*`

> Note: Render Web Services expose only one public HTTP port. `management` mode is recommended by default for health checks and operations.
> If no nodes are present yet, the service starts in monitor-only mode. Add nodes/subscriptions via WebUI/API and click reload.

**Method 1: Host Network Mode (Recommended)**

Use `network_mode: host` for direct host network access:

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

> **Note**: If you want file-based node bootstrap, mount `nodes.txt` and set `NODES_FILE`.

> **Advantage**: Container uses host network directly, all ports exposed automatically. Auto port reassignment works seamlessly.

**Method 2: Port Mapping Mode**

Manually specify port mappings:

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
      - "2323:2323"       # Pool/Hybrid mode entry
      - "9091:9091"       # Web dashboard
      - "24000-24200:24000-24200"  # Multi-Port/Hybrid mode
```

> **Note**: Multi-Port and Hybrid modes require mapping the port range. Map enough ports for your nodes plus some buffer for auto-reassignment.

## Building

```bash
# Basic build
go build -o easy-proxies ./cmd/easy_proxies

# Full feature build
go build -tags "with_utls with_quic with_grpc with_wireguard with_gvisor" -o easy-proxies ./cmd/easy_proxies
```

> `hysteria2://` / `hy2://` requires a build with `with_quic` enabled (using `./run.sh` is recommended).

## Changelog

### v1.1.0 (2026-02-02) - GeoIP, Security & Performance Release

**🌍 GeoIP Features (Pool Mode Only):**
- ⭐ **Region-Based Pool Routing** (Optional Feature)
  - Access region-specific node pools via URL paths: `/jp`, `/kr`, `/us`, `/hk`, `/tw`, `/sg`, `/de`, `/gb`, `/ca`, `/au`, `/other`
  - Automatic IP geolocation for all nodes in pool mode
  - Dashboard displays node count by region
- ⭐ **Automatic GeoIP Database Management**
  - Auto-download on first startup from GitHub (~9MB)
  - Periodic auto-update (configurable interval, default 24h)
  - Hot-reload without service interruption
  - MMDB format validation and integrity checks
- ⭐ **hy2:// Protocol Support**
  - Support for Hysteria2 shorthand (hy2://)
  - Backward compatible with hysteria2://

**🔒 Security Enhancements:**
- Enhanced session management with automatic expiration (24h TTL) and hourly cleanup
- Constant-time password comparison to prevent timing attacks
- Semaphore-based concurrency control (CPU×4 goroutines, min 10)
- File locking for safe concurrent configuration writes

**⚡ Performance Improvements:**
- 50-70% faster subscription content parsing with optimized base64 detection
- HTTP connection pooling (100 max idle, 10 per host) reduces TIME_WAIT connections
- Response size limiting (10MB) prevents memory exhaustion
- Graceful shutdown with 30s timeout and 2s connection drain

**🔧 Technical Details:**
- Added automatic GeoIP database download and update mechanism
- Implemented hot-reload for GeoIP database updates
- Added `golang.org/x/sync/semaphore` for concurrency control
- Implemented `syscall.Flock` for Unix file locking
- Configured custom HTTP transport with optimized timeouts
- No breaking changes - fully backward compatible

**📝 Upgrade Notes:**
- GeoIP is an optional feature for pool mode (disabled by default)
- GeoIP database will be auto-downloaded when enabled
- Existing sessions will be invalidated on upgrade (users need to re-login)
- No configuration changes required
- Recommended to restart service during low-traffic period

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=jasonwong1991/easy_proxies&type=Date)](https://star-history.com/#jasonwong1991/easy_proxies&Date)

## License

MIT License
