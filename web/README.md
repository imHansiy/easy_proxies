# easy-proxies-web

Frontend for Easy Proxies, built with Vue 3 + TypeScript + Element Plus.

## Development

```bash
cd web
npm install
VITE_PROXY_TARGET=http://127.0.0.1:9090 npm run dev
```

`VITE_PROXY_TARGET` points to the Go monitor/API server and is used by Vite proxy for `/api/*`.

## Build

```bash
cd web
npm run build
```

Build output is generated at `web/dist` and can be served by backend via `management.frontend_dist`.
