# clash-fusion

A lightweight Cloudflare Worker that fetches multiple subscription URLs, merges their proxies, applies filters, and outputs a complete [Mihomo](https://github.com/MetaCubeX/mihomo) YAML config with your custom DNS, rules, and proxy groups.

**Zero database. Zero cache. Fresh config on every request.**

## How It Works

```
Client (Mihomo/Surge/etc.)
  │
  │  GET /config.yaml?token=xxx
  ▼
┌─────────────────────────────┐
│  Cloudflare Worker          │
│                             │
│  1. Fetch N subscription    │
│     URLs in parallel        │
│  2. Parse Clash YAML/JSON   │
│     or proxy URIs           │
│  3. Exclude info nodes      │
│     (configurable regex)    │
│  4. Deduplicate by server   │
│     + port                  │
│  5. Sort by name            │
│  6. Merge with your template│
│     (DNS, rules, proxies,   │
│      proxy-groups,          │
│      rule-providers)        │
│  7. Return Mihomo YAML      │
└─────────────────────────────┘
```

## Quick Start

### 1. Deploy

```bash
pnpm install
pnpm deploy
```

### 2. Set Secrets

In Cloudflare Dashboard → Workers & Pages → `clash-config` → Settings → Secrets:

| Secret | Required | Description |
|--------|----------|-------------|
| `SUBSCRIPTION_URLS` | Yes | Newline-separated subscription URLs |
| `AUTH_TOKEN` | No | Protects the endpoint. No token = public. |
| `EXCLUDE_PATTERN` | No | Regex to remove info nodes. Not set = keep all. |

Example `SUBSCRIPTION_URLS`:
```
https://sub1.example.com/api/v1/client/subscribe?token=xxx
https://sub2.example.com/sub?sid=123&uid=456&token=yyy
```

### 3. Customize Template

Edit `src/config.ts` to change DNS, proxy groups, rules, and rule providers.

### 4. Use in Client

```
https://your-domain.com/config.yaml?token=xxx
```

## Configuration

### Environment Variables

All sensitive configuration is stored as Cloudflare Secrets — never committed to code.

| Variable | Source | Behavior when missing |
|----------|--------|----------------------|
| `AUTH_TOKEN` | Secret | No auth required |
| `SUBSCRIPTION_URLS` | Secret | Returns 500 error |
| `EXCLUDE_PATTERN` | Secret | No nodes excluded |

### Template (`src/config.ts`)

The template is the fixed part of your Mihomo config — DNS, proxy groups, rules, and rule providers. The Worker merges its dynamically-generated `proxies` list into this template.

```ts
export const TEMPLATE = {
  dns: { ... },
  "proxy-groups": [ ... ],
  "rule-providers": { ... },
  rules: [ ... ],
};
```

The special token `$all` in a proxy group's `proxies` array expands to every discovered node name.

### Filter Pipeline

1. **Exclude** — Remove nodes matching `EXCLUDE_PATTERN` regex (if configured)
2. **Deduplicate** — Keep first occurrence of each `server:port` pair
3. **Sort** — Alphabetical by name (Chinese-aware)

## Response Headers

| Header | Value |
|--------|-------|
| `content-type` | `text/yaml; charset=utf-8` |
| `profile-update-interval` | `6` (hours) |
| `cache-control` | `no-store` |

## Supported Proxy Formats

The parser handles both structured and URI formats:

- **Clash YAML** — Standard `proxies:` section
- **Clash JSON** — Array or `{ "proxies": [...] }`
- **URI formats** — `ss://`, `vmess://`, `vless://`, `trojan://`, `hysteria2://`, `tuic://`, `anytls://`, `http/https`, `socks5://`

## Deployment

### GitHub Integration (recommended)

1. Push to GitHub
2. Cloudflare Dashboard → Workers & Pages → `clash-config` → Settings → CI/CD → Connect repository
3. Set secrets in Cloudflare Dashboard
4. Every push auto-deploys

### Manual

```bash
pnpm install
pnpm deploy
```

## Comparison

| Feature | clash-fusion | Full Sub-Store |
|---------|-------------|----------------|
| Database | None | D1 |
| UI | None | Vue SPA |
| Change config | Edit file + redeploy | Web UI |
| Client formats | Mihomo only | 12 formats |
| Auto-refresh | Real-time per request | Real-time per request |
| Worker size | ~50 KB gzip | ~400 KB gzip |
| Dependencies | 1 (`yaml`) | 10+ |

## License

AGPL-3.0

## Credits

The default DNS configuration and routing rules in `src/config.ts` are adapted from [bling-yshs's Mihomo configuration guide](https://linux.do/t/topic/1999640) on Linux.do.
