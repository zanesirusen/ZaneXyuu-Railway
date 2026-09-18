# ZaneXyuu Studio API

This service preserves the existing Railway API contract used by the uploader:

- OAuth: Discord, Google, Roblox, and Discord linking
- Upload: `/api/upload`
- Operation polling/cancellation: `/api/operation/:id`
- Stats and auth: `/api/stats`, `/api/user/stats`, `/api/auth/me`
- Conversion and previews: `/api/convert`, `/api/preview`

Operational endpoints:

- `GET /health` returns liveness without requiring PostgreSQL.
- `GET /ready` checks PostgreSQL and FFmpeg readiness.
- `GET /api/config` returns the active upload and converter limits.
- `GET /api/user/dashboard` returns authenticated quota, asset stats, and active operations.

Local validation:

```powershell
npm.cmd run check
npm.cmd test
```

Set `TRUST_PROXY=true` only when the service is behind a trusted reverse proxy. Otherwise rate limiting uses the direct socket address and ignores client-supplied `X-Forwarded-For` values.

Deploy this directory as its own Railway service. Keep `FRONTEND_URL=https://zanexyuu-asset-uploader.vercel.app` and `BACKEND_URL=https://zanexyuu-railway.up.railway.app`, with no trailing slash. Keep the existing PostgreSQL and OAuth environment values.
