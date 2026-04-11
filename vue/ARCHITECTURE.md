# Frontend / Backend Design

## Frontend

- Stack: Vite + Vue 3 + TypeScript
- Entry: `src/App.vue`
- API adapter: `src/lib/api.ts`
- Types: `src/lib/types.ts`
- Styling: `src/style.css`

The frontend is designed as a single operational console for the `CDN -> rust_waf -> SafeLine WAF -> Nginx` chain. It emphasizes:

- upstream health visibility
- proxy-path metrics
- latest blocked events
- active blocked IPs
- current rules overview

During development, Vite proxies `/api/*` to the Rust Axum API on `http://127.0.0.1:3000`.

## Backend

- Stack: Rust + Axum
- Read APIs:
  - `/health`
  - `/metrics`
  - `/events`
  - `/blocked-ips`
  - `/rules`

The backend acts as the control-plane API for the console, while the Rust WAF runtime remains the data-plane component responsible for pre-filtering, health checking, forwarding and metrics collection.

## Suggested Runtime Split

- Data plane: Rust listener, proxying, health check loop, upstream decision logic
- Control plane: Axum API + Vue console
- Persistence plane: SQLite for events, blocked IPs and rules

## Start Commands

1. Rust API:
   `cargo run --features api`
2. Vue console:
   `cd vue && npm install && npm run dev`
