# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Le Chalet Bar** — menu management system for a French alpine bar. Static frontend hosted on GitHub Pages, backend on Cloudflare Workers, menu data stored as `menu.json` in this GitHub repo.

## Commands

```bash
npm run dev      # Local dev server (Cloudflare Worker via wrangler)
npm run deploy   # Deploy Worker to Cloudflare
```

Secrets must be set via `wrangler secret put <NAME>` (not in code):
- `ADMIN_PASSWORD_HASH` — SHA-256 of admin password
- `GITHUB_TOKEN` — GitHub token with repo scope
- `JWT_SECRET` — JWT signing secret

Local secrets go in `.dev.vars` (gitignored).

## Architecture

```
GitHub Pages (static)          Cloudflare Worker (src/index.js)
  index.html   ──── GET /menu ────►  reads menu.json from GitHub API
  admin.html   ── POST /login ──►   returns JWT (30-day)
               ──  PUT /menu  ──►   writes menu.json back to GitHub
  print.html   ──── GET /menu ────►  (same endpoint, direct GitHub raw in print.html)
```

`print.html` fetches `menu.json` directly from GitHub raw URL (bypasses the Worker). `index.html` and `admin.html` go through the Worker API.

## menu.json Structure

Two category types drive how items are rendered:

**`"type": "simple"`** — one price per item. Supports optional `subsections` for grouping.
```json
{ "id": "...", "name": "...", "active": true, "price": 4.5, "desc": "optional" }
```

**`"type": "double_prix"`** — two prices per item (e.g. 25cl / 50cl). Requires `col1`/`col2` labels on the category.
```json
{ "id": "...", "name": "...", "active": true, "price1": 3.8, "price2": 7.6 }
```

**`"type": "formule"`** — boxed items with a larger price display (for meal deals/platters).

Use `"price": null` (not `0`) to display "ardoise" (price on chalkboard).

`"active": false` hides a category or item without deleting it.

## Frontend Rendering (print.html / index.html)

Both files use the same design tokens: `--gold`, `--dark`, `--cream`, `--muted`. Fonts: Cinzel (headers), Playfair Display (prices), EB Garamond (body).

`print.html` generates an A5-formatted card. All categories render into a single `.page.content` div — the browser handles pagination at print time. Cover and back-cover are separate `.page` divs with `page-break-after: always`.

The `fmt(price)` helper returns `"ardoise"` for `null`/`undefined`, otherwise formats as `"X,XX\u00a0€"`.
