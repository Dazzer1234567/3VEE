# pIX — Project Brief

## What we're building
A product landing page for **pIX**, a pixel measuring desktop app for Mac & Windows.
Sold via **Lemon Squeezy** (handles VAT/merchant of record automatically).
Site domain: **3vee.app**

## Pricing model
- One-time purchase for full license (all v1.x updates free)
- Optional paid upgrade per major version (e.g. v2.0) — never forced
- Prices TBD (placeholder €XX in the HTML)

## Buyline
> "Screen measure tool for AI assisted design."

## Design
- Dark minimal, center-justified, single column, max-width 680px
- Font: JetBrains Mono + Instrument Serif
- Accent color: #E8390E (orange-red)
- Background: #0E0D0C
- Subtle 40px grid overlay
- App mockup (HTML/CSS, no images) in the hero section

## Current state of the file
`index.html` is the entire site — one self-contained file, no dependencies except Google Fonts.
It is currently located at: `/var/www/3vee/index.html` on the Raspberry Pi.

## Hosting setup (in progress)
- **Server:** Raspberry Pi (`darius@WKO-Pi`, Tailscale IP: `100.72.39.110`)
- **Web server:** Nginx (installed, config in progress)
- **Tunnel:** Cloudflare Tunnel (`cloudflared`) — connects Pi to 3vee.app without opening router ports
- **Domain:** 3vee.app — needs to be pointed to Cloudflare nameservers

## Next steps (where we left off)
1. Configure Nginx to serve `/var/www/3vee/index.html`
2. Install and configure `cloudflared` tunnel
3. Route `3vee.app` through the tunnel
4. Set both Nginx and cloudflared to start on boot

## Nginx config to create
File: `/etc/nginx/sites-available/3vee`
```nginx
server {
    listen 80;
    server_name localhost;
    root /var/www/3vee;
    index index.html;
}
```
Then symlink to sites-enabled and remove default.

## Cloudflare Tunnel steps (not started yet)
```bash
cloudflared tunnel create 3vee
cloudflared tunnel route dns 3vee 3vee.app
```
Config at `~/.cloudflared/config.yml`:
```yaml
tunnel: 3vee
credentials-file: /home/darius/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: 3vee.app
    service: http://localhost:80
  - service: http_status:404
```
