# PrivacyReport

Generate comprehensive privacy reports for any website. This single-file PHP app inspects headers, cookies, trackers, third-party requests, common privacy endpoints, and UI signals to help you understand a site’s privacy posture fast.

## Features

### What it checks
- **Security Headers**: Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, and CO\* headers (CORP/COEP/COOP).  
- **HTTPS/TLS Snapshot**: Basic certificate details (issuer, expiry).  
- **Cookies**: Set-Cookie flags (Secure, HttpOnly, SameSite) with per-cookie hints.  
- **Trackers**: Heuristic detection for common analytics/ads SDKs (e.g., GA, GTM, FB Pixel, Hotjar, Segment, Mixpanel, Matomo, Amplitude, Clarity, LinkedIn Insight, Sentry).  
- **Third-Party Requests**: External hosts loaded by scripts, links, iframes, images.  
- **Privacy Endpoints**: `robots.txt`, `/.well-known/security.txt`, `/privacy`, `/privacy-policy`.  
- **Forms / PII Signals**: Inputs that suggest personal data collection (email, phone, name, address, etc.).  
- **UI Signals**: Cookie-banner keyword hints.

### Output
- **Overall Grade** (A+ to F) based on weighted checks.  
- **Actionable Recommendations** prioritized from findings.  
- **Exports**: JSON and Markdown.

### Design
- Light, clean UI with Tailwind (CDN).  
- No build step. Drop in a PHP server and go.

## Requirements

- PHP **8.0+**  
- Extensions: `curl`, `dom`, `openssl` (recommended), `mbstring`

> Heuristics only. JavaScript-heavy sites, geo-based consent flows, or server-side variations may affect results.

## Quick Start

1. Copy `index.php` into a web-served directory.
2. Ensure required PHP extensions are enabled.
3. Open in your browser: http://localhost/privacyreport/index.php

4. Enter a URL (include `https://`) and **Run Audit**.  
5. Use **Export JSON/Markdown** for sharing.

## How It Works (High Level)

- Fetches the page (with redirects) and captures response headers/body.  
- Parses HTML to enumerate scripts, links, iframes, images and derive hostnames.  
- Compares hostnames to the site’s registrable domain to estimate third-party calls.  
- Looks for known tracker domains and inline code signatures.  
- Evaluates common security headers and `Set-Cookie` attributes.  
- Probes convenience endpoints (`/privacy`, `/privacy-policy`, `/.well-known/security.txt`, `robots.txt`).  
- Extracts PII signals from forms (heuristic).  
- Aggregates findings into a grade and recommendations.

## Roadmap

- Public Suffix List (PSL) for accurate registrable domain parsing.  
- Deeper TLS inspection (protocols/ciphers) and HSTS preload hints.  
- Script/network interception via headless browser mode (optional sidecar).  
- Regional consent flow simulation.

## License

MIT
