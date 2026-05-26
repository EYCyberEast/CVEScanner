# CVEScan Pro — Web Edition

A hosted, browser-based vulnerability scanner. This is the web port of the
CVEScan Pro v4.0 command-line tool — same scanning engine, now with a
dashboard, an **automated Day-1 watchlist** (no more editing source code to
add CVE IDs), and **AI analysis powered by Google Gemini**.

## What it does

- **Domain recon** — subdomain enumeration (crt.sh, HackerTarget, AlienVault,
  brute-force), port scanning, technology fingerprinting, and **virtual-host
  detection** (multiple hostnames sharing one IP).
- **Live CVE matching** against four free sources: NVD, OSV, CISA KEV,
  GitHub Security Advisories.
- **Automated Day-1 Watchlist** — paste or upload your team's CVE numbers
  from the UI. Each ID is fetched directly from NVD/OSV and cross-referenced
  against every scanned host. No source-code editing.
- **AI Insights — Gemini, OpenAI, Claude or Groq** — bring whichever API key
  you have. Per-CVE plain-English risk explanations with a patch-priority
  verdict and exploit-status assessment; board-level executive summaries; a
  prioritised remediation triage plan; an **AI Deep Analysis** that correlates
  fingerprints to surface likely CVEs, exposed services and an exploitability
  assessment; and a Q&A chat grounded in your scan data.
- **Reports** — download as **PDF**, self-contained **HTML**, or **JSON**
  (for SIEM / ticketing integration).

## Project layout

```
cvescan_web/
├── app.py             Flask backend — routes, background job manager
├── scanner.py         Core scanning engine (ported from the CLI tool)
├── ai.py              Google Gemini integration
├── templates/
│   └── index.html     The dashboard (single-page app)
├── data/              Watchlist + CVE cache (auto-created; git-ignored)
├── requirements.txt
├── .env.example       Copy to .env and fill in
├── Procfile           Process definition for PaaS hosts
└── render.yaml        One-click Render.com deploy config
```

## Quick start (local)

```bash
cd cvescan_web
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # then edit .env — see below
python app.py
```

Open <http://127.0.0.1:5000>.

## Configuration — the `.env` file

All secrets live in `.env`. **This file is git-ignored and is never
committed.** Copy `.env.example` to `.env` and fill in:

### AI provider keys (set at least one)

The AI features work with **any one** of four providers — use whichever key
you already have. The tool auto-detects whatever you supply.

| Variable            | Provider | Get a key |
|---------------------|----------|-----------|
| `GEMINI_API_KEY`    | Google Gemini   | <https://aistudio.google.com/apikey> |
| `OPENAI_API_KEY`    | OpenAI (GPT)    | <https://platform.openai.com/api-keys> |
| `ANTHROPIC_API_KEY` | Anthropic (Claude) | <https://console.anthropic.com/settings/keys> |
| `GROQ_API_KEY`      | Groq (Llama)    | <https://console.groq.com/keys> |

- `AI_PROVIDER` — which provider to use by default (`gemini`, `openai`,
  `anthropic` or `groq`). Leave blank to auto-pick the first one configured.
- If you set more than one key, you can switch providers live from the
  **AI Insights** tab — no restart needed.
- Each provider also has a `*_MODEL` variable (`GEMINI_MODEL`, `OPENAI_MODEL`,
  `ANTHROPIC_MODEL`, `GROQ_MODEL`) with a sensible default. Override it if
  your account uses a different model name.

### CVE data source keys

| Variable          | Required? | Purpose |
|-------------------|-----------|---------|
| `NVD_API_KEY`     | recommended | Free key: <https://nvd.nist.gov/developers/request-an-api-key>. Without it, CVE syncs are heavily rate-limited (slow). |
| `GITHUB_TOKEN`    | optional  | Raises the GitHub Advisory rate limit. |
| `CVESCAN_DATA_DIR`| optional  | Where the watchlist + cache are stored. Point this at a persistent disk on ephemeral hosts. |

Your API keys go **only** in `.env` — they are read from the environment at
runtime and are never written into source, logs, or reports.

### Why an NVD key matters

Without an NVD API key, NIST rate-limits you to ~5 requests per 30 seconds,
so a watchlist of 150 CVEs takes ~15+ minutes to sync. With a free key it
drops to roughly 2 minutes. Get one — it takes a minute and is free.

## Using the watchlist (the automated Day-1 feature)

1. Open the **Day-1 Watchlist** tab.
2. Paste CVE IDs in any format — straight from an email or advisory. The tool
   auto-extracts every `CVE-YYYY-NNNN` pattern and ignores everything else.
   You can also upload a `.txt` / `.csv` file.
3. Click **Import & Add** (merges into the list) or **Replace Entire List**.
4. Click **Sync Watchlist Now** — each CVE is fetched live by direct ID.
5. Run a scan; any tracked CVE matching a scanned host is flagged as a
   Day-1 hit in the results and report.

The watchlist persists in `data/watchlist.json` between restarts.

## Deploying (hosted)

The app ships with a `Procfile` and `render.yaml`, and runs under gunicorn.

**Render.com (one click):** push this folder to a Git repo, create a new
Web Service from it — `render.yaml` is detected automatically. It provisions
a 1 GB persistent disk for the watchlist/cache. Add `GEMINI_API_KEY` and
`NVD_API_KEY` as environment variables in the Render dashboard.

**Railway / Heroku / Fly.io:** the `Procfile` works as-is. Set the same
environment variables in the platform's config, and attach a persistent
volume if you want the watchlist/cache to survive restarts (otherwise set
`CVESCAN_DATA_DIR` to a writable path).

**Any VPS:**

```bash
pip install -r requirements.txt
gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:8000
```

Use one worker with multiple threads — scan jobs are tracked in memory, so
multiple workers would not share job state. Put nginx/Caddy in front for TLS.

### A note on port scanning when hosted

Subdomain enumeration and CVE syncing use ordinary HTTPS and work on every
host. **Raw-socket port scanning** needs outbound TCP to arbitrary ports —
some managed platforms restrict this on lower tiers. If port scans come back
empty everywhere, your host is likely blocking outbound connections; run the
app on a VPS or a plan that permits outbound TCP. CVE matching from
fingerprinted HTTP headers still works regardless.

## Authorised use only

This is a defensive vulnerability-assessment tool. Only scan domains you own
or have explicit written permission to test. Unauthorised scanning may be
illegal in your jurisdiction. You are responsible for how you use it.
