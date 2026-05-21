#!/usr/bin/env python3
"""
CVEScan Pro — Web Edition :: app.py
Flask backend. Hosts the dashboard, runs scans/watchlist syncs as background
jobs, and exposes the AI endpoints.

Run locally:   python app.py
Run hosted:    gunicorn app:app --workers 1 --threads 8 --timeout 120
"""

import os, json, uuid, time, threading, datetime, html
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()                       # load .env before importing our modules

from flask import (Flask, request, jsonify, render_template,
                   Response, abort)

import scanner
import ai

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent

# ════════════════════════════════════════════════════════════════
# JOB MANAGER  — simple in-memory background job store
# ════════════════════════════════════════════════════════════════
JOBS = {}
JOBS_LOCK = threading.Lock()
MAX_JOBS = 50          # keep memory bounded


def _new_job(job_type):
    jid = uuid.uuid4().hex[:12]
    job = {
        "id": jid, "type": job_type, "status": "queued",
        "progress": 0, "log": [], "result": None, "error": None,
        "created": datetime.datetime.now().isoformat(),
        "label": "",
    }
    with JOBS_LOCK:
        JOBS[jid] = job
        # evict oldest finished jobs if over the cap
        if len(JOBS) > MAX_JOBS:
            done = sorted((j for j in JOBS.values()
                           if j["status"] in ("done", "error")),
                          key=lambda j: j["created"])
            for old in done[:len(JOBS) - MAX_JOBS]:
                JOBS.pop(old["id"], None)
    return job


def _run_job(job, target_fn):
    """Wrap a job: wire up logging/progress callbacks, run, capture result."""
    def log(level, msg):
        line = {"t": time.strftime("%H:%M:%S"), "level": level, "msg": str(msg)}
        job["log"].append(line)
        if len(job["log"]) > 1200:        # cap log size
            del job["log"][:400]

    def progress(pct):
        job["progress"] = max(0, min(100, int(pct)))

    scanner.set_logger(log)
    scanner.set_progress_cb(progress)
    job["status"] = "running"
    try:
        job["result"] = target_fn(log, progress)
        job["status"] = "done"
        job["progress"] = 100
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        log("bad", f"Job failed: {e}")


def _start(job, target_fn):
    threading.Thread(target=_run_job, args=(job, target_fn), daemon=True).start()


# ════════════════════════════════════════════════════════════════
# SCAN PIPELINE
# ════════════════════════════════════════════════════════════════
def _scan_pipeline(targets, full, client, force_sync):
    """Runs inside a job thread. Returns the full scan result dict."""
    merged_db, cisa_map, watchlist_db = scanner.sync_all_cves(force=force_sync)

    domains = []
    for i, raw in enumerate(targets):
        dc = scanner.clean_domain(raw)
        if not dc:
            scanner.warn(f"Skipping invalid target: {raw}")
            continue
        scanner.hdr(f"[{i+1}/{len(targets)}] TARGET: {dc}")
        t0 = time.time()
        results = scanner.run_domain_scan(dc, merged_db, full=full)

        scanner.hdr("DAY-1 WATCHLIST CROSS-REFERENCE")
        wl_matches = scanner.cross_reference_watchlist(results, watchlist_db, cisa_map)
        if wl_matches:
            scanner.warn(f"{len(wl_matches)} watchlist CVEs matched detected tech!")
        else:
            scanner.good("No watchlist CVEs matched detected tech on this domain")

        domains.append({
            "domain": dc, "results": results,
            "wl_matches": wl_matches,
            "elapsed": f"{time.time() - t0:.1f}s",
        })

    return {
        "targets": [scanner.clean_domain(t) for t in targets
                    if scanner.clean_domain(t)],
        "client": client,
        "full": full,
        "domains": domains,
        "watchlist_count": len(watchlist_db),
        "watchlist_pending": sum(1 for v in watchlist_db.values()
                                 if v.get("pending")),
        "generated": datetime.datetime.now().isoformat(),
        "stats": _scan_stats(domains),
    }


def _scan_stats(domains):
    all_cves, hosts, wl_hits = [], 0, 0
    for d in domains:
        hosts += len(d["results"])
        wl_hits += len(d["wl_matches"])
        for h in d["results"]:
            all_cves.extend(h["cves"])
    crit = sum(1 for c in all_cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in all_cves if c["severity"] == "HIGH")
    med = sum(1 for c in all_cves if c["severity"] == "MEDIUM")
    kev = sum(1 for c in all_cves if c.get("known_exploited"))
    risk = ("CRITICAL" if crit else "HIGH" if high
            else "MEDIUM" if med else "LOW")
    return {"domains": len(domains), "hosts": hosts, "total_cves": len(all_cves),
            "critical": crit, "high": high, "medium": med, "kev": kev,
            "watchlist_hits": wl_hits, "risk": risk}


# ════════════════════════════════════════════════════════════════
# ROUTES — pages
# ════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    meta = scanner.load_meta()
    db = scanner.load_cve_cache()
    wl_ids = scanner.load_watchlist_ids()
    wl_cache = scanner.load_watchlist_cache()
    sources = {}
    for src in ["nvd", "osv", "cisa", "github"]:
        last = meta.get(f"last_{src}", 0)
        age = int((time.time() - last) / 60) if last else None
        sources[src] = {"entries": len(db.get(src, {})), "age_min": age}
    wl_last = meta.get("last_watchlist", 0)
    return jsonify({
        "sources": sources,
        "watchlist": {
            "tracked": len(wl_ids),
            "indexed": sum(1 for c in wl_ids
                           if c in wl_cache and not wl_cache[c].get("pending")),
            "pending": sum(1 for c in wl_ids
                           if c in wl_cache and wl_cache[c].get("pending")),
            "age_min": int((time.time() - wl_last) / 60) if wl_last else None,
        },
        "ai": ai.ai_status(),
        "nvd_key": bool(scanner.NVD_API_KEY),
    })


# ════════════════════════════════════════════════════════════════
# ROUTES — watchlist (the automated Day-1 CVE list)
# ════════════════════════════════════════════════════════════════
@app.route("/api/watchlist")
def watchlist_get():
    ids = scanner.load_watchlist_ids()
    cache = scanner.load_watchlist_cache()
    items = []
    for cid in ids:
        c = cache.get(cid)
        if c:
            items.append({
                "id": cid, "severity": c.get("severity", "UNKNOWN"),
                "cvss": c.get("cvss", 0), "desc": c.get("desc", ""),
                "published": c.get("published", "?"),
                "source": c.get("source", "?"),
                "pending": bool(c.get("pending")),
                "affected_product": c.get("affected_product", ""),
                "patch": c.get("patch", ""),
            })
        else:
            items.append({"id": cid, "severity": "UNKNOWN", "cvss": 0,
                           "desc": "Not yet synced", "pending": True,
                           "source": "-", "published": "-",
                           "affected_product": "", "patch": ""})
    items.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
         "UNKNOWN": 4}.get(x["severity"], 4), -x.get("cvss", 0)))
    return jsonify({"count": len(ids), "items": items})


@app.route("/api/watchlist/import", methods=["POST"])
def watchlist_import():
    """Import CVE IDs from pasted text OR an uploaded file. Merges into list."""
    text = ""
    if "file" in request.files:
        text += request.files["file"].read().decode("utf-8", errors="ignore")
    if request.is_json:
        text += "\n" + ((request.json or {}).get("text", ""))
    else:
        text += "\n" + request.form.get("text", "")

    found = scanner.extract_cve_ids(text)
    if not found:
        return jsonify({"ok": False,
                        "error": "No valid CVE IDs found in the input."}), 400
    merged, newly_added = scanner.add_watchlist_ids(text)
    return jsonify({"ok": True, "imported": len(newly_added),
                    "found": len(found), "total": len(merged),
                    "new_ids": newly_added,
                    "note": ("All supplied CVEs were already tracked."
                             if not newly_added else "")})


@app.route("/api/watchlist/replace", methods=["POST"])
def watchlist_replace():
    """Replace the entire watchlist with a new set of CVE IDs."""
    data = request.get_json(silent=True) or {}
    ids = scanner.extract_cve_ids(data.get("text", ""))
    clean = scanner.save_watchlist_ids(ids)
    return jsonify({"ok": True, "total": len(clean)})


@app.route("/api/watchlist/clear", methods=["POST"])
def watchlist_clear():
    scanner.save_watchlist_ids([])
    return jsonify({"ok": True})


@app.route("/api/watchlist/sync", methods=["POST"])
def watchlist_sync():
    """Kick off a background watchlist sync (fetch each CVE by ID)."""
    if not scanner.load_watchlist_ids():
        return jsonify({"ok": False, "error": "Watchlist is empty."}), 400
    force = bool((request.get_json(silent=True) or {}).get("force"))
    job = _new_job("watchlist")
    job["label"] = "Watchlist sync"

    def task(log, progress):
        wl = scanner.sync_watchlist(force=force)
        return {"synced": len(wl)}

    _start(job, task)
    return jsonify({"ok": True, "job_id": job["id"]})


# ════════════════════════════════════════════════════════════════
# ROUTES — scanning
# ════════════════════════════════════════════════════════════════
@app.route("/api/scan", methods=["POST"])
def scan_start():
    data = request.get_json(silent=True) or {}
    raw = data.get("targets", "")
    targets = [t for t in
               (scanner.clean_domain(x) for x in
                __import__("re").split(r"[,\s]+", raw))
               if t]
    if not targets:
        return jsonify({"ok": False, "error": "No valid domains given."}), 400
    full = bool(data.get("full"))
    client = (data.get("client") or "").strip()
    force_sync = bool(data.get("force_sync"))

    job = _new_job("scan")
    job["label"] = f"Scan: {', '.join(targets[:3])}" + (
        f" +{len(targets)-3}" if len(targets) > 3 else "")

    def task(log, progress):
        return _scan_pipeline(targets, full, client, force_sync)

    _start(job, task)
    return jsonify({"ok": True, "job_id": job["id"], "targets": targets})


@app.route("/api/job/<jid>")
def job_status(jid):
    job = JOBS.get(jid)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    # send only the tail of the log unless explicitly asked for all
    since = int(request.args.get("since", 0))
    log_slice = job["log"][since:]
    return jsonify({
        "id": job["id"], "type": job["type"], "status": job["status"],
        "progress": job["progress"], "label": job["label"],
        "error": job["error"], "log": log_slice, "log_total": len(job["log"]),
        "result": job["result"] if job["status"] == "done" else None,
    })


@app.route("/api/jobs")
def jobs_list():
    with JOBS_LOCK:
        items = sorted(JOBS.values(), key=lambda j: j["created"], reverse=True)
    return jsonify([{"id": j["id"], "type": j["type"], "status": j["status"],
                     "label": j["label"], "progress": j["progress"],
                     "created": j["created"]} for j in items[:20]])


# ════════════════════════════════════════════════════════════════
# ROUTES — AI (Gemini)
# ════════════════════════════════════════════════════════════════
@app.route("/api/ai/status")
def ai_status_route():
    return jsonify(ai.ai_status())


@app.route("/api/ai/provider", methods=["POST"])
def ai_set_provider():
    """Switch the active AI provider at runtime (must have a key configured)."""
    name = (request.get_json(silent=True) or {}).get("provider", "")
    if ai.set_provider(name):
        return jsonify({"ok": True, "status": ai.ai_status()})
    return jsonify({"ok": False,
                    "error": f"Provider '{name}' has no API key configured."}), 400


def _job_result_or_404(jid):
    job = JOBS.get(jid)
    if not job or job["status"] != "done" or not job["result"]:
        abort(404)
    return job["result"]


def _all_cves(scan):
    out = []
    for d in scan.get("domains", []):
        for h in d.get("results", []):
            for c in h.get("cves", []):
                out.append({**c, "host": h["host"]})
    return out


@app.route("/api/ai/explain", methods=["POST"])
def ai_explain():
    if not ai.ai_available():
        return jsonify({"ok": False, "error": "Gemini not configured."}), 400
    cve = (request.get_json(silent=True) or {}).get("cve")
    if not cve or not cve.get("id"):
        return jsonify({"ok": False, "error": "No CVE supplied."}), 400
    try:
        return jsonify({"ok": True, "result": ai.explain_cve(cve)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/ai/summary", methods=["POST"])
def ai_summary():
    if not ai.ai_available():
        return jsonify({"ok": False, "error": "Gemini not configured."}), 400
    jid = (request.get_json(silent=True) or {}).get("job_id")
    scan = _job_result_or_404(jid)
    try:
        return jsonify({"ok": True, "result": ai.executive_summary(scan)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/ai/triage", methods=["POST"])
def ai_triage():
    if not ai.ai_available():
        return jsonify({"ok": False, "error": "Gemini not configured."}), 400
    jid = (request.get_json(silent=True) or {}).get("job_id")
    scan = _job_result_or_404(jid)
    cves = _all_cves(scan)
    if not cves:
        return jsonify({"ok": False, "error": "No CVEs to triage."}), 400
    try:
        return jsonify({"ok": True, "result": ai.triage_findings(cves)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/ai/ask", methods=["POST"])
def ai_ask():
    if not ai.ai_available():
        return jsonify({"ok": False, "error": "Gemini not configured."}), 400
    data = request.get_json(silent=True) or {}
    scan = _job_result_or_404(data.get("job_id"))
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "No question supplied."}), 400
    try:
        return jsonify({"ok": True, "answer": ai.ask(question, scan)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


# ════════════════════════════════════════════════════════════════
# ROUTES — report download
# ════════════════════════════════════════════════════════════════
@app.route("/api/report/<jid>")
def report(jid):
    scan = _job_result_or_404(jid)
    fmt = request.args.get("fmt", "html")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        return Response(
            json.dumps(scan, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition":
                     f"attachment; filename=CVEScan_{ts}.json"})
    html_doc = build_html_report(scan)
    return Response(html_doc, mimetype="text/html",
                    headers={"Content-Disposition":
                             f"attachment; filename=CVEScan_{ts}.html"})


def build_html_report(scan):
    """Self-contained HTML report (open in browser, Ctrl+P for PDF)."""
    e = lambda s: html.escape(str(s))
    sev_c = {"CRITICAL": "#C00000", "HIGH": "#E26B0A",
             "MEDIUM": "#B8860B", "LOW": "#2E7D32", "UNKNOWN": "#777"}
    st = scan["stats"]
    today = datetime.date.today().strftime("%d %B %Y")
    rc = sev_c.get(st["risk"], "#333")

    domain_blocks = ""
    for d in scan["domains"]:
        cves = [{**c, "host": h["host"], "ip": h["ip"]}
                for h in d["results"] for c in h["cves"]]
        if not cves and not d["wl_matches"]:
            continue
        rows = ""
        for c in sorted(cves, key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3),
                -x.get("cvss", 0))):
            col = sev_c.get(c["severity"], "#777")
            kev = (' <b style="color:#C00000">[KEV]</b>'
                   if c.get("known_exploited") else "")
            rows += f"""<tr>
              <td style="font-family:monospace;color:#1565C0;font-weight:700">
                <a href="https://nvd.nist.gov/vuln/detail/{e(c['id'])}"
                   style="color:#1565C0">{e(c['id'])}</a></td>
              <td>{e(c['host'])}</td>
              <td><span style="color:{col};border:1.5px solid {col};
                  border-radius:3px;padding:1px 7px;font-weight:700;
                  font-size:8.5pt">{e(c['severity'])}</span></td>
              <td style="color:{col};font-weight:700;text-align:center">
                {e(c.get('cvss', 0))}</td>
              <td style="font-size:9pt">{e(c.get('desc', '')[:170])}{kev}</td>
              <td style="font-size:9pt;color:#444">
                {e((c.get('affected_product') or c.get('matched_keyword') or '-').title())}</td>
              <td style="color:#2E7D32;font-size:9pt">{e(c.get('patch', '')[:70])}</td>
            </tr>"""
        wl_block = ""
        if d["wl_matches"]:
            wl_rows = "".join(f"""<tr style="background:#fff0f0">
              <td style="font-family:monospace;font-weight:700;color:#C00000">
                {e(m['id'])}</td>
              <td>{e(m['host'])}</td>
              <td>{e(m['severity'])}</td>
              <td>{e(m.get('matched_reason', ''))}</td>
              <td style="font-size:9pt">{e(m.get('desc', '')[:130])}</td>
            </tr>""" for m in d["wl_matches"])
            wl_block = f"""<div style="background:#fff0f0;border:1.5px solid #C00000;
                border-radius:4px;padding:10px;margin:10px 0">
              <b style="color:#C00000">Day-1 Watchlist: {len(d['wl_matches'])}
                CVE(s) matched on {e(d['domain'])}</b>
              <table style="margin-top:8px"><thead><tr>
                <th>CVE</th><th>Host</th><th>Severity</th>
                <th>Match Reason</th><th>Description</th></tr></thead>
                <tbody>{wl_rows}</tbody></table></div>"""
        domain_blocks += f"""<div style="margin-bottom:24px;border:1px solid #ddd;
            border-radius:6px;overflow:hidden">
          <div style="background:#1a1a24;color:#FFE600;padding:9px 14px;
               font-weight:700">{e(d['domain'])}
            <span style="color:#999;font-weight:400;font-size:9pt">
              &nbsp;{len(cves)} CVEs &middot; {d['elapsed']}</span></div>
          {wl_block}
          <table><thead><tr><th>CVE ID</th><th>Host</th><th>Severity</th>
            <th>CVSS</th><th>Description</th><th>Affected</th><th>Fix</th>
          </tr></thead><tbody>{rows}</tbody></table></div>"""

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>CVEScan Pro Report</title><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;
     color:#1a1a24;font-size:11pt}}
.cover{{background:#1a1a24;color:#fff;padding:48px 50px}}
.cover h1{{font-size:21pt;margin-top:14px;color:#FFE600}}
.meta{{margin-top:14px;color:#aaa;line-height:1.9;font-size:10pt}}
.meta b{{color:#FFE600}}
.badge{{display:inline-block;margin-top:16px;background:{rc};color:#fff;
       padding:6px 20px;font-weight:900;letter-spacing:2px}}
.page{{background:#fff;padding:32px 50px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.stat{{flex:1;min-width:110px;background:#f8f8f8;border-top:3px solid #FFE600;
      padding:12px;text-align:center}}
.stat .v{{font-size:21pt;font-weight:900}}
.stat .l{{font-size:8pt;color:#888;text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;font-size:9.5pt}}
th{{background:#1a1a24;color:#FFE600;padding:7px 9px;text-align:left;font-size:8.5pt}}
td{{padding:6px 9px;border-bottom:1px solid #eee;vertical-align:top}}
h2{{font-size:13pt;border-left:4px solid #FFE600;padding-left:10px;margin:22px 0 12px}}
@media print{{.cover,th,.badge,.stat{{-webkit-print-color-adjust:exact;
  print-color-adjust:exact}}}}
</style></head><body>
<div class="cover">
  <div style="letter-spacing:3px;color:#FFE600;font-size:10pt">
    CVESCAN PRO &mdash; WEB EDITION &mdash; VULNERABILITY ASSESSMENT</div>
  <h1>Live CVE Scan Report</h1>
  <div class="meta">
    {"Client: <b>" + e(scan['client']) + "</b><br>" if scan.get('client') else ""}
    Targets: <b>{e(', '.join(scan['targets']))}</b><br>
    Date: <b>{today}</b><br>
    Sources: <b>NVD &middot; OSV &middot; CISA-KEV &middot; GitHub Advisories
      &middot; Day-1 Watchlist</b><br>
    Watchlist tracked: <b>{scan.get('watchlist_count', 0)}</b>
      &middot; Pending NVD: <b>{scan.get('watchlist_pending', 0)}</b>
  </div>
  <div class="badge">OVERALL RISK: {st['risk']}</div>
</div>
<div class="page">
  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat"><div class="v">{st['domains']}</div><div class="l">Domains</div></div>
    <div class="stat"><div class="v">{st['hosts']}</div><div class="l">Hosts</div></div>
    <div class="stat"><div class="v">{st['total_cves']}</div><div class="l">Total CVEs</div></div>
    <div class="stat"><div class="v" style="color:#C00000">{st['critical']}</div>
      <div class="l">Critical</div></div>
    <div class="stat"><div class="v" style="color:#E26B0A">{st['high']}</div>
      <div class="l">High</div></div>
    <div class="stat"><div class="v" style="color:#C00000">{st['kev']}</div>
      <div class="l">Exploited (KEV)</div></div>
    <div class="stat"><div class="v" style="color:#C00000">{st['watchlist_hits']}</div>
      <div class="l">Watchlist Hits</div></div>
  </div>
  <h2>Findings by Domain</h2>
  {domain_blocks or '<p style="color:#888">No CVEs matched.</p>'}
  <p style="margin-top:24px;font-size:8.5pt;color:#999">
    Generated by CVEScan Pro Web Edition. Authorised assessment use only.</p>
</div></body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  CVEScan Pro Web Edition  ->  http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=bool(os.environ.get("FLASK_DEBUG")))
