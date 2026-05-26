#!/usr/bin/env python3
"""
CVEScan Pro — Web Edition :: scanner.py
Core scanning engine. Adapted from the original cvescan_pro.py CLI tool.

What changed vs. the CLI version:
  * All ANSI-coloured print() calls replaced by a structured log callback,
    so the web UI can stream live progress.
  * The Day-1 watchlist is no longer a hard-coded Python list — it is
    loaded from data/watchlist.json and managed from the web UI.
  * Cache + data directories are configurable via env vars.

CVE sources (all live, free):
  NVD, OSV, CISA KEV, GitHub Security Advisories.
"""

import os, json, socket, ssl, re, time, datetime, threading
import concurrent.futures, urllib.request
from pathlib import Path

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver, dns.zone, dns.query
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ════════════════════════════════════════════════════════════════
# PATHS  (configurable for hosted environments)
# ════════════════════════════════════════════════════════════════
BASE_DIR  = Path(__file__).resolve().parent
DATA_DIR  = Path(os.environ.get("CVESCAN_DATA_DIR", BASE_DIR / "data"))
CACHE_DIR = Path(os.environ.get("CVESCAN_CACHE_DIR", DATA_DIR / "cache"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CVE_CACHE       = CACHE_DIR / "live_cve_db.json"
META_FILE       = CACHE_DIR / "meta.json"
WATCHLIST_FILE  = DATA_DIR  / "watchlist.json"        # user-managed CVE IDs
WATCHLIST_CACHE = CACHE_DIR / "watchlist_cache.json"  # fetched CVE details

CACHE_TTL = {"nvd": 21600, "osv": 21600, "cisa": 3600, "github": 43200}
WATCHLIST_TTL = 3600

NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# ════════════════════════════════════════════════════════════════
# LOGGING  — per-thread callback so each scan job streams its own log
# ════════════════════════════════════════════════════════════════
_ctx = threading.local()

def set_logger(fn):
    """Register a log callback fn(level, message) for the current thread."""
    _ctx.log = fn

def _emit(level, msg):
    fn = getattr(_ctx, "log", None)
    if fn:
        try:
            fn(level, msg)
        except Exception:
            pass

def info(m): _emit("info", m)
def good(m): _emit("good", m)
def warn(m): _emit("warn", m)
def bad(m):  _emit("bad",  m)
def hdr(m):  _emit("hdr",  m)

def set_progress(pct):
    fn = getattr(_ctx, "progress", None)
    if fn:
        try:
            fn(pct)
        except Exception:
            pass

def set_progress_cb(fn):
    _ctx.progress = fn

# ════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ════════════════════════════════════════════════════════════════
def http_get(url, headers=None, timeout=20, as_text=False):
    h = {"User-Agent": "CVEScanPro/5.0-web"}
    if headers:
        h.update(headers)
    if HAS_REQUESTS:
        r = req_lib.get(url, headers=h, timeout=timeout, verify=True)
        r.raise_for_status()
        return r.text if as_text else r.json()
    rq = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(rq, timeout=timeout) as resp:
        raw = resp.read().decode(errors="ignore")
        return raw if as_text else json.loads(raw)

def http_post(url, payload, timeout=20):
    h = {"Content-Type": "application/json", "User-Agent": "CVEScanPro/5.0-web"}
    if HAS_REQUESTS:
        r = req_lib.post(url, json=payload, headers=h, timeout=timeout)
        r.raise_for_status()
        return r.json()
    body = json.dumps(payload).encode()
    rq = urllib.request.Request(url, data=body, headers=h)
    with urllib.request.urlopen(rq, timeout=timeout) as resp:
        return json.loads(resp.read())

# ════════════════════════════════════════════════════════════════
# CACHE / META
# ════════════════════════════════════════════════════════════════
def load_meta():
    try:
        return json.loads(META_FILE.read_text()) if META_FILE.exists() else {}
    except Exception:
        return {}

def save_meta(meta):
    META_FILE.write_text(json.dumps(meta, indent=2))

def load_cve_cache():
    try:
        return json.loads(CVE_CACHE.read_text()) if CVE_CACHE.exists() else {}
    except Exception:
        return {}

def save_cve_cache(db):
    CVE_CACHE.write_text(json.dumps(db))

def needs_refresh(source, meta):
    last = meta.get(f"last_{source}", 0)
    return (time.time() - last) > CACHE_TTL.get(source, 3600)

# ════════════════════════════════════════════════════════════════
# WATCHLIST STORAGE  — the automated, user-managed CVE list
# ════════════════════════════════════════════════════════════════
# Word-boundary + negative lookahead so an over-long number (e.g. an
# 8-digit sequence) is rejected outright rather than silently truncated.
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)

def extract_cve_ids(text):
    """Pull every CVE-ID out of free-form text (comma/space/newline separated)."""
    ids = [m.upper() for m in CVE_ID_RE.findall(text or "")]
    return list(dict.fromkeys(ids))           # dedupe, keep order

def load_watchlist_ids():
    """Return the list of CVE IDs the user is tracking."""
    try:
        if WATCHLIST_FILE.exists():
            data = json.loads(WATCHLIST_FILE.read_text())
            return list(dict.fromkeys(data.get("cves", [])))
    except Exception:
        pass
    return []

def save_watchlist_ids(cve_ids):
    """Persist the watchlist. Returns the cleaned list."""
    clean = list(dict.fromkeys(c.upper() for c in cve_ids if CVE_ID_RE.fullmatch(c.strip())))
    WATCHLIST_FILE.write_text(json.dumps({
        "cves": clean,
        "updated": datetime.datetime.now().isoformat(),
    }, indent=2))
    return clean

def add_watchlist_ids(new_text):
    """
    Merge newly imported CVE IDs into the existing watchlist.
    Returns (merged_list, newly_added) where newly_added excludes IDs
    that were already being tracked.
    """
    current = load_watchlist_ids()
    incoming = extract_cve_ids(new_text)
    newly_added = [c for c in incoming if c not in current]
    merged = list(dict.fromkeys(current + incoming))
    save_watchlist_ids(merged)
    return merged, newly_added

def load_watchlist_cache():
    try:
        if WATCHLIST_CACHE.exists():
            return json.loads(WATCHLIST_CACHE.read_text())
    except Exception:
        pass
    return {}

# ════════════════════════════════════════════════════════════════
# SOURCE 1 — NVD
# ════════════════════════════════════════════════════════════════
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_PRODUCTS = [
    "apache", "nginx", "iis", "tomcat", "openssl", "openssh", "php",
    "wordpress", "drupal", "joomla", "laravel", "django", "flask",
    "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "log4j", "spring", "struts", "jenkins", "gitlab", "grafana",
    "docker", "kubernetes", "samba", "openvpn", "fortinet", "cisco",
]


def _parse_nvd_cve(cve_data, fallback_kw=""):
    """Normalise one NVD CVE record into our internal dict shape."""
    cve_id = cve_data.get("id", "?")
    desc = next((d["value"] for d in cve_data.get("descriptions", [])
                 if d.get("lang") == "en"), "No description available")[:300]
    cvss, sev = 0.0, "UNKNOWN"
    for mkey in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metrics = cve_data.get("metrics", {}).get(mkey, [])
        if metrics:
            cvss = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
            sev = (metrics[0].get("baseSeverity")
                   or metrics[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"))
            break
    versions, affected_product = [], ""
    for cfg in cve_data.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                vi = cpe.get("versionStartIncluding", "")
                ve = cpe.get("versionEndExcluding", "")
                if vi or ve:
                    versions.append(f"{vi}-{ve}".strip("-"))
                if not affected_product:
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 4:
                        affected_product = (parts[3].replace("_", " ").title()
                                            + " " + parts[4].replace("_", " ").title()).strip()
    refs = [r.get("url", "") for r in cve_data.get("references", [])[:3]]
    return {
        "id": cve_id,
        "severity": str(sev).upper(),
        "cvss": float(cvss or 0.0),
        "desc": desc,
        "published": cve_data.get("published", "?")[:10],
        "versions": versions[:4],
        "affected_product": affected_product,
        "refs": refs,
        "source": "NVD",
        "patch": refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "keyword": fallback_kw or cve_id,
    }


def fetch_cve_by_id(cve_id):
    """
    Look up ONE CVE by exact ID. This powers the automated watchlist —
    every imported CVE number is resolved directly, no keyword matching.
    Fallback chain: NVD direct -> OSV direct -> stub (pending indexing).
    """
    hdrs = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    # Attempt 1: NVD
    try:
        data = http_get(f"{NVD_API}?cveId={cve_id}", headers=hdrs, timeout=20)
        vulns = data.get("vulnerabilities", [])
        if vulns:
            entry = _parse_nvd_cve(vulns[0].get("cve", {}), fallback_kw=cve_id)
            entry["source"] = "NVD-Direct"
            entry["day1"] = True
            if entry["severity"] == "UNKNOWN":
                entry["severity"] = "MEDIUM"
            return entry
    except Exception:
        pass
    # Attempt 2: OSV
    try:
        osv = http_get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=15)
        if osv and osv.get("id"):
            summary = (osv.get("summary") or osv.get("details", ""))[:300]
            refs = [r.get("url", "") for r in osv.get("references", [])[:3]
                    if isinstance(r, dict)]
            fixed = []
            for aff in osv.get("affected", []):
                for rng in aff.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fixed.append(f"fixed in {evt['fixed']}")
            return {
                "id": cve_id, "severity": "MEDIUM", "cvss": 0.0,
                "desc": summary or "See OSV for details",
                "published": osv.get("published", "?")[:10],
                "versions": fixed[:3], "affected_product": "",
                "refs": refs, "source": "OSV-Direct",
                "patch": fixed[0] if fixed else (refs[0] if refs else "See osv.dev"),
                "keyword": cve_id, "day1": True,
            }
    except Exception:
        pass
    # Attempt 3: stub — brand-new CVE not yet indexed
    return {
        "id": cve_id, "severity": "UNKNOWN", "cvss": 0.0,
        "desc": "Pending NVD indexing - CVE reserved/published but full "
                "details not yet available.",
        "published": datetime.date.today().isoformat(),
        "versions": [], "affected_product": "Unknown - check NVD",
        "refs": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        "source": "Pending-NVD",
        "patch": f"Monitor https://nvd.nist.gov/vuln/detail/{cve_id}",
        "keyword": cve_id, "day1": True, "pending": True,
    }


def sync_watchlist(force=False):
    """
    Fetch every CVE in the user-managed watchlist directly by ID.
    Returns {cve_id: entry}. Caches results for WATCHLIST_TTL seconds.
    """
    wl_ids = load_watchlist_ids()
    wl_cache = load_watchlist_cache()
    meta = load_meta()

    if not wl_ids:
        info("Watchlist is empty - import CVE IDs from the Watchlist tab.")
        return {}

    last = meta.get("last_watchlist", 0)
    age_min = int((time.time() - last) / 60) if last else 999
    cached_ok = (not force and age_min < (WATCHLIST_TTL // 60)
                 and len([c for c in wl_ids if c in wl_cache]) >= len(wl_ids) * 0.9)
    if cached_ok:
        info(f"Watchlist cache fresh ({age_min}m old) - {len(wl_cache)} CVEs loaded")
        return {c: wl_cache[c] for c in wl_ids if c in wl_cache}

    hdr(f"DAY-1 WATCHLIST - fetching {len(wl_ids)} CVEs by direct ID lookup")
    if not NVD_API_KEY:
        warn("No NVD_API_KEY set - watchlist sync will be slow (NVD rate limit). "
             "Get a free key at nvd.nist.gov/developers")

    fetched = pending = 0
    for i, cve_id in enumerate(wl_ids):
        existing = wl_cache.get(cve_id, {})
        if existing and not existing.get("pending") and not force:
            fetched += 1
            set_progress(int((i + 1) / len(wl_ids) * 100))
            continue
        entry = fetch_cve_by_id(cve_id)
        wl_cache[cve_id] = entry
        if entry.get("pending"):
            pending += 1
        else:
            fetched += 1
        info(f"[{i+1}/{len(wl_ids)}] {cve_id} -> {entry['severity']} "
             f"(CVSS {entry['cvss']}) [{entry['source']}]")
        set_progress(int((i + 1) / len(wl_ids) * 100))
        time.sleep(0.8 if NVD_API_KEY else 6.5)   # respect NVD rate limit

    try:
        WATCHLIST_CACHE.write_text(json.dumps(wl_cache))
        meta["last_watchlist"] = time.time()
        save_meta(meta)
    except Exception as e:
        warn(f"Could not save watchlist cache: {e}")

    n_crit = sum(1 for v in wl_cache.values() if v.get("severity") == "CRITICAL")
    n_high = sum(1 for v in wl_cache.values() if v.get("severity") == "HIGH")
    good(f"Watchlist sync complete - {fetched} indexed, {pending} pending, "
         f"{n_crit} critical, {n_high} high")
    return {c: wl_cache[c] for c in wl_ids if c in wl_cache}


def fetch_nvd_product(keyword, max_results=40):
    results = []
    try:
        hdrs = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        url = f"{NVD_API}?keywordSearch={keyword}&resultsPerPage={max_results}"
        data = http_get(url, headers=hdrs, timeout=25)
        for item in data.get("vulnerabilities", []):
            results.append(_parse_nvd_cve(item.get("cve", {}), fallback_kw=keyword))
        time.sleep(0.7 if NVD_API_KEY else 6.5)
    except Exception as e:
        warn(f"NVD fetch failed [{keyword}]: {e}")
    return results


def sync_nvd(force=False):
    meta, db = load_meta(), load_cve_cache()
    if not force and not needs_refresh("nvd", meta):
        info(f"NVD cache fresh - {len(db.get('nvd', {}))} keywords cached")
        return db.get("nvd", {})
    hdr(f"NVD - syncing {len(NVD_PRODUCTS)} products")
    nvd_db = {}
    for i, product in enumerate(NVD_PRODUCTS):
        info(f"[{i+1}/{len(NVD_PRODUCTS)}] NVD: {product}")
        cves = fetch_nvd_product(product)
        if cves:
            nvd_db[product] = cves
        set_progress(int((i + 1) / len(NVD_PRODUCTS) * 100))
    db["nvd"] = nvd_db
    save_cve_cache(db)
    meta["last_nvd"] = time.time()
    save_meta(meta)
    good(f"NVD sync complete - {sum(len(v) for v in nvd_db.values())} CVEs")
    return nvd_db

# ════════════════════════════════════════════════════════════════
# SOURCE 2 — OSV
# ════════════════════════════════════════════════════════════════
OSV_API = "https://api.osv.dev/v1"
OSV_PACKAGES = [
    {"name": "django", "ecosystem": "PyPI"}, {"name": "flask", "ecosystem": "PyPI"},
    {"name": "requests", "ecosystem": "PyPI"}, {"name": "pillow", "ecosystem": "PyPI"},
    {"name": "urllib3", "ecosystem": "PyPI"}, {"name": "pyyaml", "ecosystem": "PyPI"},
    {"name": "express", "ecosystem": "npm"}, {"name": "lodash", "ecosystem": "npm"},
    {"name": "axios", "ecosystem": "npm"}, {"name": "jquery", "ecosystem": "npm"},
    {"name": "log4j-core", "ecosystem": "Maven"},
    {"name": "spring-core", "ecosystem": "Maven"},
    {"name": "jackson-databind", "ecosystem": "Maven"},
    {"name": "struts2-core", "ecosystem": "Maven"},
]


def fetch_osv_package(name, ecosystem):
    results = []
    try:
        data = http_post(f"{OSV_API}/query",
                         {"package": {"name": name, "ecosystem": ecosystem}})
        for vuln in data.get("vulns", []):
            cvss_score, severity = 0.0, "MEDIUM"
            for sv in vuln.get("severity", []):
                m = re.search(r"(\d+\.?\d*)", sv.get("score", ""))
                if m:
                    cvss_score = float(m.group(1))
                    severity = ("CRITICAL" if cvss_score >= 9 else
                                "HIGH" if cvss_score >= 7 else
                                "MEDIUM" if cvss_score >= 4 else "LOW")
                    break
            fixed = []
            for aff in vuln.get("affected", []):
                for rng in aff.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fixed.append(f"fixed in {evt['fixed']}")
            refs = [r.get("url", "") for r in vuln.get("references", [])[:2]]
            results.append({
                "id": vuln.get("id", "?"), "severity": severity, "cvss": cvss_score,
                "desc": (vuln.get("summary") or vuln.get("details", "N/A"))[:250],
                "published": vuln.get("published", "?")[:10], "versions": fixed[:3],
                "refs": refs, "source": "OSV",
                "patch": next((v for v in fixed if "fixed" in v),
                              refs[0] if refs else "See osv.dev"),
                "keyword": name.lower(),
            })
    except Exception as e:
        warn(f"OSV fetch failed [{name}]: {e}")
    return results


def sync_osv(force=False):
    meta, db = load_meta(), load_cve_cache()
    if not force and not needs_refresh("osv", meta):
        info("OSV cache fresh - skipping")
        return db.get("osv", {})
    hdr(f"OSV - syncing {len(OSV_PACKAGES)} packages")
    osv_db = {}
    for i, pkg in enumerate(OSV_PACKAGES):
        info(f"[{i+1}/{len(OSV_PACKAGES)}] OSV: {pkg['name']} ({pkg['ecosystem']})")
        cves = fetch_osv_package(pkg["name"], pkg["ecosystem"])
        if cves:
            key = pkg["name"].lower().replace("-", "").replace("_", "")
            osv_db.setdefault(key, []).extend(cves)
        time.sleep(0.2)
        set_progress(int((i + 1) / len(OSV_PACKAGES) * 100))
    db["osv"] = osv_db
    save_cve_cache(db)
    meta["last_osv"] = time.time()
    save_meta(meta)
    good(f"OSV sync complete - {sum(len(v) for v in osv_db.values())} CVEs")
    return osv_db

# ════════════════════════════════════════════════════════════════
# SOURCE 3 — CISA KEV
# ════════════════════════════════════════════════════════════════
CISA_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")


def sync_cisa(force=False):
    meta, db = load_meta(), load_cve_cache()
    if not force and not needs_refresh("cisa", meta):
        info(f"CISA KEV cache fresh - {len(db.get('cisa', {}))} entries")
        return db.get("cisa", {})
    hdr("CISA KEV - downloading actively-exploited catalog")
    kev_map = {}
    try:
        data = http_get(CISA_URL, timeout=30)
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID", "")
            if cid:
                kev_map[cid] = {
                    "product": v.get("product", ""),
                    "vendor": v.get("vendorProject", ""),
                    "desc": v.get("shortDescription", "")[:200],
                    "due_date": v.get("dueDate", ""),
                    "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "date_added": v.get("dateAdded", ""),
                    "source": "CISA-KEV",
                }
        db["cisa"] = kev_map
        save_cve_cache(db)
        meta["last_cisa"] = time.time()
        save_meta(meta)
        good(f"CISA KEV sync complete - {len(kev_map)} actively-exploited CVEs")
    except Exception as e:
        warn(f"CISA KEV sync failed: {e}")
    return kev_map

# ════════════════════════════════════════════════════════════════
# SOURCE 4 — GitHub Security Advisories
# ════════════════════════════════════════════════════════════════
GITHUB_ADV_URL = "https://api.github.com/advisories"


def sync_github(force=False):
    meta, db = load_meta(), load_cve_cache()
    if not force and not needs_refresh("github", meta):
        info("GitHub Advisories cache fresh - skipping")
        return db.get("github", {})
    hdr("GitHub Advisories - fetching latest")
    gh_db = {}
    try:
        hdrs = {"Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}
        if GITHUB_TOKEN:
            hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        data = http_get(f"{GITHUB_ADV_URL}?per_page=100&sort=updated&direction=desc",
                        headers=hdrs, timeout=20)
        for adv in data:
            cve_id = adv.get("cve_id", "") or adv.get("ghsa_id", "")
            if not cve_id:
                continue
            sev = adv.get("severity", "UNKNOWN").upper()
            if sev == "MODERATE":
                sev = "MEDIUM"
            keywords, versions = [], []
            for v in adv.get("vulnerabilities", []):
                kw = v.get("package", {}).get("name", "").lower()
                if kw:
                    keywords.append(kw)
                if v.get("vulnerable_version_range"):
                    versions.append(f"affected: {v['vulnerable_version_range']}")
                if v.get("patched_versions"):
                    versions.append(f"fixed: {v['patched_versions']}")
            refs = [r.get("url", "") for r in adv.get("references", [])[:2]
                    if isinstance(r, dict)]
            entry = {
                "id": cve_id, "severity": sev,
                "cvss": float(adv.get("cvss", {}).get("score", 0.0) or 0.0),
                "desc": (adv.get("summary") or adv.get("description", ""))[:250],
                "published": (adv.get("published_at") or "?")[:10],
                "versions": versions[:3], "refs": refs,
                "source": "GitHub-Advisories",
                "patch": versions[-1] if versions else (refs[0] if refs else "See GitHub"),
            }
            for kw in keywords:
                clean = kw.replace("-", "").replace("_", "").replace(".", "")
                gh_db.setdefault(clean, [])
                if not any(c["id"] == cve_id for c in gh_db[clean]):
                    gh_db[clean].append({**entry, "keyword": kw})
        db["github"] = gh_db
        save_cve_cache(db)
        meta["last_github"] = time.time()
        save_meta(meta)
        good(f"GitHub Advisories sync complete - "
             f"{sum(len(v) for v in gh_db.values())} CVEs")
    except Exception as e:
        warn(f"GitHub Advisories sync failed: {e}")
    return gh_db

# ════════════════════════════════════════════════════════════════
# MASTER SYNC
# ════════════════════════════════════════════════════════════════
def sync_all_cves(force=False, include_watchlist=True):
    """Sync all sources. Returns (merged_db, cisa_map, watchlist_db)."""
    hdr("SYNCING LIVE CVE DATABASES")
    nvd_db = sync_nvd(force)
    osv_db = sync_osv(force)
    cisa_map = sync_cisa(force)
    github_db = sync_github(force)
    watchlist_db = sync_watchlist(force) if include_watchlist else {}

    merged = {}
    for src_db in [nvd_db, osv_db, github_db]:
        for keyword, cves in src_db.items():
            key = keyword.lower().replace("-", "").replace("_", "").replace(".", "")
            merged.setdefault(key, [])
            for cve in cves:
                if not any(c["id"] == cve["id"] for c in merged[key]):
                    merged[key].append(cve)

    for cve_id, entry in watchlist_db.items():
        if not entry.get("pending"):
            key = cve_id.lower().replace("-", "")
            merged.setdefault(key, [])
            if not any(c["id"] == cve_id for c in merged[key]):
                merged[key].append(entry)

    kev_count = 0
    for cves in merged.values():
        for cve in cves:
            if cve["id"] in cisa_map:
                cve["known_exploited"] = True
                cve["kev"] = cisa_map[cve["id"]]
                cve["severity"] = "CRITICAL"
                kev_count += 1

    total = sum(len(v) for v in merged.values())
    good(f"Merged database: {total} CVEs | {kev_count} actively exploited (KEV)")
    good(f"Watchlist: {len(watchlist_db)} Day-1 CVEs tracked")
    return merged, cisa_map, watchlist_db

# ════════════════════════════════════════════════════════════════
# CVE LOOKUP / CROSS-REFERENCE
# ════════════════════════════════════════════════════════════════
def lookup_cves(tech_list, merged_db, banner_text=""):
    findings, seen = [], set()
    combined = " ".join(t.get("name", "").lower() + " " + t.get("version", "").lower()
                        for t in tech_list) + " " + banner_text.lower()
    for keyword, cves in merged_db.items():
        if keyword in combined or any(
                keyword in t.get("name", "").lower().replace("-", "").replace("_", "")
                for t in tech_list):
            for cve in cves:
                uid = cve["id"] + keyword
                if uid not in seen:
                    seen.add(uid)
                    findings.append({**cve, "matched_keyword": keyword})
    findings.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(x["severity"], 4),
        -x.get("cvss", 0)))
    return findings


def cross_reference_watchlist(host_results, watchlist_db, cisa_map):
    matches, seen = [], set()
    for result in host_results:
        techs = [t["name"].lower() for t in result.get("technologies", [])]
        for _, svc in result.get("services", {}).items():
            techs.append(str(svc).lower())
        if not techs:
            continue
        for cve_id, cve_entry in watchlist_db.items():
            uid = f"{cve_id}:{result['host']}"
            if uid in seen:
                continue
            desc = (cve_entry.get("desc", "") + " "
                    + cve_entry.get("affected_product", "")).lower()
            kw = cve_entry.get("keyword", "").lower()
            matched = next((t for t in techs if len(t) > 2 and (t in desc or t in kw)), None)
            if matched:
                seen.add(uid)
                entry = {**cve_entry, "host": result["host"], "ip": result["ip"],
                         "matched_reason": f"Detected: {matched}", "watchlist": True}
                if cve_id in cisa_map:
                    entry["known_exploited"] = True
                    entry["kev"] = cisa_map[cve_id]
                    entry["severity"] = "CRITICAL"
                matches.append(entry)
    matches.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(x["severity"], 4),
        -x.get("cvss", 0)))
    return matches

# ════════════════════════════════════════════════════════════════
# DOMAIN RECON
# ════════════════════════════════════════════════════════════════
WORDLIST = list(dict.fromkeys([
    "www", "web", "app", "apps", "portal", "m", "mobile", "api", "api1", "api2",
    "apiv1", "apiv2", "rest", "graphql", "gateway", "proxy", "backend", "frontend",
    "dev", "dev1", "develop", "staging", "stage", "stg", "uat", "preprod", "qa",
    "test", "test1", "sandbox", "demo", "poc", "beta", "lab", "admin", "panel",
    "console", "cpanel", "phpmyadmin", "pma", "manage", "mgmt", "auth", "login",
    "sso", "oauth", "idp", "iam", "accounts", "mail", "smtp", "imap", "webmail",
    "owa", "mx", "mx1", "mx2", "ns", "ns1", "ns2", "dns", "ftp", "sftp", "files",
    "upload", "download", "media", "share", "storage", "vpn", "remote", "citrix",
    "rdp", "jump", "bastion", "cdn", "static", "assets", "img", "images", "video",
    "monitor", "grafana", "prometheus", "kibana", "elastic", "splunk", "jenkins",
    "ci", "cicd", "build", "deploy", "git", "gitlab", "repo", "registry", "docker",
    "k8s", "kubernetes", "nexus", "sonar", "vault", "jira", "confluence", "wiki",
    "docs", "kb", "intranet", "internal", "sharepoint", "db", "db1", "database",
    "mysql", "postgres", "mongo", "redis", "mssql", "security", "soc", "siem",
    "waf", "firewall", "scanner", "router", "switch", "fw", "dmz", "wifi",
    "cloud", "aws", "azure", "gcp", "s3", "shop", "store", "ecommerce", "cart",
    "checkout", "payment", "billing", "hr", "erp", "crm", "careers", "jobs",
    "prod", "prod1", "live", "server", "server1", "host", "node", "vm", "box",
    "wordpress", "wp", "blog", "cms", "forum", "chat", "old", "new", "legacy",
    "backup", "temp", "v1", "v2", "v3",
]))


def clean_domain(raw):
    raw = (raw or "").strip()
    if not raw or raw.startswith("#"):
        return None
    raw = re.sub(r"^https?://", "", raw, flags=re.I)
    raw = raw.split("/")[0].split("?")[0].split(":")[0].strip().lower()
    return raw or None


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def enum_crtsh(domain):
    found, seen = [], set()
    try:
        info("crt.sh: querying certificate transparency logs")
        data = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        names = set()
        for entry in data:
            for nm in (entry.get("name_value", "") or "").splitlines():
                nm = nm.strip().lower().lstrip("*.")
                if nm.endswith(domain) and nm not in names:
                    names.add(nm)

        def chk(nm):
            ip = resolve(nm)
            return (nm, ip) if ip else None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            for r in ex.map(chk, list(names)[:300]):
                if r and r[0] not in seen:
                    seen.add(r[0])
                    found.append({"host": r[0], "ip": r[1], "method": "crt.sh"})
        good(f"crt.sh: {len(found)} live subdomains resolved")
    except Exception as e:
        warn(f"crt.sh failed: {e}")
    return found


def enum_hackertarget(domain):
    found = []
    try:
        info("HackerTarget: querying passive DNS")
        text = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                        timeout=20, as_text=True)
        if any(k in text.lower() for k in ["api count", "error", "limit"]):
            warn("HackerTarget: rate limited or no data")
            return found
        for line in text.splitlines():
            if "," in line:
                host, ip = line.split(",", 1)
                host = host.strip().lower()
                if host.endswith(f".{domain}"):
                    found.append({"host": host, "ip": ip.strip(),
                                  "method": "hackertarget"})
        good(f"HackerTarget: {len(found)} subdomains found")
    except Exception as e:
        warn(f"HackerTarget failed: {e}")
    return found


def enum_alienvault(domain):
    found, seen = [], set()
    try:
        info("AlienVault OTX: querying passive DNS")
        data = http_get(f"https://otx.alienvault.com/api/v1/indicators/"
                        f"domain/{domain}/passive_dns", timeout=25)
        for entry in data.get("passive_dns", []):
            host = entry.get("hostname", "").strip().lower()
            ip = entry.get("address", "").strip()
            if host.endswith(f".{domain}") and host not in seen and ip:
                seen.add(host)
                found.append({"host": host, "ip": ip, "method": "alienvault"})
        good(f"AlienVault OTX: {len(found)} subdomains found")
    except Exception as e:
        warn(f"AlienVault OTX failed: {e}")
    return found


def enum_bruteforce(domain):
    info(f"Brute-force: testing {len(WORDLIST)} common names")
    found = []

    def chk(sub):
        host = f"{sub}.{domain}"
        ip = resolve(host)
        return {"host": host, "ip": ip, "method": "bruteforce"} if ip else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        for r in ex.map(chk, WORDLIST):
            if r:
                found.append(r)
    good(f"Brute-force: {len(found)} subdomains found")
    return found

# ════════════════════════════════════════════════════════════════
# PORT SCAN + FINGERPRINT
# ════════════════════════════════════════════════════════════════
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
             1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]
QUICK_PORTS = [21, 22, 80, 443, 8080, 8443, 3306, 6379, 9200, 27017, 5432]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Dev", 9200: "Elasticsearch", 27017: "MongoDB",
}


def scan_ports(ip, ports, timeout=1.0):
    open_ports = []

    def chk(port):
        try:
            s = socket.socket()
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return port if r == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for p in ex.map(chk, ports):
            if p:
                open_ports.append(p)
    return sorted(open_ports)


HEADER_CHECKS = [
    ("server", r"apache[\/ ]([\d\.]+)?", "apache"),
    ("server", r"nginx[\/ ]([\d\.]+)?", "nginx"),
    ("server", r"microsoft-iis[\/ ]([\d\.]+)?", "iis"),
    ("server", r"tomcat[\/ ]([\d\.]+)?", "tomcat"),
    ("server", r"openssl[\/ ]([\d\.]+)?", "openssl"),
    ("x-powered-by", r"php[\/ ]([\d\.]+)?", "php"),
    ("x-powered-by", r"asp\.net", "aspnet"),
    ("x-powered-by", r"express", "express"),
    ("x-generator", r"drupal", "drupal"),
    ("x-generator", r"wordpress", "wordpress"),
    ("x-jenkins", "", "jenkins"),
]
BODY_CHECKS = [
    (r"wp-content|wp-includes|wordpress", "wordpress"),
    (r"drupal\.js|drupal\.settings", "drupal"),
    (r"joomla", "joomla"), (r"laravel", "laravel"),
    (r"django|csrfmiddlewaretoken", "django"), (r"flask", "flask"),
    (r"jquery[\./]", "jquery"), (r"grafana", "grafana"),
    (r"jenkins", "jenkins"), (r"gitlab", "gitlab"), (r"kibana", "kibana"),
    (r"phpmyadmin", "phpmyadmin"), (r"tomcat", "tomcat"),
]
SEC_HEADERS = ["strict-transport-security", "content-security-policy",
               "x-frame-options", "x-content-type-options",
               "referrer-policy", "permissions-policy"]


def grab_http(host, port=80, use_ssl=False, timeout=6):
    hdrs = {}
    try:
        prefix = "https" if use_ssl else "http"
        url = f"{prefix}://{host}:{port}/"
        if HAS_REQUESTS:
            r = req_lib.get(url, timeout=timeout, verify=False, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 CVEScanPro/5.0"})
            for k, v in r.headers.items():
                hdrs[k.lower()] = v
            hdrs["_status"] = str(r.status_code)
            hdrs["_body_snippet"] = r.text[:1500]
    except Exception:
        pass
    return hdrs


def fingerprint(hdrs, body=""):
    techs, missing = [], []
    h = {k.lower(): str(v).lower() for k, v in hdrs.items()}
    b = body.lower()
    for hdr_key, pattern, tech in HEADER_CHECKS:
        for mk in [k for k in h if re.match(hdr_key, k)]:
            val = h.get(mk, "")
            if not pattern or re.search(pattern, val, re.I):
                m = re.search(pattern, val, re.I) if pattern else None
                ver = m.group(1) if (m and m.lastindex) else ""
                if not any(t["name"] == tech for t in techs):
                    techs.append({"name": tech, "version": ver or "",
                                  "source": f"header:{mk}"})
                break
    for pattern, tech in BODY_CHECKS:
        if re.search(pattern, b, re.I) and not any(t["name"] == tech for t in techs):
            techs.append({"name": tech, "version": "", "source": "body"})
    for sh in SEC_HEADERS:
        if sh not in h:
            missing.append(sh)
    return techs, missing


def analyse_host(host_entry, merged_db, full=False):
    host, ip = host_entry["host"], host_entry["ip"]
    result = {"host": host, "ip": ip, "ports": [], "services": {},
              "technologies": [], "missing_sec_headers": [], "banners": {}, "cves": []}
    info(f"Analysing {host} ({ip})")
    ports = scan_ports(ip, TOP_PORTS if full else QUICK_PORTS)
    result["ports"] = ports
    if not ports:
        warn(f"No open ports on {host}")
        return result
    good(f"{host}: ports {', '.join(map(str, ports))}")

    all_banners, all_techs = "", []
    for port in ports:
        result["services"][port] = SERVICE_MAP.get(port, f"port/{port}")
        if port in (80, 8080, 8000, 8888):
            hdrs = grab_http(host, port, use_ssl=False)
        elif port in (443, 8443):
            hdrs = grab_http(host, port, use_ssl=True)
        else:
            hdrs = {}
        if hdrs:
            t, ms = fingerprint(hdrs, hdrs.get("_body_snippet", ""))
            all_techs.extend(t)
            result["missing_sec_headers"].extend(ms)
            all_banners += str(hdrs)

    seen = set()
    for t in all_techs:
        if t["name"] not in seen:
            seen.add(t["name"])
            result["technologies"].append(t)
    if result["technologies"]:
        good(f"{host}: tech = " + ", ".join(t["name"] for t in result["technologies"]))

    result["cves"] = lookup_cves(result["technologies"], merged_db, all_banners)
    result["missing_sec_headers"] = sorted(set(result["missing_sec_headers"]))
    n_crit = sum(1 for c in result["cves"] if c["severity"] == "CRITICAL")
    if result["cves"]:
        warn(f"{host}: {len(result['cves'])} CVEs ({n_crit} critical)")
    else:
        good(f"{host}: no CVEs matched")
    return result


def run_domain_scan(domain, merged_db, full=False):
    """Full recon + CVE scan for one domain. Returns list of host results."""
    domain = clean_domain(domain) or domain
    hdr(f"SCANNING: {domain}")

    all_hosts = []
    root_ip = resolve(domain)
    if root_ip:
        all_hosts.append({"host": domain, "ip": root_ip, "method": "root"})
        good(f"Root: {domain} -> {root_ip}")
    else:
        warn(f"Root domain {domain} did not resolve")

    hdr(f"SUBDOMAIN ENUMERATION - {domain}")
    all_hosts += enum_crtsh(domain)
    all_hosts += enum_hackertarget(domain)
    all_hosts += enum_alienvault(domain)
    all_hosts += enum_bruteforce(domain)

    seen, unique = set(), []
    for h in all_hosts:
        if h["host"] not in seen:
            seen.add(h["host"])
            unique.append(h)
    good(f"Unique hosts discovered: {len(unique)}")

    hdr("PORT SCAN + FINGERPRINT + CVE MAPPING")
    results = []
    for idx, he in enumerate(unique):
        results.append(analyse_host(he, merged_db, full=full))
        set_progress(int((idx + 1) / max(len(unique), 1) * 100))
    return results


def group_virtual_hosts(results):
    """
    Detect virtual hosting: multiple discovered hostnames served from the
    same IP address. Returns a list of {ip, hosts:[...], count}.
    """
    by_ip = {}
    for r in results:
        ip = r.get("ip")
        if ip:
            by_ip.setdefault(ip, []).append(r.get("host"))
    vhosts = [{"ip": ip, "hosts": sorted(set(names)), "count": len(set(names))}
              for ip, names in by_ip.items() if len(set(names)) > 1]
    vhosts.sort(key=lambda x: -x["count"])
    return vhosts
