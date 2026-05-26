#!/usr/bin/env python3
"""
CVEScan Pro - Web Edition :: ai.py
Multi-provider AI layer. Adds AI analysis on top of the raw scan data.

Supported providers (use whichever API key you have):
  * gemini     - Google Gemini
  * openai     - OpenAI (GPT)
  * anthropic  - Anthropic (Claude)
  * groq       - Groq (fast Llama inference)

All API keys are read from environment variables - NEVER hard-coded.
The active provider is chosen by AI_PROVIDER, or auto-selected from
whichever key is present. It can also be switched at runtime from the UI.

Capabilities (provider-agnostic):
  explain_cve(), executive_summary(), triage_findings(), ask()
"""

import os, json

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ════════════════════════════════════════════════════════════════
# PROVIDER REGISTRY
# ════════════════════════════════════════════════════════════════
def _env(name, default=""):
    return os.environ.get(name, default).strip()

PROVIDERS = {
    "gemini": {
        "label": "Google Gemini",
        "key": _env("GEMINI_API_KEY"),
        "model": _env("GEMINI_MODEL", "gemini-2.0-flash"),
    },
    "openai": {
        "label": "OpenAI (GPT)",
        "key": _env("OPENAI_API_KEY"),
        "model": _env("OPENAI_MODEL", "gpt-4.1-mini"),
    },
    "anthropic": {
        "label": "Anthropic (Claude)",
        "key": _env("ANTHROPIC_API_KEY"),
        "model": _env("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
    },
    "groq": {
        "label": "Groq (Llama)",
        "key": _env("GROQ_API_KEY"),
        "model": _env("GROQ_MODEL", "llama-3.3-70b-versatile"),
    },
}

# auto-selection priority when AI_PROVIDER is not set
_PRIORITY = ["gemini", "openai", "anthropic", "groq"]

# runtime override (set from the UI); falls back to env / auto
_OVERRIDE = None


def configured_providers():
    """List of provider names that have an API key set."""
    return [p for p in _PRIORITY if PROVIDERS[p]["key"]]


def active_provider():
    """Resolve which provider to use right now."""
    if _OVERRIDE and PROVIDERS.get(_OVERRIDE, {}).get("key"):
        return _OVERRIDE
    env_choice = _env("AI_PROVIDER").lower()
    if env_choice in PROVIDERS and PROVIDERS[env_choice]["key"]:
        return env_choice
    avail = configured_providers()
    return avail[0] if avail else None


def set_provider(name):
    """Switch the active provider at runtime. Returns True on success."""
    global _OVERRIDE
    if name in PROVIDERS and PROVIDERS[name]["key"]:
        _OVERRIDE = name
        return True
    return False


def ai_available():
    """True if at least one provider is usable."""
    return HAS_REQUESTS and active_provider() is not None


def ai_status():
    """Full status: active provider, model, and per-provider availability."""
    active = active_provider()
    return {
        "available": ai_available(),
        "active": active,
        "active_label": PROVIDERS[active]["label"] if active else None,
        "model": PROVIDERS[active]["model"] if active else None,
        "requests_lib": HAS_REQUESTS,
        "providers": {
            name: {
                "label": p["label"],
                "configured": bool(p["key"]),
                "model": p["model"],
            } for name, p in PROVIDERS.items()
        },
    }


# ════════════════════════════════════════════════════════════════
# LOW-LEVEL PROVIDER CALLS
# ════════════════════════════════════════════════════════════════
def _call_gemini(key, model, prompt, temperature, max_tokens):
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent")
    r = requests.post(
        url,
        headers={"Content-Type": "application/json", "x-goog-api-key": key},
        json={
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature,
                                 "maxOutputTokens": max_tokens},
        }, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(_err("Gemini", r))
    data = r.json()
    try:
        parts = data["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError):
        reason = (data.get("candidates", [{}])[0].get("finishReason")
                  or data.get("promptFeedback", {}).get("blockReason")
                  or "no content")
        raise RuntimeError(f"Gemini returned no usable text ({reason}).")


def _call_anthropic(key, model, prompt, temperature, max_tokens):
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": model, "max_tokens": max_tokens,
              "temperature": temperature,
              "messages": [{"role": "user", "content": prompt}]},
        timeout=60)
    if r.status_code != 200:
        raise RuntimeError(_err("Claude", r))
    data = r.json()
    text = "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text").strip()
    if not text:
        raise RuntimeError("Claude returned no usable text "
                            f"({data.get('stop_reason', 'unknown')}).")
    return text


def _call_openai_compatible(label, base_url, key, model,
                            prompt, temperature, max_tokens):
    """Used for both OpenAI and Groq (Groq is OpenAI-API-compatible)."""
    headers = {"Authorization": f"Bearer {key}",
               "Content-Type": "application/json"}
    body = {"model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature, "max_tokens": max_tokens}
    r = requests.post(base_url, headers=headers, json=body, timeout=60)

    # some newer models reject temperature / max_tokens - retry minimal
    if r.status_code == 400:
        msg = ""
        try:
            msg = r.json().get("error", {}).get("message", "")
        except Exception:
            pass
        if any(k in msg for k in ("max_tokens", "max_completion_tokens",
                                  "temperature", "unsupported")):
            r = requests.post(base_url, headers=headers, json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_completion_tokens": max_tokens,
            }, timeout=60)

    if r.status_code != 200:
        raise RuntimeError(_err(label, r))
    data = r.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError):
        raise RuntimeError(f"{label} returned no usable text.")


def _err(label, resp):
    detail = ""
    try:
        j = resp.json()
        detail = (j.get("error", {}).get("message")
                  or j.get("error", {}).get("type") or "")
    except Exception:
        detail = resp.text[:200]
    return f"{label} API error {resp.status_code}: {detail}"


# ════════════════════════════════════════════════════════════════
# DISPATCH
# ════════════════════════════════════════════════════════════════
def _call(prompt, temperature=0.3, max_tokens=2048):
    """Send a prompt to the active provider. Returns text or raises."""
    if not HAS_REQUESTS:
        raise RuntimeError("The 'requests' library is not installed.")
    name = active_provider()
    if not name:
        raise RuntimeError("No AI provider configured. Set one of "
                           "GEMINI_API_KEY / OPENAI_API_KEY / "
                           "ANTHROPIC_API_KEY / GROQ_API_KEY.")
    p = PROVIDERS[name]
    key, model = p["key"], p["model"]
    try:
        if name == "gemini":
            return _call_gemini(key, model, prompt, temperature, max_tokens)
        if name == "anthropic":
            return _call_anthropic(key, model, prompt, temperature, max_tokens)
        if name == "openai":
            return _call_openai_compatible(
                "OpenAI", "https://api.openai.com/v1/chat/completions",
                key, model, prompt, temperature, max_tokens)
        if name == "groq":
            return _call_openai_compatible(
                "Groq", "https://api.groq.com/openai/v1/chat/completions",
                key, model, prompt, temperature, max_tokens)
    except requests.RequestException as e:
        raise RuntimeError(f"Could not reach the {p['label']} API: {e}")
    raise RuntimeError(f"Unknown provider: {name}")


def _call_json(prompt, temperature=0.2):
    """Call the active provider and parse a JSON object from the reply."""
    raw = _call(prompt, temperature=temperature)
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        if "```" in cleaned:
            cleaned = cleaned[:cleaned.rfind("```")]
    cleaned = cleaned.strip().strip("`").strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1:
        cleaned = cleaned[start:end + 1]
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"_raw": raw}


# ════════════════════════════════════════════════════════════════
# CAPABILITY 1 - explain a single CVE
# ════════════════════════════════════════════════════════════════
def explain_cve(cve):
    """Plain-English risk explanation + patch-priority verdict for one CVE."""
    kev = cve.get("known_exploited")
    prompt = f"""You are a senior security analyst writing for a client report.
Explain this CVE clearly and concisely for a technical-but-busy IT manager.

CVE ID: {cve.get('id')}
Severity: {cve.get('severity')}   CVSS: {cve.get('cvss')}
Affected: {cve.get('affected_product') or cve.get('matched_keyword') or 'unknown'}
Actively exploited (CISA KEV): {"YES" if kev else "no"}
Description: {cve.get('desc', '')}

Return ONLY a JSON object with these keys:
  "summary"       : 2-3 sentence plain-English explanation of the vulnerability
  "attack"        : 1-2 sentences on how an attacker would realistically abuse it
  "exploit_status": one of "PUBLIC EXPLOIT LIKELY", "POC POSSIBLE", "NO KNOWN EXPLOIT" - your best assessment of whether a working public exploit/PoC exists
  "verdict"       : one of "PATCH TODAY", "PATCH THIS WEEK", "SCHEDULE", "MONITOR"
  "verdict_why"   : 1 sentence justifying the verdict
  "remediation"   : a short actionable fix recommendation (1-2 sentences)
No markdown, no backticks, just the JSON object."""
    result = _call_json(prompt)
    result["cve_id"] = cve.get("id")
    return result


# ════════════════════════════════════════════════════════════════
# CAPABILITY 2 - executive summary of a whole scan
# ════════════════════════════════════════════════════════════════
def _scan_digest(scan):
    """Compress a scan result into a compact text digest for the prompt."""
    lines = [f"Targets: {', '.join(scan.get('targets', []))}"]
    domains = scan.get("domains", [])
    all_cves = []
    for d in domains:
        for host in d.get("results", []):
            for c in host.get("cves", []):
                all_cves.append(c)
        lines.append(f"  Domain {d.get('domain')}: "
                      f"{len(d.get('results', []))} hosts, "
                      f"{sum(len(h.get('cves', [])) for h in d.get('results', []))} CVEs, "
                      f"{len(d.get('wl_matches', []))} watchlist hits")
    sev = {}
    for c in all_cves:
        sev[c["severity"]] = sev.get(c["severity"], 0) + 1
    kev = sum(1 for c in all_cves if c.get("known_exploited"))
    lines.append(f"Severity spread: {sev}")
    lines.append(f"Actively exploited (KEV): {kev}")
    top = sorted(all_cves, key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3),
        -x.get("cvss", 0)))[:15]
    lines.append("Top findings:")
    for c in top:
        lines.append(f"  {c['id']} [{c['severity']} {c.get('cvss')}] "
                     f"{c.get('desc', '')[:110]}")
    return "\n".join(lines)


def executive_summary(scan):
    """Generate a board-level executive summary of the scan."""
    digest = _scan_digest(scan)
    prompt = f"""You are a lead penetration tester writing the Executive Summary
section of a vulnerability assessment report for senior management.

SCAN DATA:
{digest}

Write a concise executive summary. Return ONLY a JSON object with keys:
  "overall_risk"  : one of "CRITICAL", "HIGH", "MEDIUM", "LOW"
  "headline"      : one punchy sentence describing the security posture
  "summary"       : 3-5 sentences of plain-English assessment for executives
  "key_risks"     : array of 3-5 short strings, the most important risks
  "priorities"    : array of 3-5 short strings, recommended actions in priority order
No markdown, no backticks, just the JSON object."""
    return _call_json(prompt)


# ════════════════════════════════════════════════════════════════
# CAPABILITY 3 - remediation triage
# ════════════════════════════════════════════════════════════════
def triage_findings(cves, limit=25):
    """Produce a prioritised remediation plan from a list of CVEs."""
    subset = sorted(cves, key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3),
        -x.get("cvss", 0)))[:limit]
    listing = "\n".join(
        f"- {c['id']} [{c['severity']} CVSS {c.get('cvss')}] "
        f"host={c.get('host', '?')} kev={bool(c.get('known_exploited'))} "
        f"product={c.get('affected_product') or c.get('matched_keyword') or '?'}"
        for c in subset)
    prompt = f"""You are a security remediation lead. Given these scan findings,
build a prioritised remediation plan grouped into time-based waves.

FINDINGS:
{listing}

Return ONLY a JSON object with key "waves" = array of objects, each:
  "wave"   : e.g. "Immediate (24-48h)", "This week", "This month"
  "rationale" : 1 sentence on why these belong in this wave
  "items"  : array of objects {{"cve": "...", "action": "short fix action"}}
No markdown, no backticks, just the JSON object."""
    return _call_json(prompt)


# ════════════════════════════════════════════════════════════════
# CAPABILITY 4 - free-form Q&A
# ════════════════════════════════════════════════════════════════
def ask(question, scan):
    """Answer a free-form question grounded in the scan data."""
    digest = _scan_digest(scan)
    prompt = f"""You are a security analyst assistant. Answer the user's question
using ONLY the scan data below. If the data does not contain the answer, say so.
Be concise and practical. Plain text, no markdown headers.

SCAN DATA:
{digest}

USER QUESTION: {question}

ANSWER:"""
    return _call(prompt, temperature=0.4, max_tokens=1024)


# ════════════════════════════════════════════════════════════════
# CAPABILITY 5 - AI deep analysis (fingerprint correlation +
#                exploitability assessment)
# ════════════════════════════════════════════════════════════════
def _host_digest(scan, limit=20):
    """Compact per-host fingerprint digest for the deep-analysis prompt."""
    lines = []
    hosts = []
    for d in scan.get("domains", []):
        ip_groups = {}
        for h in d.get("results", []):
            ip_groups.setdefault(h.get("ip", "?"), []).append(h.get("host"))
            hosts.append((d.get("domain"), h))
        # surface shared IPs (virtual hosting)
        shared = {ip: names for ip, names in ip_groups.items() if len(names) > 1}
        if shared:
            lines.append(f"Domain {d.get('domain')} - shared IPs (virtual hosts): "
                         + "; ".join(f"{ip} -> {', '.join(n)}"
                                     for ip, n in list(shared.items())[:5]))
    # rank hosts by exposure (open ports + CVE count)
    hosts.sort(key=lambda x: -(len(x[1].get("ports", []))
                               + len(x[1].get("cves", []))))
    for domain, h in hosts[:limit]:
        if not h.get("ports"):
            continue
        techs = ", ".join(f"{t['name']}{('/' + t['version']) if t.get('version') else ''}"
                          for t in h.get("technologies", [])) or "none detected"
        lines.append(
            f"Host {h.get('host')} ({h.get('ip')}): "
            f"ports={h.get('ports')}; "
            f"services={list(h.get('services', {}).values())}; "
            f"tech={techs}; "
            f"missing_security_headers={h.get('missing_sec_headers', [])}; "
            f"matched_CVEs={len(h.get('cves', []))}")
    return "\n".join(lines) or "No hosts with open ports were found."


def deep_analysis(scan):
    """
    AI-assisted deep analysis. Reasons over the collected fingerprints to:
      - surface likely CVEs the keyword matcher may have missed,
      - assess exploitability / exposure for prioritisation,
      - flag misconfigurations and risky exposed services.
    This is defensive enrichment of already-collected recon data - it does
    NOT attempt or simulate any exploitation against the targets.
    """
    digest = _host_digest(scan)
    prompt = f"""You are a senior penetration tester reviewing reconnaissance
data from an AUTHORISED vulnerability assessment. Using only the fingerprint
data below, produce a deeper analysis to help the defender prioritise.

Do NOT provide exploit code or step-by-step intrusion instructions. Focus on
identification, risk assessment and remediation guidance only.

RECON DATA:
{digest}

Return ONLY a JSON object with these keys:
  "exposed_services" : array of objects {{"host","service","why_risky"}} for
                       internet-exposed services that should not be public
                       (databases, admin panels, dev ports, etc.)
  "likely_cves"      : array of objects {{"host","cve_or_class","reason"}} -
                       vulnerabilities likely present given the detected
                       software/versions, that keyword matching may miss
  "misconfigurations": array of short strings - notable weaknesses
                       (missing security headers, weak TLS, etc.)
  "exploitability"   : array of objects {{"target","assessment","public_exploit"}}
                       where public_exploit is "likely"/"possible"/"unlikely"
  "priority_actions" : array of 3-6 short strings, what to fix first
No markdown, no backticks, just the JSON object."""
    return _call_json(prompt, temperature=0.3)
