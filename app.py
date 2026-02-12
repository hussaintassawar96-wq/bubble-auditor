import re
import time
import json
import hashlib
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st


# ---------------------------
# UI CONFIG
# ---------------------------
st.set_page_config(
    page_title="Bubble App Auditor",
    page_icon="🫧",
    layout="wide",
)

# ---------------------------
# HELPERS
# ---------------------------

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "BubbleAppAuditor/1.0 (+public-scan)"
})
REQUEST_TIMEOUT = 12


def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    # remove trailing spaces and keep trailing slash normalized later
    return u


def safe_get(url: str):
    """Return (status_code, headers, text, json_or_none, elapsed_seconds, error_or_none)"""
    t0 = time.time()
    try:
        r = SESSION.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        elapsed = time.time() - t0
        js = None
        ct = (r.headers.get("content-type") or "").lower()
        if "application/json" in ct or "text/json" in ct or ct.endswith("+json"):
            try:
                js = r.json()
            except Exception:
                js = None
        return r.status_code, dict(r.headers), r.text, js, elapsed, None
    except Exception as e:
        elapsed = time.time() - t0
        return None, {}, "", None, elapsed, str(e)


def safe_head(url: str):
    t0 = time.time()
    try:
        r = SESSION.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        elapsed = time.time() - t0
        return r.status_code, dict(r.headers), elapsed, None
    except Exception as e:
        elapsed = time.time() - t0
        return None, {}, elapsed, str(e)


def find_favicon(html: str, base_url: str):
    # try <link rel="icon" href="...">
    m = re.search(r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]*>', html, re.I)
    if m:
        tag = m.group(0)
        href = re.search(r'href=["\']([^"\']+)["\']', tag, re.I)
        if href:
            return urljoin(base_url, href.group(1))
    # fallback: /favicon.ico
    return urljoin(base_url, "/favicon.ico")


def find_og_image(html: str, base_url: str):
    m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    if m:
        return urljoin(base_url, m.group(1))
    return ""


def find_title(html: str):
    m = re.search(r"<title>(.*?)</title>", html, re.I | re.S)
    if m:
        t = re.sub(r"\s+", " ", m.group(1)).strip()
        return t[:120]
    return ""


def env_base_from_inputs(app_url: str, app_id: str, env: str) -> str:
    """
    env:
      - "live" -> https://<app_url> OR https://<app_id>.bubbleapps.io
      - "version-test" -> base + /version-test
    """
    app_url = normalize_url(app_url)
    app_id = (app_id or "").strip()

    if app_url:
        base = app_url
    else:
        # if user only gives app id like "yourapp-28503"
        if not app_id:
            return ""
        base = f"https://{app_id}.bubbleapps.io"

    base = base.rstrip("/")

    if env == "version-test":
        base = base + "/version-test"

    return base


def score_headers(h: dict):
    # Simple header scoring (public signal)
    checks = {
        "Content-Security-Policy": False,
        "Strict-Transport-Security": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "Permissions-Policy": False,
    }
    for k in list(checks.keys()):
        if any(hk.lower() == k.lower() for hk in h.keys()):
            checks[k] = True

    missing = [k for k, ok in checks.items() if not ok]
    present = [k for k, ok in checks.items() if ok]
    # score out of 100
    score = int((len(present) / len(checks)) * 100)
    return score, present, missing


def extract_swagger_stats(swagger_json):
    # swagger v2 / openapi v3
    paths = {}
    if isinstance(swagger_json, dict):
        if "paths" in swagger_json and isinstance(swagger_json["paths"], dict):
            paths = swagger_json["paths"]
    total_paths = len(paths)
    methods = 0
    for p, methods_obj in paths.items():
        if isinstance(methods_obj, dict):
            methods += len([k for k in methods_obj.keys() if k.lower() in ("get", "post", "put", "patch", "delete")])
    return total_paths, methods, list(paths.keys())[:25]


def extract_meta_datatypes(meta_json):
    """
    Bubble meta endpoint contents vary.
    We try multiple shapes safely.
    """
    types = []
    if not isinstance(meta_json, dict):
        return types

    # Possible keys seen in Bubble meta responses
    for key in ["data_types", "dataTypes", "types", "datatype", "datatypes"]:
        v = meta_json.get(key)
        if isinstance(v, list):
            # list of objects or strings
            for item in v:
                if isinstance(item, str):
                    types.append(item)
                elif isinstance(item, dict):
                    # common fields
                    nm = item.get("name") or item.get("display_name") or item.get("type") or item.get("id")
                    if nm:
                        types.append(str(nm))
        elif isinstance(v, dict):
            # dict keyed by type name
            types.extend([str(k) for k in v.keys()])

    # Some meta responses embed in "response" or similar
    for wrap_key in ["response", "data", "result"]:
        w = meta_json.get(wrap_key)
        if isinstance(w, dict):
            types.extend(extract_meta_datatypes(w))

    # dedupe and keep stable order
    seen = set()
    out = []
    for t in types:
        t = t.strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def probe_paths(base: str, paths):
    results = []
    for p in paths:
        url = urljoin(base + "/", p.lstrip("/"))
        code, headers, elapsed, err = safe_head(url)
        results.append({
            "path": p,
            "url": url,
            "status": code,
            "elapsed": elapsed,
            "error": err,
        })
    return results


def stable_key(*parts) -> str:
    s = "|".join([str(p) for p in parts])
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


# ---------------------------
# SCANNER (CACHED PER APP)
# ---------------------------

@st.cache_data(show_spinner=False)
def run_public_scan(app_url: str, app_id: str, env: str):
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        return {"error": "Missing App URL or Bubble App ID."}

    steps = []

    # 1) Homepage fetch
    home_url = base + "/"
    code, headers, html, js, elapsed, err = safe_get(home_url)
    steps.append(("Fetch homepage", home_url, code, elapsed, err))

    title = find_title(html) if html else ""
    og_img = find_og_image(html, base) if html else ""
    favicon = find_favicon(html, base) if html else urljoin(base, "/favicon.ico")

    # 2) Security headers (from homepage)
    header_score, header_present, header_missing = score_headers(headers or {})

    # 3) Bubble meta
    meta_url = base + "/api/1.1/meta"
    m_code, m_headers, m_text, m_json, m_elapsed, m_err = safe_get(meta_url)
    steps.append(("Fetch /api/1.1/meta", meta_url, m_code, m_elapsed, m_err))

    data_types = extract_meta_datatypes(m_json)

    # 4) Swagger
    swagger_url = base + "/api/1.1/meta/swagger.json"
    s_code, s_headers, s_text, s_json, s_elapsed, s_err = safe_get(swagger_url)
    steps.append(("Fetch swagger.json", swagger_url, s_code, s_elapsed, s_err))

    swagger_paths = 0
    swagger_methods = 0
    swagger_samples = []
    if isinstance(s_json, dict):
        swagger_paths, swagger_methods, swagger_samples = extract_swagger_stats(s_json)

    # 5) Admin-ish path probes (HEAD only)
    admin_candidates = [
        "/admin", "/dashboard", "/settings", "/super_admin", "/superadmin",
        "/backend", "/logs", "/api", "/version-test/admin"
    ]
    probe = probe_paths(base, admin_candidates)

    # 6) Performance-ish signals (public)
    html_size_kb = int((len(html.encode("utf-8")) / 1024)) if html else 0
    # simplistic: count script tags
    scripts = re.findall(r"<script\b", html or "", re.I)
    script_count = len(scripts)

    # Compute category scores (simple, transparent)
    # Security: based on headers + meta/swagger exposure + admin path responses
    exposed_meta = (m_code == 200 and isinstance(m_json, dict))
    exposed_swagger = (s_code == 200 and isinstance(s_json, dict))
    admin_public_hits = [x for x in probe if x.get("status") in (200, 301, 302) and x.get("path") in ("/admin", "/super_admin", "/superadmin")]

    security_score = 100
    if header_score < 100:
        security_score -= int((100 - header_score) * 0.4)
    if exposed_meta:
        security_score -= 18
    if exposed_swagger:
        security_score -= 12
    if admin_public_hits:
        security_score -= 15
    security_score = max(5, min(100, security_score))

    performance_score = 100
    if html_size_kb > 900:
        performance_score -= 18
    elif html_size_kb > 500:
        performance_score -= 10
    if script_count > 40:
        performance_score -= 12
    elif script_count > 25:
        performance_score -= 7
    performance_score = max(10, min(100, performance_score))

    maintainability_score = 100
    if swagger_paths > 40:
        maintainability_score -= 18
    elif swagger_paths > 20:
        maintainability_score -= 10
    if len(data_types) > 25:
        maintainability_score -= 12
    elif len(data_types) > 15:
        maintainability_score -= 7
    maintainability_score = max(10, min(100, maintainability_score))

    # Findings (right-side detail like NQU, but accurate to public scan)
    security_findings = []
    if exposed_meta:
        security_findings.append({
            "severity": "High",
            "title": "Public metadata endpoint is accessible",
            "detail": f"{meta_url} returned 200. This may reveal internal type names and API surface. If unintended, restrict access or review exposure."
        })
    if exposed_swagger:
        security_findings.append({
            "severity": "Medium",
            "title": "Swagger schema is publicly accessible",
            "detail": f"{swagger_url} returned 200 with {swagger_paths} paths / {swagger_methods} methods. Public API surface can enable automated abuse if endpoints are not protected."
        })
    if header_missing:
        security_findings.append({
            "severity": "Medium",
            "title": "Missing recommended security headers",
            "detail": "Missing: " + ", ".join(header_missing) + ". These headers reduce XSS/clickjacking/mixed-content risk."
        })
    for hit in admin_public_hits:
        security_findings.append({
            "severity": "High",
            "title": f"Admin-like route responds publicly: {hit['path']}",
            "detail": f"HEAD {hit['url']} returned {hit['status']}. Confirm this route is protected behind auth."
        })
    if not security_findings:
        security_findings.append({
            "severity": "Low",
            "title": "No major public red flags detected",
            "detail": "This scan checks only publicly visible signals. A deeper review requires editor-level access or explicit authorization."
        })

    perf_findings = []
    perf_findings.append({
        "severity": "Info",
        "title": "Homepage payload snapshot",
        "detail": f"HTML size ≈ {html_size_kb} KB, script tags ≈ {script_count}. Large payloads can slow first load on mobile."
    })
    # cache header hints
    cc = (headers or {}).get("Cache-Control") or (headers or {}).get("cache-control") or ""
    if not cc:
        perf_findings.append({
            "severity": "Low",
            "title": "Cache-Control not detected on homepage response",
            "detail": "If static assets are not cached aggressively, repeat visits may be slower."
        })

    maint_findings = []
    if data_types:
        maint_findings.append({
            "severity": "Info",
            "title": "Data types discovered via public metadata",
            "detail": "Detected " + str(len(data_types)) + " types. Sample: " + ", ".join(data_types[:8]) + ("..." if len(data_types) > 8 else "")
        })
    else:
        maint_findings.append({
            "severity": "Info",
            "title": "No data types discovered from public metadata",
            "detail": "Meta endpoint may be blocked or not exposing type listings publicly."
        })

    if exposed_swagger and swagger_samples:
        maint_findings.append({
            "severity": "Info",
            "title": "Public API surface snapshot (sample paths)",
            "detail": ", ".join(swagger_samples[:10]) + ("..." if len(swagger_samples) > 10 else "")
        })

    # Branding/logo best-effort
    logo_url = og_img if og_img else favicon

    return {
        "base": base,
        "home_url": home_url,
        "title": title,
        "logo_url": logo_url,
        "favicon": favicon,
        "og_image": og_img,
        "steps": steps,
        "headers": headers,
        "header_score": header_score,
        "header_missing": header_missing,
        "meta": {"status": m_code, "url": meta_url, "exposed": exposed_meta, "data_types": data_types},
        "swagger": {"status": s_code, "url": swagger_url, "exposed": exposed_swagger, "paths": swagger_paths, "methods": swagger_methods},
        "probe": probe,
        "signals": {"html_kb": html_size_kb, "script_count": script_count},
        "scores": {
            "security": security_score,
            "performance": performance_score,
            "maintainability": maintainability_score,
        },
        "findings": {
            "security": security_findings,
            "performance": perf_findings,
            "maintainability": maint_findings,
        }
    }


# ---------------------------
# UI STYLES
# ---------------------------
st.markdown(
    """
    <style>
      .badge {
        display:inline-block; padding:6px 10px; border-radius:999px;
        font-size:12px; font-weight:600; border:1px solid rgba(255,255,255,0.12);
      }
      .pill { padding:6px 12px; border-radius:999px; font-size:12px; font-weight:600; }
      .sev-High { background:#ff4d4f22; color:#ff7875; border:1px solid #ff4d4f55; }
      .sev-Medium { background:#faad1422; color:#ffd666; border:1px solid #faad1455; }
      .sev-Low { background:#52c41a22; color:#95de64; border:1px solid #52c41a55; }
      .sev-Info { background:#1677ff22; color:#69b1ff; border:1px solid #1677ff55; }

      .card {
        border:1px solid rgba(255,255,255,0.10);
        border-radius:16px;
        padding:16px;
        background: rgba(255,255,255,0.03);
      }
      .muted { color: rgba(255,255,255,0.72); }
      .small { font-size: 13px; }
      .title { font-size: 34px; font-weight: 800; margin-bottom: 4px; }
      .subtitle { font-size: 15px; color: rgba(255,255,255,0.72); margin-bottom: 14px; }
      hr { border-color: rgba(255,255,255,0.1); }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------------------
# PAGE HEADER
# ---------------------------
left, right = st.columns([1.2, 1])

with left:
    st.markdown('<div class="title">Bubble App Auditor</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">Public scan (Possibility 1): checks publicly available metadata, API surface and common security signals.</div>', unsafe_allow_html=True)

with right:
    st.markdown('<div class="card"><b>What this scan can do</b><br><span class="muted small">• Detect exposed meta/swagger<br>• Summarize API surface<br>• Check security headers<br>• Probe common admin routes<br>• Basic performance signals</span></div>', unsafe_allow_html=True)

st.write("")

# ---------------------------
# INPUTS
# ---------------------------
c1, c2 = st.columns([1, 1])

with c1:
    app_url = st.text_input("App URL (optional)", placeholder="your-app.com or https://yourapp.bubbleapps.io")
    app_id = st.text_input("Bubble App ID (recommended)", placeholder="yourapp-28503 (bubbleapps subdomain)")
with c2:
    env = st.selectbox("Environment", ["live", "version-test"], index=0)
    email = st.text_input("Where should we send the report? (optional)", placeholder="you@company.com")

run = st.button("Run scan", type="primary", use_container_width=True)

st.write("")

# ---------------------------
# RUN
# ---------------------------
if run:
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        st.error("Please enter at least App URL or Bubble App ID.")
        st.stop()

    scan_key = stable_key(base, app_id, env)

    prog = st.progress(0)
    status = st.empty()

    status.info("Starting scan…")
    prog.progress(10)
    time.sleep(0.1)

    status.info("Fetching and analyzing public endpoints…")
    prog.progress(35)
    scan = run_public_scan(app_url, app_id, env)

    if scan.get("error"):
        st.error(scan["error"])
        st.stop()

    prog.progress(70)
    status.info("Building report…")
    time.sleep(0.1)
    prog.progress(100)
    status.success("Audit complete ✅")

    st.write("")

    # ---------------------------
    # LAYOUT: LEFT SUMMARY + RIGHT DETAILS (NQU-like feel)
    # ---------------------------
    L, R = st.columns([0.38, 0.62], gap="large")

    with L:
        st.markdown('<div class="card">', unsafe_allow_html=True)

        # logo
        logo_url = scan.get("logo_url") or ""
        if logo_url:
            st.image(logo_url, width=88)

        app_title = scan.get("title") or (app_id.strip() if app_id else "Your Bubble App")
        st.markdown(f"### {app_title}")
        st.markdown(f'<div class="muted small">{scan["base"]}</div>', unsafe_allow_html=True)

        st.write("")
        st.markdown("**Audit Complete**")

        # steps / timing
        for (name, url, code, elapsed, err) in scan.get("steps", []):
            ok = (code == 200)
            icon = "✅" if ok else ("⚠️" if code else "❌")
            tail = f"{int(elapsed*1000)}ms"
            if code is None:
                st.write(f"{icon} {name} — {tail}")
            else:
                st.write(f"{icon} {name} — {code} — {tail}")

        st.write("")
        # scores
        s = scan["scores"]
        st.markdown("**Scores**")
        st.metric("Security", s["security"])
        st.metric("Performance", s["performance"])
        st.metric("Maintainability", s["maintainability"])

        st.write("")
        st.caption("Note: This is a public scan. It cannot directly read Bubble editor privacy rules or workflow logic unless they are publicly exposed.")
        st.markdown("</div>", unsafe_allow_html=True)

    with R:
        # Summary top box (like NQU)
        st.markdown('<div class="card">', unsafe_allow_html=True)
        bullets = []

        if scan["meta"]["exposed"]:
            bullets.append("Public metadata endpoint is accessible (type names and structure may be discoverable).")
        else:
            bullets.append("Metadata endpoint does not appear publicly accessible (good baseline).")

        if scan["swagger"]["exposed"]:
            bullets.append(f"Swagger schema is exposed with {scan['swagger']['paths']} paths (review endpoint protection).")
        else:
            bullets.append("Swagger schema not publicly accessible (good baseline).")

        if scan["header_missing"]:
            bullets.append("Some recommended security headers are missing (CSP/HSTS/XFO etc.).")
        else:
            bullets.append("Security headers look strong on the homepage response.")

        st.markdown("### Key risks and focus areas")
        for b in bullets:
            st.write("• " + b)
        st.markdown("</div>", unsafe_allow_html=True)
        st.write("")

        # Sections like NQU: Security / Performance / Maintainability
        def render_section(title, score, items):
            st.markdown('<div class="card">', unsafe_allow_html=True)
            top = st.columns([0.8, 0.2])
            with top[0]:
                st.markdown(f"### {title}")
            with top[1]:
                st.markdown(f'<div class="pill" style="text-align:right;border:1px solid rgba(255,255,255,0.12);">{score}</div>', unsafe_allow_html=True)

            st.write("")
            for it in items:
                sev = it.get("severity", "Info")
                sev_class = f"sev-{sev}"
                st.markdown(
                    f'<span class="badge {sev_class}">{sev}</span> <b>{it.get("title","")}</b>',
                    unsafe_allow_html=True
                )
                st.markdown(f'<div class="muted small">{it.get("detail","")}</div>', unsafe_allow_html=True)
                st.write("")
            st.markdown("</div>", unsafe_allow_html=True)

        render_section("Security", scan["scores"]["security"], scan["findings"]["security"])
        st.write("")
        render_section("Performance", scan["scores"]["performance"], scan["findings"]["performance"])
        st.write("")
        render_section("Maintainability", scan["scores"]["maintainability"], scan["findings"]["maintainability"])

        # Extra: show discovered types/paths (developer detail)
        with st.expander("Developer details (what we actually detected)"):
            st.markdown("**Discovered data types (from /api/1.1/meta):**")
            st.write(scan["meta"]["data_types"][:50])
            st.markdown("**Swagger stats:**")
            st.write(scan["swagger"])
            st.markdown("**Admin route probes (HEAD):**")
            st.write(scan["probe"])
            st.markdown("**Homepage headers snapshot:**")
            st.write({k: scan["headers"].get(k) for k in list(scan["headers"].keys())[:30]})
