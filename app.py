import re
import time
import hashlib
from urllib.parse import urljoin

import requests
import streamlit as st


st.set_page_config(page_title="Bubble App Auditor", page_icon="🫧", layout="wide")

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "BubbleAppAuditor/1.1 (+public-scan)"})
REQUEST_TIMEOUT = 12


def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u.rstrip("/")


def safe_get(url: str):
    t0 = time.time()
    try:
        r = SESSION.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        elapsed = time.time() - t0
        js = None
        ct = (r.headers.get("content-type") or "").lower()
        if "json" in ct:
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


def find_title(html: str):
    m = re.search(r"<title>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    t = re.sub(r"\s+", " ", m.group(1)).strip()
    return t[:120]


def find_favicon(html: str, base_url: str):
    m = re.search(r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]*>', html, re.I)
    if m:
        tag = m.group(0)
        href = re.search(r'href=["\']([^"\']+)["\']', tag, re.I)
        if href:
            return urljoin(base_url + "/", href.group(1))
    return urljoin(base_url + "/", "favicon.ico")


def find_og_image(html: str, base_url: str):
    m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    if m:
        return urljoin(base_url + "/", m.group(1))
    return ""


def score_headers(h: dict):
    checks = {
        "Content-Security-Policy": False,
        "Strict-Transport-Security": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "Permissions-Policy": False,
    }
    for k in list(checks.keys()):
        for hk in h.keys():
            if hk.lower() == k.lower():
                checks[k] = True
                break
    missing = [k for k, ok in checks.items() if not ok]
    present = [k for k, ok in checks.items() if ok]
    score = int((len(present) / len(checks)) * 100)
    return score, present, missing


def env_base_from_inputs(app_url: str, app_id: str, env: str) -> str:
    """
    - If App URL provided, use it.
    - Else use https://{app_id}.bubbleapps.io
    - Apply env:
        live -> base
        version-test -> base/version-test
    - IMPORTANT: don't double-add version-test if user already included it in URL.
    """
    app_url = normalize_url(app_url)
    app_id = (app_id or "").strip()

    if app_url:
        base = app_url
    else:
        if not app_id:
            return ""
        base = f"https://{app_id}.bubbleapps.io"

    # If user already pasted /version-test in the URL, don't add again.
    if env == "version-test":
        if not base.endswith("/version-test"):
            base = base + "/version-test"

    # If env is live but user pasted /version-test, strip it.
    if env == "live":
        if base.endswith("/version-test"):
            base = base[: -len("/version-test")]

    return base.rstrip("/")


def extract_swagger_stats(swagger_json):
    paths = {}
    if isinstance(swagger_json, dict) and isinstance(swagger_json.get("paths"), dict):
        paths = swagger_json["paths"]
    total_paths = len(paths)
    methods = 0
    for _, obj in paths.items():
        if isinstance(obj, dict):
            methods += len([k for k in obj.keys() if k.lower() in ("get", "post", "put", "patch", "delete")])
    return total_paths, methods, list(paths.keys())[:25]


def probe_paths(base: str, paths):
    out = []
    for p in paths:
        url = urljoin(base + "/", p.lstrip("/"))
        code, headers, elapsed, err = safe_head(url)
        out.append({"path": p, "url": url, "status": code, "elapsed": elapsed, "error": err})
    return out


def stable_key(*parts) -> str:
    s = "|".join([str(p) for p in parts])
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


@st.cache_data(show_spinner=False)
def run_public_scan(app_url: str, app_id: str, env: str):
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        return {"error": "Missing App URL or Bubble App ID."}

    steps = []

    # 1) Homepage
    home_url = base + "/"
    code, headers, html, _, elapsed, err = safe_get(home_url)
    steps.append(("Fetch homepage", home_url, code, elapsed, err))

    # If homepage is blocked (401/403), do NOT pretend we analyzed HTML.
    home_blocked = code in (401, 403)

    title = find_title(html) if (html and not home_blocked) else (app_id.strip() if app_id else "Bubble App")
    og_img = find_og_image(html, base) if (html and not home_blocked) else ""
    favicon = find_favicon(html, base) if (html and not home_blocked) else urljoin(base + "/", "favicon.ico")

    header_score, header_present, header_missing = score_headers(headers or {})

    # 2) Meta
    meta_url = base + "/api/1.1/meta"
    m_code, _, _, m_json, m_elapsed, m_err = safe_get(meta_url)
    steps.append(("Fetch /api/1.1/meta", meta_url, m_code, m_elapsed, m_err))
    exposed_meta = (m_code == 200 and isinstance(m_json, dict))

    # 3) Swagger
    swagger_url = base + "/api/1.1/meta/swagger.json"
    s_code, _, _, s_json, s_elapsed, s_err = safe_get(swagger_url)
    steps.append(("Fetch swagger.json", swagger_url, s_code, s_elapsed, s_err))
    exposed_swagger = (s_code == 200 and isinstance(s_json, dict))

    swagger_paths = swagger_methods = 0
    swagger_samples = []
    if exposed_swagger:
        swagger_paths, swagger_methods, swagger_samples = extract_swagger_stats(s_json)

    # 4) Admin probes
    admin_candidates = ["/admin", "/dashboard", "/settings", "/super_admin", "/superadmin", "/backend"]
    probe = probe_paths(base, admin_candidates)

    # 5) Performance signals only if homepage wasn't blocked
    html_size_kb = int(len(html.encode("utf-8")) / 1024) if (html and not home_blocked) else None
    script_count = len(re.findall(r"<script\b", html or "", re.I)) if (html and not home_blocked) else None

    # Scores
    security_score = 100
    if header_score < 100:
        security_score -= int((100 - header_score) * 0.4)
    if exposed_meta:
        security_score -= 18
    if exposed_swagger:
        security_score -= 12
    security_score = max(5, min(100, security_score))

    performance_score = 100
    if html_size_kb is None:
        performance_score = 0  # unknown
    else:
        if html_size_kb > 900:
            performance_score -= 18
        elif html_size_kb > 500:
            performance_score -= 10
        if script_count and script_count > 40:
            performance_score -= 12
        elif script_count and script_count > 25:
            performance_score -= 7
        performance_score = max(10, min(100, performance_score))

    maintainability_score = 100
    if exposed_swagger and swagger_paths > 40:
        maintainability_score -= 18
    elif exposed_swagger and swagger_paths > 20:
        maintainability_score -= 10
    maintainability_score = max(10, min(100, maintainability_score))

    # Findings
    security_findings = []
    if home_blocked:
        security_findings.append({
            "severity": "Info",
            "title": "App is protected (homepage requires authorization)",
            "detail": f"Homepage returned {code}. Public scan cannot read page HTML or branding when access is restricted."
        })
    if exposed_meta:
        security_findings.append({
            "severity": "High",
            "title": "Public metadata endpoint is accessible",
            "detail": f"{meta_url} returned 200. This may reveal internal type names and API surface."
        })
    if exposed_swagger:
        security_findings.append({
            "severity": "Medium",
            "title": "Swagger schema is publicly accessible",
            "detail": f"{swagger_url} returned 200 with {swagger_paths} paths / {swagger_methods} methods."
        })
    if header_missing:
        security_findings.append({
            "severity": "Medium",
            "title": "Missing recommended security headers",
            "detail": "Missing: " + ", ".join(header_missing)
        })
    if not security_findings:
        security_findings.append({
            "severity": "Low",
            "title": "No major public red flags detected",
            "detail": "This scan checks only public signals. Deeper audit needs explicit access."
        })

    perf_findings = []
    if html_size_kb is None:
        perf_findings.append({
            "severity": "Info",
            "title": "Performance details unavailable",
            "detail": f"Homepage returned {code}. Because HTML is not accessible, payload size and script counts cannot be measured."
        })
    else:
        perf_findings.append({
            "severity": "Info",
            "title": "Homepage payload snapshot",
            "detail": f"HTML size ≈ {html_size_kb} KB, script tags ≈ {script_count}."
        })

    maint_findings = []
    if exposed_swagger and swagger_samples:
        maint_findings.append({
            "severity": "Info",
            "title": "Public API surface snapshot (sample paths)",
            "detail": ", ".join(swagger_samples[:10]) + ("..." if len(swagger_samples) > 10 else "")
        })
    else:
        maint_findings.append({
            "severity": "Info",
            "title": "Maintainability details limited (public scan)",
            "detail": "Without public swagger/meta exposure, internal structure cannot be inferred reliably."
        })

    logo_url = og_img if og_img else favicon

    return {
        "base": base,
        "home_url": home_url,
        "title": title,
        "logo_url": logo_url,
        "steps": steps,
        "headers": headers,
        "header_score": header_score,
        "header_missing": header_missing,
        "meta": {"status": m_code, "url": meta_url, "exposed": exposed_meta},
        "swagger": {"status": s_code, "url": swagger_url, "exposed": exposed_swagger, "paths": swagger_paths, "methods": swagger_methods},
        "probe": probe,
        "signals": {"html_kb": html_size_kb, "script_count": script_count},
        "scores": {"security": security_score, "performance": performance_score, "maintainability": maintainability_score},
        "findings": {"security": security_findings, "performance": perf_findings, "maintainability": maint_findings},
    }


st.markdown(
    """
    <style>
      .card{border:1px solid rgba(255,255,255,0.10); border-radius:16px; padding:16px; background: rgba(255,255,255,0.03);}
      .muted{color: rgba(255,255,255,0.72);}
      .small{font-size:13px;}
      .pill{padding:6px 12px; border-radius:999px; font-size:12px; font-weight:600; border:1px solid rgba(255,255,255,0.12);}
      .badge{display:inline-block; padding:6px 10px; border-radius:999px; font-size:12px; font-weight:600; border:1px solid rgba(255,255,255,0.12);}
      .sev-High{background:#ff4d4f22; color:#ff7875; border:1px solid #ff4d4f55;}
      .sev-Medium{background:#faad1422; color:#ffd666; border:1px solid #faad1455;}
      .sev-Low{background:#52c41a22; color:#95de64; border:1px solid #52c41a55;}
      .sev-Info{background:#1677ff22; color:#69b1ff; border:1px solid #1677ff55;}
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown("## Bubble App Auditor")
st.markdown('<div class="muted">Public scan only (no Bubble API key required).</div>', unsafe_allow_html=True)
st.write("")

c1, c2 = st.columns(2)
with c1:
    app_url = st.text_input("App URL (optional)", placeholder="steyel.com or https://yourapp.bubbleapps.io")
    app_id = st.text_input("Bubble App ID (recommended)", placeholder="yourapp-28503")
with c2:
    env = st.selectbox("Environment", ["live", "version-test"], index=0)
    email = st.text_input("Where should we send the report? (optional)", placeholder="you@company.com")

run = st.button("Run scan", type="primary", use_container_width=True)

if run:
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        st.error("Please enter at least App URL or Bubble App ID.")
        st.stop()

    prog = st.progress(0)
    status = st.empty()
    status.info("Starting scan…")
    prog.progress(25)

    status.info("Fetching and analyzing public endpoints…")
    scan = run_public_scan(app_url, app_id, env)
    if scan.get("error"):
        st.error(scan["error"])
        st.stop()

    prog.progress(100)
    status.success("Audit complete ✅")
    st.write("")

    L, R = st.columns([0.38, 0.62], gap="large")

    with L:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        if scan.get("logo_url"):
            st.image(scan["logo_url"], width=80)

        st.markdown(f"### {scan['title']}")
        st.markdown(f'<div class="muted small">{scan["base"]}</div>', unsafe_allow_html=True)

        st.write("")
        st.markdown("**Audit Complete**")
        for (name, url, code, elapsed, err) in scan.get("steps", []):
            ok = (code == 200)
            icon = "✅" if ok else ("⚠️" if code else "❌")
            ms = f"{int(elapsed*1000)}ms"
            if code is None:
                st.write(f"{icon} {name} — {ms}")
            else:
                st.write(f"{icon} {name} — {code} — {ms}")

        st.write("")
        st.markdown("**Scores**")
        st.metric("Security", scan["scores"]["security"])
        if scan["scores"]["performance"] == 0:
            st.metric("Performance", "N/A")
        else:
            st.metric("Performance", scan["scores"]["performance"])
        st.metric("Maintainability", scan["scores"]["maintainability"])

        st.write("")
        st.caption("If an app returns 401/403, public scan cannot read HTML/meta/swagger. That is normal for protected apps.")
        st.markdown("</div>", unsafe_allow_html=True)

    with R:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("### Key risks and focus areas")

        if scan["meta"]["status"] in (401, 403) and scan["swagger"]["status"] in (401, 403):
            st.write("• App appears protected (401/403). Public scan cannot extract deep details.")
        else:
            if scan["meta"]["exposed"]:
                st.write("• Public metadata endpoint is accessible (may expose internal structure).")
            else:
                st.write("• Metadata endpoint does not appear publicly accessible (good baseline).")

            if scan["swagger"]["exposed"]:
                st.write(f"• Swagger schema is exposed with {scan['swagger']['paths']} paths (review protection).")
            else:
                st.write("• Swagger schema not publicly accessible (good baseline).")

        if scan["header_missing"]:
            st.write("• Some recommended security headers are missing (CSP/HSTS/XFO etc.).")
        else:
            st.write("• Security headers look strong on homepage response.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.write("")

        def render_section(title, score, items):
            st.markdown('<div class="card">', unsafe_allow_html=True)
            top = st.columns([0.8, 0.2])
            with top[0]:
                st.markdown(f"### {title}")
            with top[1]:
                st.markdown(f'<div class="pill" style="text-align:right;">{score if score else "N/A"}</div>', unsafe_allow_html=True)

            st.write("")
            for it in items:
                sev = it.get("severity", "Info")
                st.markdown(f'<span class="badge sev-{sev}">{sev}</span> <b>{it.get("title","")}</b>', unsafe_allow_html=True)
                st.markdown(f'<div class="muted small">{it.get("detail","")}</div>', unsafe_allow_html=True)
                st.write("")
            st.markdown("</div>", unsafe_allow_html=True)

        render_section("Security", scan["scores"]["security"], scan["findings"]["security"])
        st.write("")
        render_section("Performance", (scan["scores"]["performance"] if scan["scores"]["performance"] else "N/A"), scan["findings"]["performance"])
        st.write("")
        render_section("Maintainability", scan["scores"]["maintainability"], scan["findings"]["maintainability"])
