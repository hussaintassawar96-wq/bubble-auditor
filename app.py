import re
import time
import hashlib
from urllib.parse import urljoin

import requests
import streamlit as st


# ---------------------------
# CONFIG
# ---------------------------
CALENDLY_URL = "https://calendly.com/tassawarhussain/30min"
REQUEST_TIMEOUT = 12

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "BubbleAppAuditor/2.0 (+public-scan)"})


# ---------------------------
# PAGE SETUP + STYLES
# ---------------------------
st.set_page_config(page_title="Bubble App Auditor", page_icon="🫧", layout="wide")

st.markdown(
    """
<style>
:root{
  --card: rgba(255,255,255,0.06);
  --card2: rgba(255,255,255,0.04);
  --stroke: rgba(255,255,255,0.10);
  --muted: rgba(255,255,255,0.72);
  --muted2: rgba(255,255,255,0.60);
  --accent: #b36bff;
  --accent2: #7c5cff;
  --good: #32d583;
  --warn: #fdb022;
  --bad: #ff4d4f;
  --info: #69b1ff;
}
.block-container {padding-top: 1.2rem;}
h1, h2, h3 {letter-spacing: -0.02em;}
.small {font-size: 13px; color: var(--muted);}
.muted {color: var(--muted);}
.card{
  border: 1px solid var(--stroke);
  border-radius: 18px;
  padding: 16px;
  background: var(--card);
}
.card2{
  border: 1px solid var(--stroke);
  border-radius: 18px;
  padding: 16px;
  background: var(--card2);
}
.pill{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding: 7px 12px;
  border-radius: 999px;
  border: 1px solid var(--stroke);
  background: rgba(0,0,0,0.20);
  font-size: 12px;
  font-weight: 700;
}
.kpi{
  border: 1px solid var(--stroke);
  border-radius: 16px;
  padding: 12px;
  background: rgba(0,0,0,0.18);
}
.hr{height:1px; background: var(--stroke); margin: 14px 0;}
.badge{
  display:inline-block;
  padding:6px 10px;
  border-radius:999px;
  font-size:12px;
  font-weight:700;
  border:1px solid var(--stroke);
}
.sev-High{background:#ff4d4f22;color:#ff7875;border:1px solid #ff4d4f55;}
.sev-Medium{background:#fdb02222;color:#ffd666;border:1px solid #fdb02255;}
.sev-Low{background:#32d58322;color:#95de64;border:1px solid #32d58355;}
.sev-Info{background:#69b1ff22;color:#91caff;border:1px solid #69b1ff55;}
.evidence{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  color: rgba(255,255,255,0.80);
  background: rgba(0,0,0,0.22);
  border: 1px solid var(--stroke);
  border-radius: 12px;
  padding: 10px;
  overflow-x:auto;
}
.cta{
  border: 1px solid rgba(179,107,255,0.45);
  background: radial-gradient(1200px 400px at 10% 0%, rgba(179,107,255,0.35), transparent),
              radial-gradient(900px 300px at 70% 10%, rgba(124,92,255,0.25), transparent),
              rgba(255,255,255,0.04);
  border-radius: 20px;
  padding: 18px;
}
</style>
""",
    unsafe_allow_html=True
)


# ---------------------------
# HELPERS
# ---------------------------
def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u.rstrip("/")


def env_base_from_inputs(app_url: str, app_id: str, env: str) -> str:
    """
    Builds base URL:
      - If App URL provided, use it
      - Else use https://{app_id}.bubbleapps.io
      - Apply env:
          live -> base
          version-test -> base/version-test
      - Avoid double version-test if user already included it
      - If env=live and user pasted /version-test, strip it
    """
    app_url = normalize_url(app_url)
    app_id = (app_id or "").strip()

    if app_url:
        base = app_url
    else:
        if not app_id:
            return ""
        base = f"https://{app_id}.bubbleapps.io"

    if env == "version-test":
        if not base.endswith("/version-test"):
            base = base + "/version-test"

    if env == "live":
        if base.endswith("/version-test"):
            base = base[: -len("/version-test")]

    return base.rstrip("/")


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


def extract_swagger_stats(swagger_json):
    paths = {}
    if isinstance(swagger_json, dict) and isinstance(swagger_json.get("paths"), dict):
        paths = swagger_json["paths"]
    total_paths = len(paths)
    methods = 0
    for _, obj in paths.items():
        if isinstance(obj, dict):
            methods += len([k for k in obj.keys() if k.lower() in ("get", "post", "put", "patch", "delete")])
    return total_paths, methods, list(paths.keys())[:30]


def probe_paths(base: str, paths):
    out = []
    for p in paths:
        url = urljoin(base + "/", p.lstrip("/"))
        code, headers, elapsed, err = safe_head(url)
        out.append({"path": p, "url": url, "status": code, "elapsed": elapsed, "error": err})
    return out


def build_evidence_lines(scan):
    lines = []
    for (name, url, code, elapsed, err) in scan.get("steps", []):
        ms = f"{int(elapsed*1000)}ms"
        if code is None:
            lines.append(f"{name}: ERROR ({err}) — {ms}")
        else:
            lines.append(f"{name}: {code} — {ms} — {url}")

    # probe results summary
    for pr in scan.get("probe", [])[:8]:
        s = pr.get("status")
        ms = f"{int(pr.get('elapsed',0)*1000)}ms"
        lines.append(f"Probe {pr['path']}: {s} — {ms}")

    return "\n".join(lines)[:4000]


def calc_scores(home_blocked, header_score, meta_exposed, swagger_exposed, html_kb, script_count):
    # Security
    sec = 100
    sec -= int((100 - header_score) * 0.45)
    if meta_exposed:
        sec -= 18
    if swagger_exposed:
        sec -= 12
    if home_blocked:
        sec += 6  # protected homepage is often a positive baseline
    sec = max(5, min(100, sec))

    # Performance (unknown if blocked)
    if home_blocked or html_kb is None:
        perf = 0
    else:
        perf = 100
        if html_kb > 900:
            perf -= 18
        elif html_kb > 500:
            perf -= 10
        if script_count and script_count > 40:
            perf -= 12
        elif script_count and script_count > 25:
            perf -= 7
        perf = max(10, min(100, perf))

    # Maintainability
    maint = 100
    if swagger_exposed:
        # big exposed surface often means more endpoints to manage
        maint -= 10
    maint = max(10, min(100, maint))

    return sec, perf, maint


def severity_for_issue(kind: str):
    return {
        "meta_exposed": "High",
        "swagger_exposed": "Medium",
        "missing_headers": "Medium",
        "cache_missing": "Low",
        "home_blocked": "Info",
        "unknown_perf": "Info",
    }.get(kind, "Info")


def stable_cache_key(app_url: str, app_id: str, env: str):
    s = f"{normalize_url(app_url)}|{(app_id or '').strip()}|{env}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:18]


@st.cache_data(show_spinner=False)
def run_public_scan_cached(app_url: str, app_id: str, env: str, cache_key: str):
    # cache_key is included so two different apps never collide in cache
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        return {"error": "Missing App URL or Bubble App ID."}

    steps = []

    # Homepage
    home_url = base + "/"
    code, headers, html, _, elapsed, err = safe_get(home_url)
    steps.append(("Fetch homepage", home_url, code, elapsed, err))
    home_blocked = code in (401, 403)

    title = find_title(html) if (html and not home_blocked) else ((app_id.strip() if app_id else "Bubble App").lower())
    og_img = find_og_image(html, base) if (html and not home_blocked) else ""
    favicon = find_favicon(html, base) if (html and not home_blocked) else urljoin(base + "/", "favicon.ico")
    logo_url = og_img if og_img else favicon

    header_score, header_present, header_missing = score_headers(headers or {})

    # Meta
    meta_url = base + "/api/1.1/meta"
    m_code, _, _, m_json, m_elapsed, m_err = safe_get(meta_url)
    steps.append(("Fetch /api/1.1/meta", meta_url, m_code, m_elapsed, m_err))
    meta_exposed = (m_code == 200 and isinstance(m_json, dict))

    # Swagger
    swagger_url = base + "/api/1.1/meta/swagger.json"
    s_code, _, _, s_json, s_elapsed, s_err = safe_get(swagger_url)
    steps.append(("Fetch swagger.json", swagger_url, s_code, s_elapsed, s_err))
    swagger_exposed = (s_code == 200 and isinstance(s_json, dict))

    swagger_paths = swagger_methods = 0
    swagger_samples = []
    if swagger_exposed:
        swagger_paths, swagger_methods, swagger_samples = extract_swagger_stats(s_json)

    # Probes
    admin_candidates = ["/admin", "/dashboard", "/settings", "/super_admin", "/superadmin", "/backend", "/login"]
    probe = probe_paths(base, admin_candidates)

    # Perf signals only if readable
    html_kb = int(len(html.encode("utf-8")) / 1024) if (html and not home_blocked) else None
    script_count = len(re.findall(r"<script\b", html or "", re.I)) if (html and not home_blocked) else None

    cache_control = ""
    for hk, hv in (headers or {}).items():
        if hk.lower() == "cache-control":
            cache_control = hv
            break
    cache_missing = (not cache_control) and (not home_blocked)

    sec, perf, maint = calc_scores(home_blocked, header_score, meta_exposed, swagger_exposed, html_kb, script_count)

    # Build crisp “Key risks and focus areas”
    key_bullets = []

    if home_blocked:
        key_bullets.append(("home_blocked", "Homepage is protected (401/403), limiting public exposure (good baseline)."))
    else:
        key_bullets.append(("home_blocked", "Homepage is publicly accessible (normal), so public misconfigurations matter more."))

    if meta_exposed:
        key_bullets.append(("meta_exposed", "Public metadata endpoint is accessible: internal surface may be discoverable."))
    else:
        key_bullets.append(("meta_exposed", "Metadata endpoint does not appear publicly accessible (good baseline)."))

    if swagger_exposed:
        key_bullets.append(("swagger_exposed", f"Swagger schema is exposed with {swagger_paths} paths: review access control."))
    else:
        key_bullets.append(("swagger_exposed", "Swagger schema not publicly accessible (good baseline)."))

    if header_missing:
        key_bullets.append(("missing_headers", "Some recommended security headers are missing (CSP/HSTS/XFO etc.)."))
    else:
        key_bullets.append(("missing_headers", "Security headers look strong on homepage response."))

    if perf == 0:
        key_bullets.append(("unknown_perf", "Performance measurements are limited because HTML isn't accessible to this scan."))
    else:
        key_bullets.append(("unknown_perf", f"Homepage snapshot: ~{html_kb} KB HTML and ~{script_count} script tags."))

    if cache_missing:
        key_bullets.append(("cache_missing", "Cache-Control header not detected; repeat visits may be slower."))

    # Findings (detail)
    security_findings = []
    if meta_exposed:
        security_findings.append({
            "severity": "High",
            "title": "Public /api/1.1/meta is accessible",
            "why": "This can reveal details that make an app easier to map or misuse.",
            "evidence": f"GET {meta_url} → 200",
            "fix": "Restrict access to public metadata if possible. If not, ensure no sensitive data is exposed via public endpoints."
        })
    if swagger_exposed:
        security_findings.append({
            "severity": "Medium",
            "title": "Public swagger schema is accessible",
            "why": "Swagger exposes the shape of endpoints and can accelerate abuse if endpoints are misconfigured.",
            "evidence": f"GET {swagger_url} → 200 ({swagger_paths} paths)",
            "fix": "Ensure endpoint authorization and consider restricting swagger exposure if it isn’t meant to be public."
        })
    if header_missing:
        security_findings.append({
            "severity": "Medium",
            "title": "Missing recommended security headers",
            "why": "Headers reduce XSS, clickjacking, and mixed-content risk.",
            "evidence": "Missing: " + ", ".join(header_missing),
            "fix": "Add CSP/HSTS/XFO/Referrer-Policy/Permissions-Policy via CDN/reverse proxy (Cloudflare, Nginx, etc.)."
        })
    if home_blocked:
        security_findings.append({
            "severity": "Info",
            "title": "App is protected (401/403)",
            "why": "Protected apps reduce public info leakage and make scanning harder.",
            "evidence": f"GET {home_url} → {code}",
            "fix": "If this is intended, great. If not, review your access settings and public pages."
        })
    if not security_findings:
        security_findings.append({
            "severity": "Low",
            "title": "No major public red flags detected",
            "why": "This scan checks only public signals. A deeper audit needs explicit access.",
            "evidence": "Public endpoints did not expose meta/swagger and headers look reasonable.",
            "fix": "Consider a deeper audit if you handle sensitive user data or payments."
        })

    perf_findings = []
    if perf == 0:
        perf_findings.append({
            "severity": "Info",
            "title": "Performance details limited",
            "why": "When a homepage is protected, payload size and script complexity cannot be measured by a public scan.",
            "evidence": f"GET {home_url} → {code}",
            "fix": "If you'd like, share a public test page or collaborator access for deeper performance profiling."
        })
    else:
        perf_findings.append({
            "severity": "Info",
            "title": "Homepage payload snapshot",
            "why": "Large HTML and too many scripts can slow first load on mobile.",
            "evidence": f"HTML ≈ {html_kb} KB, scripts ≈ {script_count}",
            "fix": "Reduce plugin bloat, defer heavy scripts, and avoid running workflows on page load."
        })
        if cache_missing:
            perf_findings.append({
                "severity": "Low",
                "title": "Cache-Control not detected on homepage",
                "why": "Caching static assets improves repeat visit speed.",
                "evidence": "Cache-Control header missing",
                "fix": "Configure caching for static assets at CDN/proxy level."
            })

    maint_findings = []
    if swagger_exposed and swagger_samples:
        maint_findings.append({
            "severity": "Info",
            "title": "Public API surface snapshot (sample paths)",
            "why": "A wide API surface increases maintenance overhead if not documented and standardized.",
            "evidence": "Sample: " + ", ".join(swagger_samples[:10]) + ("..." if len(swagger_samples) > 10 else ""),
            "fix": "Document endpoints, standardize naming, and ensure consistent authorization patterns."
        })
    else:
        maint_findings.append({
            "severity": "Info",
            "title": "Maintainability detail limited (public scan)",
            "why": "Without meta/swagger exposure, internal structure cannot be inferred reliably.",
            "evidence": "No public swagger/meta available, or access restricted.",
            "fix": "For a real maintainability audit, we review workflows, data types, privacy rules, and plugin usage with access."
        })

    return {
        "base": base,
        "title": title,
        "logo_url": logo_url,
        "home_url": home_url,
        "steps": steps,
        "scores": {"security": sec, "performance": perf, "maintainability": maint},
        "headers": headers,
        "header_score": header_score,
        "header_missing": header_missing,
        "meta": {"url": meta_url, "status": m_code, "exposed": meta_exposed},
        "swagger": {"url": swagger_url, "status": s_code, "exposed": swagger_exposed, "paths": swagger_paths, "methods": swagger_methods},
        "probe": probe,
        "signals": {"html_kb": html_kb, "script_count": script_count, "cache_control": cache_control},
        "key_bullets": key_bullets,
        "findings": {"security": security_findings, "performance": perf_findings, "maintainability": maint_findings},
        "evidence": build_evidence_lines({
            "steps": steps,
            "probe": probe
        })
    }


def run_scan(app_url: str, app_id: str, env: str):
    ck = stable_cache_key(app_url, app_id, env)
    return run_public_scan_cached(app_url, app_id, env, ck)


def sev_badge(sev: str):
    return f'<span class="badge sev-{sev}">{sev}</span>'


def section_card(title: str, score_value):
    score_label = "N/A" if score_value == 0 else str(score_value)
    st.markdown(
        f"""
<div class="card">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
    <h2 style="margin:0;">{title}</h2>
    <span class="pill">{score_label}</span>
  </div>
</div>
""",
        unsafe_allow_html=True
    )


def render_findings(findings, gated: bool):
    for it in findings:
        sev = it.get("severity", "Info")
        title = it.get("title", "")
        why = it.get("why", "")
        evidence = it.get("evidence", "")
        fix = it.get("fix", "")

        st.markdown(
            f"""
<div class="card2">
  <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
    {sev_badge(sev)}
    <div style="font-weight:800;">{title}</div>
  </div>
  <div class="hr"></div>
  <div class="small"><b>Why flagged:</b> {why}</div>
  <div style="height:10px;"></div>
  <div class="small"><b>Evidence:</b></div>
  <div class="evidence">{evidence}</div>
  <div style="height:10px;"></div>
  <div class="small"><b>Suggested fix:</b> {"(Unlock full fix plan below)" if gated else fix}</div>
</div>
""",
            unsafe_allow_html=True
        )
        st.write("")


def render_key_bullets(key_bullets):
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### Key risks and focus areas")
    st.write("")
    for kind, text in key_bullets[:6]:
        st.write(f"• {text}")
    st.markdown("</div>", unsafe_allow_html=True)


def lead_gate_ui(scan):
    st.markdown(
        """
<div class="cta">
  <h2 style="margin:0;">Unlock the full Fix Plan + Book a 30-min call</h2>
  <div class="small" style="margin-top:8px;">
    If you want, I’ll turn this scan into a clear action plan: what to fix first, how to fix it, and what to ignore.
    Ideal if you’re scaling, handling user data, payments, or dealing with weird Bubble bugs.
  </div>
  <div class="hr"></div>
  <div style="display:flex; gap:10px; flex-wrap:wrap;">
    <span class="pill">✅ Prioritized fix list (fast wins first)</span>
    <span class="pill">✅ Security hardening checklist</span>
    <span class="pill">✅ Performance cleanup plan</span>
    <span class="pill">✅ Maintainability + tech debt cleanup</span>
  </div>
</div>
""",
        unsafe_allow_html=True
    )

    st.write("")
    st.markdown("### Get the full report")
    st.markdown('<div class="small">Enter details and you’ll instantly unlock the full fixes + meeting scheduler.</div>', unsafe_allow_html=True)

    with st.form("lead_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            name = st.text_input("Your name")
            email = st.text_input("Email")
            role = st.selectbox("Your role", ["Founder", "Bubble Developer", "Product", "Agency", "Other"])
        with c2:
            company = st.text_input("Company (optional)")
            budget = st.selectbox("Timeline", ["ASAP (this week)", "This month", "Next 1–3 months", "Just exploring"])
            notes = st.text_area("What should I know? (optional)", placeholder="e.g. app has payments, marketplace, multi-tenant, user files, etc.")

        submitted = st.form_submit_button("Unlock full fix plan + book call", type="primary", use_container_width=True)

    if submitted:
        st.session_state["lead_unlocked"] = True
        st.session_state["lead_data"] = {
            "name": name,
            "email": email,
            "role": role,
            "company": company,
            "timeline": budget,
            "notes": notes,
            "scanned_base": scan.get("base", ""),
            "scores": scan.get("scores", {}),
            "timestamp": int(time.time())
        }
        st.success("Unlocked ✅ Scroll down to book your call.")

    return bool(st.session_state.get("lead_unlocked", False))


def calendly_embed():
    st.markdown("### Book a 30-minute meeting")
    st.markdown('<div class="small">Pick a time that works for you. I’ll review your scan and share the fastest wins first.</div>', unsafe_allow_html=True)

    st.components.v1.html(
        f"""
<div style="border:1px solid rgba(255,255,255,0.10); border-radius:18px; overflow:hidden; background: rgba(255,255,255,0.04);">
  <iframe src="{CALENDLY_URL}" width="100%" height="780" frameborder="0"></iframe>
</div>
""",
        height=820
    )


# ---------------------------
# HEADER
# ---------------------------
st.markdown("## Bubble App Auditor")
st.markdown(
    '<div class="muted">Public scan only (no Bubble API key required). Shows evidence-based signals from public endpoints.</div>',
    unsafe_allow_html=True
)
st.write("")


# ---------------------------
# INPUTS
# ---------------------------
c1, c2, c3 = st.columns([0.44, 0.28, 0.28])
with c1:
    app_url = st.text_input("App URL (optional)", placeholder="yourapp.com or https://yourapp.bubbleapps.io")
with c2:
    app_id = st.text_input("Bubble App ID (recommended)", placeholder="yourapp-28503")
with c3:
    env = st.selectbox("Environment", ["live", "version-test"], index=0)

run_btn = st.button("Run scan", type="primary", use_container_width=True)

# Reset unlock when inputs change (so one lead unlock doesn't apply to another app)
fingerprint = stable_cache_key(app_url, app_id, env)
if st.session_state.get("last_fingerprint") != fingerprint:
    st.session_state["lead_unlocked"] = False
    st.session_state["last_fingerprint"] = fingerprint

if not run_btn and "last_scan" not in st.session_state:
    st.info("Enter App URL or Bubble App ID, choose environment, then click **Run scan**.")
    st.stop()


# ---------------------------
# RUN SCAN
# ---------------------------
if run_btn or "last_scan" in st.session_state:
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        st.error("Please enter at least App URL or Bubble App ID.")
        st.stop()

    prog = st.progress(0)
    status = st.empty()
    status.info("Starting scan…")
    prog.progress(18)

    time.sleep(0.1)
    status.info("Fetching and analyzing public endpoints…")
    prog.progress(45)

    scan = run_scan(app_url, app_id, env)
    if scan.get("error"):
        st.error(scan["error"])
        st.stop()

    prog.progress(100)
    status.success("Audit complete ✅")
    st.session_state["last_scan"] = scan

else:
    scan = st.session_state.get("last_scan")


# ---------------------------
# LAYOUT: LEFT SUMMARY + RIGHT DETAILS
# ---------------------------
L, R = st.columns([0.36, 0.64], gap="large")

with L:
    st.markdown('<div class="card">', unsafe_allow_html=True)

    if scan.get("logo_url"):
        st.image(scan["logo_url"], width=72)

    st.markdown(f"### {scan.get('title','Bubble App')}")
    st.markdown(f'<div class="small">{scan.get("base","")}</div>', unsafe_allow_html=True)

    st.markdown('<div class="hr"></div>', unsafe_allow_html=True)

    st.markdown("**Audit status**")
    for (name, url, code, elapsed, err) in scan.get("steps", []):
        ok = (code == 200)
        icon = "✅" if ok else ("⚠️" if code else "❌")
        ms = f"{int(elapsed*1000)}ms"
        if code is None:
            st.write(f"{icon} {name} — {ms}")
        else:
            st.write(f"{icon} {name} — {code} — {ms}")

    st.markdown('<div class="hr"></div>', unsafe_allow_html=True)

    # KPIs
    s = scan["scores"]["security"]
    p = scan["scores"]["performance"]
    m = scan["scores"]["maintainability"]

    k1, k2, k3 = st.columns(3)
    with k1:
        st.markdown('<div class="kpi">', unsafe_allow_html=True)
        st.markdown("**Security**")
        st.markdown(f"<h2 style='margin:0;'>{s}</h2>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with k2:
        st.markdown('<div class="kpi">', unsafe_allow_html=True)
        st.markdown("**Performance**")
        st.markdown(f"<h2 style='margin:0;'>{'N/A' if p==0 else p}</h2>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with k3:
        st.markdown('<div class="kpi">', unsafe_allow_html=True)
        st.markdown("**Maintainability**")
        st.markdown(f"<h2 style='margin:0;'>{m}</h2>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
    st.caption("Note: Public scan cannot read Bubble editor privacy rules or workflows unless they’re publicly exposed.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    with st.expander("View evidence log (what was checked)"):
        st.code(scan.get("evidence", ""), language="text")


with R:
    render_key_bullets(scan.get("key_bullets", []))
    st.write("")

    unlocked = bool(st.session_state.get("lead_unlocked", False))
    gated = not unlocked

    # SECURITY
    section_card("Security", scan["scores"]["security"])
    st.write("")
    render_findings(scan["findings"]["security"], gated=gated)

    # PERFORMANCE
    section_card("Performance", scan["scores"]["performance"])
    st.write("")
    render_findings(scan["findings"]["performance"], gated=gated)

    # MAINTAINABILITY
    section_card("Maintainability", scan["scores"]["maintainability"])
    st.write("")
    render_findings(scan["findings"]["maintainability"], gated=gated)

    st.write("")

    # Lead gate + Calendly
    unlocked_now = lead_gate_ui(scan)
    if unlocked_now:
        st.write("")
        calendly_embed()
