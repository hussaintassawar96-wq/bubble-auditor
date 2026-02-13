# app.py
# Bubble + Lovable Public Auditor (Streamlit)
# - Validates URL/App ID before scanning
# - Public-only checks (no editor access, no private APIs)
# - Shows Security / Performance / SEO
# - Lead unlock + Calendly booking in a popup (modal)

import re
import time
import json
import hashlib
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse

import requests
import streamlit as st

# -----------------------------
# CONFIG
# -----------------------------
APP_TITLE = "Bubble App Auditor"
CALENDLY_URL = "https://calendly.com/tassawarhussain/30min"
REQUEST_TIMEOUT = 10

# -----------------------------
# UTILITIES
# -----------------------------
def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    # strip trailing slash
    url = url.rstrip("/")
    return url

def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def stable_cache_key(*parts) -> str:
    s = "|".join([str(p).strip().lower() for p in parts])
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]

def safe_head(url: str) -> Tuple[Optional[int], Dict[str, str], float, Optional[str]]:
    try:
        t0 = time.time()
        r = requests.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        return r.status_code, dict(r.headers), (time.time() - t0), None
    except Exception as e:
        return None, {}, 0.0, str(e)

def safe_get(url: str) -> Tuple[Optional[int], Dict[str, str], str, float, Optional[str]]:
    try:
        t0 = time.time()
        r = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        text = r.text if isinstance(r.text, str) else ""
        return r.status_code, dict(r.headers), text, (time.time() - t0), None
    except Exception as e:
        return None, {}, "", 0.0, str(e)

def quick_access_check(url: str) -> Tuple[bool, str]:
    """
    Returns: (ok: bool, message: str)
    - Checks URL format
    - Checks reachability (HEAD then GET fallback)
    """
    u = normalize_url(url)
    if not u or not is_valid_url(u):
        return False, "URL is not valid. Please enter a full domain (e.g. https://yourapp.com)."

    code, headers, elapsed, err = safe_head(u + "/")
    if code is None:
        code2, headers2, text2, elapsed2, err2 = safe_get(u + "/")
        if code2 is None:
            return False, "URL is not accessible (network error / blocked). Try again or use another URL."
        code = code2

    # Reachable but restricted (allow scan, but warn)
    if code in (401, 403):
        return True, "URL is reachable but restricted (401/403). Public checks may be limited."

    # Hard fail cases
    if code == 404:
        return False, "URL returned 404 (page not found). Please check the domain/path."
    if code in (500, 502, 503, 504):
        return False, f"URL is reachable but server returned {code}. Try again later."

    if 200 <= code < 400:
        return True, "OK"

    return False, f"URL returned status {code}. Please confirm it’s correct."

def is_valid_bubble_app_id(app_id: str) -> bool:
    """
    Bubble app IDs commonly look like: yourapp-28503
    We'll allow letters/numbers/dashes and must end with -digits.
    """
    if not app_id:
        return True
    app_id = app_id.strip()
    return bool(re.match(r"^[a-z0-9-]+-\d+$", app_id, re.I))

def bubble_base_from_env(app_id: str, env: str, url_override: str) -> str:
    """
    If URL is provided, use it.
    Else try bubbleapps.io guess based on env.
    """
    if url_override:
        return normalize_url(url_override)

    # If user only gave app_id, attempt bubbleapps.io default pattern
    # NOTE: Many apps use custom domains; this is just a best-effort fallback.
    # Bubble test can be: https://appname.bubbleapps.io/version-test
    # Live can be:       https://appname.bubbleapps.io
    # App ID isn't always the same as subdomain. But user wants App ID input like NQU.
    # We'll still prefer URL input for accuracy.
    # We'll attempt to use app_id prefix before last dash as subdomain.
    sub = app_id.rsplit("-", 1)[0].strip().lower()
    if not sub:
        return ""
    if env == "version-test":
        return f"https://{sub}.bubbleapps.io/version-test"
    return f"https://{sub}.bubbleapps.io"

# -----------------------------
# AUDIT CHECKS
# -----------------------------
SECURITY_HEADERS_RECOMMENDED = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

SEO_TAGS = {
    "title": re.compile(r"<title>(.*?)</title>", re.I | re.S),
    "meta_desc": re.compile(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', re.I | re.S),
    "canonical": re.compile(r'<link\s+rel=["\']canonical["\']\s+href=["\'](.*?)["\']', re.I | re.S),
    "robots_meta": re.compile(r'<meta\s+name=["\']robots["\']\s+content=["\'](.*?)["\']', re.I | re.S),
    "h1": re.compile(r"<h1[^>]*>(.*?)</h1>", re.I | re.S),
}

def extract_first(regex: re.Pattern, html: str) -> str:
    m = regex.search(html or "")
    if not m:
        return ""
    val = m.group(1)
    val = re.sub(r"\s+", " ", val).strip()
    # strip remaining tags for H1
    val = re.sub(r"<[^>]+>", "", val).strip()
    return val

def detect_favicon(base_url: str) -> str:
    # Try common favicon path
    code, headers, text, elapsed, err = safe_get(base_url + "/favicon.ico")
    if code and 200 <= code < 400:
        return base_url + "/favicon.ico"
    return ""

def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    missing = []
    present = []
    for h in SECURITY_HEADERS_RECOMMENDED:
        if h in lower:
            present.append(h)
        else:
            missing.append(h)

    issues = []
    if missing:
        issues.append({
            "title": "Missing recommended security headers",
            "severity": "Medium",
            "details": "Missing: " + ", ".join([h.title() if "-" not in h else h for h in missing]) +
                       ". These reduce XSS/clickjacking/mixed-content risk."
        })
    else:
        issues.append({
            "title": "Recommended security headers present",
            "severity": "Low",
            "details": "All common security headers detected on the homepage response."
        })

    return {
        "missing": missing,
        "present": present,
        "issues": issues
    }

def check_cache_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    cc = lower.get("cache-control", "")
    if not cc:
        return {
            "issues": [{
                "title": "Cache-Control not detected on homepage response",
                "severity": "Low",
                "details": "If static assets are not cached aggressively, repeat visits may be slower."
            }]
        }
    return {
        "issues": [{
            "title": "Cache-Control detected",
            "severity": "Info",
            "details": f"Cache-Control: {cc}"
        }]
    }

def check_seo(html: str) -> Dict[str, Any]:
    title = extract_first(SEO_TAGS["title"], html)
    meta_desc = extract_first(SEO_TAGS["meta_desc"], html)
    canonical = extract_first(SEO_TAGS["canonical"], html)
    robots_meta = extract_first(SEO_TAGS["robots_meta"], html)
    h1 = extract_first(SEO_TAGS["h1"], html)

    issues = []
    score = 100

    if not title:
        issues.append({"title": "Missing <title>", "severity": "High", "details": "Title tag is important for SEO and sharing previews."})
        score -= 25
    if not meta_desc:
        issues.append({"title": "Missing meta description", "severity": "Medium", "details": "Meta description improves click-through and previews."})
        score -= 15
    if not canonical:
        issues.append({"title": "Missing canonical link", "severity": "Low", "details": "Canonical helps avoid duplicate content issues."})
        score -= 10
    if not h1:
        issues.append({"title": "Missing H1 on homepage", "severity": "Low", "details": "A clear H1 helps structure and accessibility."})
        score -= 10
    if robots_meta and ("noindex" in robots_meta.lower()):
        issues.append({"title": "robots meta contains noindex", "severity": "High", "details": f'robots="{robots_meta}" can prevent indexing.'})
        score -= 25

    score = max(0, min(100, score))
    return {
        "score": score,
        "title": title,
        "meta_desc": meta_desc,
        "canonical": canonical,
        "robots": robots_meta,
        "h1": h1,
        "issues": issues
    }

def score_security(sec: Dict[str, Any]) -> int:
    # Simple scoring: missing headers reduce score
    missing = sec.get("missing", [])
    s = 100 - (len(missing) * 6)
    return max(40, min(100, s))

def score_performance(home_elapsed: float, html_len: int) -> int:
    # Very simple proxy scoring (public-only)
    s = 100
    if home_elapsed > 2.0:
        s -= 20
    elif home_elapsed > 1.0:
        s -= 10
    if html_len > 500_000:
        s -= 15
    elif html_len > 200_000:
        s -= 10
    return max(40, min(100, s))

def score_maintainability(platform: str) -> int:
    # Public-only maintainability is limited; we keep it high but not perfect
    # because we can't inspect editor workflows/privacy rules unless exposed.
    return 92 if platform == "Bubble" else 90

def build_key_risks(scan: Dict[str, Any]) -> List[str]:
    bullets = []
    # endpoint accessibility signals
    if scan["checks"].get("meta", {}).get("status") in (401, 403, 404, None):
        bullets.append("Metadata endpoint does not appear publicly accessible (good baseline).")
    else:
        bullets.append("Metadata endpoint is publicly accessible — review exposure risk.")

    if scan["checks"].get("swagger", {}).get("status") in (401, 403, 404, None):
        bullets.append("Swagger schema not publicly accessible (good baseline).")
    else:
        bullets.append("Swagger schema appears public — your backend surface may be exposed.")

    sec_missing = scan["security"].get("missing", [])
    if sec_missing:
        bullets.append("Some recommended security headers are missing (CSP/HSTS/XFO etc.).")
    else:
        bullets.append("Recommended security headers look good on the homepage response.")

    # SEO summary
    seo_score = scan["seo"].get("score", 0)
    if seo_score < 70:
        bullets.append("SEO basics need attention (title/meta/canonical/H1).")
    else:
        bullets.append("SEO basics look decent (public homepage checks).")

    return bullets

def run_public_checks(base_url: str) -> Dict[str, Any]:
    # Homepage
    home_code, home_headers, home_html, home_elapsed, home_err = safe_get(base_url + "/")

    # Bubble-ish public endpoints (safe to try on any host)
    meta_code, meta_headers, meta_html, meta_elapsed, meta_err = safe_get(base_url + "/api/1.1/meta")
    swag_code, swag_headers, swag_html, swag_elapsed, swag_err = safe_get(base_url + "/swagger.json")

    return {
        "homepage": {"status": home_code, "elapsed": home_elapsed, "error": home_err, "headers": home_headers, "html": home_html},
        "meta": {"status": meta_code, "elapsed": meta_elapsed, "error": meta_err},
        "swagger": {"status": swag_code, "elapsed": swag_elapsed, "error": swag_err},
    }

def run_scan(platform: str, app_url: str, app_id: str, env: str) -> Dict[str, Any]:
    # Resolve base URL
    base = ""
    if platform == "Bubble":
        base = bubble_base_from_env(app_id.strip(), env, app_url.strip())
    else:
        base = normalize_url(app_url)

    if not base:
        return {"error": "Could not determine a valid base URL. Please enter a valid App URL."}

    checks = run_public_checks(base)
    home = checks["homepage"]

    if home.get("status") is None:
        return {"error": "Failed to fetch homepage (network error). Please try again."}

    # favicon / logo
    favicon = detect_favicon(base)

    # security
    sec = check_security_headers(home.get("headers", {}))

    # performance (public proxy)
    perf_issues = []
    html_len = len(home.get("html") or "")
    perf_issues.append({
        "title": "Homepage payload snapshot",
        "severity": "Info",
        "details": f"HTML size ≈ {round(html_len/1024, 1)} KB, response time ≈ {round(home.get('elapsed', 0.0)*1000)} ms."
    })
    perf_issues.extend(check_cache_headers(home.get("headers", {})).get("issues", []))

    # SEO
    seo = check_seo(home.get("html") or "")

    # Scores
    s_security = score_security(sec)
    s_perf = score_performance(home.get("elapsed", 0.0), html_len)
    s_maint = score_maintainability(platform)

    scan = {
        "input": {
            "platform": platform,
            "app_url": normalize_url(app_url),
            "app_id": app_id.strip(),
            "env": env,
            "base": base
        },
        "app": {
            "name": (app_id.strip() or urlparse(base).netloc.split(":")[0]).strip() or "App",
            "favicon": favicon
        },
        "checks": {
            "homepage": {"status": home.get("status"), "elapsed": home.get("elapsed")},
            "meta": {"status": checks["meta"].get("status"), "elapsed": checks["meta"].get("elapsed")},
            "swagger": {"status": checks["swagger"].get("status"), "elapsed": checks["swagger"].get("elapsed")},
        },
        "security": sec,
        "performance": {"issues": perf_issues},
        "maintainability": {"issues": [{
            "title": "Public scan limitation",
            "severity": "Info",
            "details": "This is a public scan. It cannot directly read Bubble editor privacy rules or workflow logic unless they are publicly exposed."
        }]},
        "seo": seo,
        "scores": {
            "security": s_security,
            "performance": s_perf,
            "maintainability": s_maint
        }
    }
    scan["key_risks"] = build_key_risks(scan)
    return scan

# -----------------------------
# UI HELPERS
# -----------------------------
def pill(sev: str) -> str:
    sev = (sev or "").lower()
    if sev == "high":
        return "🔴 High"
    if sev == "medium":
        return "🟠 Medium"
    if sev == "low":
        return "🟢 Low"
    return "🔵 Info"

def status_line(label: str, status: Optional[int], ms: Optional[float]) -> str:
    s = "—"
    if status is None:
        s = "ERR"
    else:
        s = str(status)
    t = ""
    if ms is not None:
        t = f"{int(ms*1000)}ms"
    return f"{label} — {s} — {t}"

def issue_block(title: str, sev: str, details: str):
    st.markdown(f"**{pill(sev)} {title}**")
    st.caption(details)

def init_state():
    if "last_scan" not in st.session_state:
        st.session_state["last_scan"] = None
    if "lead_unlocked" not in st.session_state:
        st.session_state["lead_unlocked"] = False
    if "lead_step" not in st.session_state:
        st.session_state["lead_step"] = "form"  # form | calendly
    if "last_fingerprint" not in st.session_state:
        st.session_state["last_fingerprint"] = ""

# -----------------------------
# STREAMLIT PAGE
# -----------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
init_state()

# Basic dark styling
st.markdown(
    """
    <style>
      .block-container { padding-top: 2rem; }
      .stApp { background: #0b0f14; color: #eaeef6; }
      h1, h2, h3 { color: #eaeef6; }
      .muted { color: rgba(234,238,246,.7); }
      .card {
        background: rgba(255,255,255,.04);
        border: 1px solid rgba(255,255,255,.08);
        border-radius: 18px;
        padding: 16px;
      }
      .big { font-size: 44px; font-weight: 800; margin: 0; }
      .label { font-size: 13px; opacity: .75; margin: 0; }
      .scorebox { display:flex; gap:18px; flex-wrap:wrap; }
      .scoreitem { min-width: 180px; }
      .barwrap {
        background: rgba(255,255,255,.06);
        border-radius: 999px;
        padding: 6px;
        border: 1px solid rgba(255,255,255,.08);
      }
      .barfill {
        height: 12px;
        border-radius: 999px;
        background: linear-gradient(90deg, #7c3aed, #ec4899);
        width: 50%;
      }
      .tiny { font-size: 12px; opacity:.75;}
      .btnPrimary button { background: #ff3b3b !important; border: none !important; }
      iframe { border-radius: 14px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header
left, right = st.columns([1, 2], gap="large")
with left:
    st.markdown(f"# {APP_TITLE}")
    st.markdown('<div class="muted">Public scan for Bubble and Lovable apps. No editor access required.</div>', unsafe_allow_html=True)

# Input bar
with right:
    c1, c2, c3 = st.columns([1.1, 1, 0.7])
    with c1:
        platform = st.selectbox("Platform", ["Bubble", "Lovable"], index=0)
        app_url = st.text_input("App URL", placeholder="https://yourapp.com or yourapp.bubbleapps.io")
    with c2:
        if platform == "Bubble":
            app_id = st.text_input("Bubble App ID", placeholder="yourapp-28503 (optional)")
        else:
            app_id = st.text_input("Lovable App ID", placeholder="Not required", disabled=True, value="")
    with c3:
        env = st.selectbox("Environment", ["live", "version-test"], index=0)
    run_btn = st.button("Run scan", type="primary", use_container_width=True)

# Reset unlock when inputs change
fingerprint = stable_cache_key(platform, app_url, app_id, env)
if st.session_state.get("last_fingerprint") != fingerprint:
    st.session_state["lead_unlocked"] = False
    st.session_state["lead_step"] = "form"
    st.session_state["last_fingerprint"] = fingerprint

# ✅ VALIDATE ONLY WHEN CLICKING RUN
if run_btn:
    if platform == "Bubble":
        if not (app_url.strip() or app_id.strip()):
            st.error("Please enter either App URL or Bubble App ID.")
            st.stop()

        if app_id.strip() and not is_valid_bubble_app_id(app_id):
            st.error("Bubble App ID looks invalid. Example: yourapp-28503")
            st.stop()

        if app_url.strip():
            ok, msg = quick_access_check(app_url)
            if not ok:
                st.error(msg)
                st.stop()
            if ok and msg != "OK":
                st.warning(msg)

    else:
        if not app_url.strip():
            st.error("Please enter the Lovable App URL.")
            st.stop()

        ok, msg = quick_access_check(app_url)
        if not ok:
            st.error(msg)
            st.stop()
        if ok and msg != "OK":
            st.warning(msg)

# Only run scan if button clicked OR last_scan exists
if not run_btn and st.session_state.get("last_scan") is None:
    st.info("Choose Bubble or Lovable, enter the URL (Bubble: ID optional), then click **Run scan**.")
    st.stop()

# Run scan
if run_btn or st.session_state.get("last_scan") is not None:
    prog = st.progress(0)
    status = st.empty()
    status.info("Starting scan…")
    prog.progress(20)

    status.info("Fetching and analyzing public endpoints…")
    prog.progress(65)

    scan = run_scan(platform, app_url, app_id, env)
    if scan.get("error"):
        st.error(scan["error"])
        st.stop()

    prog.progress(100)
    status.success("Audit complete ✅")
    st.session_state["last_scan"] = scan
else:
    scan = st.session_state.get("last_scan")

# -----------------------------
# RESULTS LAYOUT
# -----------------------------
scan = st.session_state.get("last_scan")
if not scan:
    st.stop()

L, R = st.columns([1, 2], gap="large")

# LEFT SIDEBAR (like NQU)
with L:
    st.markdown('<div class="card">', unsafe_allow_html=True)

    # app icon/name
    ico = scan["app"].get("favicon")
    name = scan["app"].get("name", "App")
    base = scan["input"]["base"]

    if ico:
        st.image(ico, width=36)
    st.markdown(f"## {name}")
    st.caption(base)

    st.markdown("### Audit Complete")
    st.markdown(
        f"- ⚠️ {status_line('Fetch homepage', scan['checks']['homepage']['status'], scan['checks']['homepage']['elapsed'])}\n"
        f"- ⚠️ {status_line('Fetch /api/1.1/meta', scan['checks']['meta']['status'], scan['checks']['meta']['elapsed'])}\n"
        f"- ⚠️ {status_line('Fetch swagger.json', scan['checks']['swagger']['status'], scan['checks']['swagger']['elapsed'])}"
    )

    st.markdown("### Scores")
    st.markdown('<div class="scorebox">', unsafe_allow_html=True)
    st.markdown(
        f'<div class="scoreitem"><p class="label">Security</p><p class="big">{scan["scores"]["security"]}</p></div>',
        unsafe_allow_html=True
    )
    st.markdown(
        f'<div class="scoreitem"><p class="label">Performance</p><p class="big">{scan["scores"]["performance"]}</p></div>',
        unsafe_allow_html=True
    )
    st.markdown(
        f'<div class="scoreitem"><p class="label">Maintainability</p><p class="big">{scan["scores"]["maintainability"]}</p></div>',
        unsafe_allow_html=True
    )
    st.markdown(
        f'<div class="scoreitem"><p class="label">SEO</p><p class="big">{scan["seo"]["score"]}</p></div>',
        unsafe_allow_html=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.caption("Note: This is a public scan. It cannot directly read editor privacy rules or workflow logic unless they are publicly exposed.")

    # CTA
    st.markdown("---")
    if not st.session_state["lead_unlocked"]:
        st.markdown("### Want the actionable fix plan?")
        st.caption("Unlock the step-by-step recommendations and I’ll walk you through the fastest wins first.")
        if st.button("Unlock report + book a 30-min review", use_container_width=True):
            st.session_state["show_modal"] = True
    else:
        st.success("Unlocked ✅ Open the booking modal to schedule.")
        if st.button("Open booking", use_container_width=True):
            st.session_state["show_modal"] = True

    st.markdown("</div>", unsafe_allow_html=True)

# RIGHT MAIN CONTENT
with R:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("## Key risks and focus areas")
    for b in scan.get("key_risks", []):
        st.markdown(f"- {b}")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")

    # SECURITY
    st.markdown('<div class="card">', unsafe_allow_html=True)
    s = scan["scores"]["security"]
    st.markdown(f"## Security")
    st.markdown(f'<div class="barwrap"><div class="barfill" style="width:{s}%;"></div></div>', unsafe_allow_html=True)
    st.caption(f"Score: {s}")

    for it in scan["security"].get("issues", []):
        issue_block(it["title"], it["severity"], it["details"])
        st.write("")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")

    # PERFORMANCE
    st.markdown('<div class="card">', unsafe_allow_html=True)
    p = scan["scores"]["performance"]
    st.markdown("## Performance")
    st.markdown(f'<div class="barwrap"><div class="barfill" style="width:{p}%;"></div></div>', unsafe_allow_html=True)
    st.caption(f"Score: {p}")

    for it in scan["performance"].get("issues", []):
        issue_block(it["title"], it["severity"], it["details"])
        st.write("")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")

    # SEO
    st.markdown('<div class="card">', unsafe_allow_html=True)
    seo_score = scan["seo"]["score"]
    st.markdown("## SEO")
    st.markdown(f'<div class="barwrap"><div class="barfill" style="width:{seo_score}%;"></div></div>', unsafe_allow_html=True)
    st.caption(f"Score: {seo_score}")

    # show key fields
    st.markdown(f"**Title:** {scan['seo'].get('title') or '—'}")
    st.markdown(f"**Meta description:** {scan['seo'].get('meta_desc') or '—'}")
    st.markdown(f"**Canonical:** {scan['seo'].get('canonical') or '—'}")
    st.markdown(f"**Robots:** {scan['seo'].get('robots') or '—'}")
    st.markdown(f"**H1:** {scan['seo'].get('h1') or '—'}")
    st.write("")

    for it in scan["seo"].get("issues", []):
        issue_block(it["title"], it["severity"], it["details"])
        st.write("")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")

    # MAINTAINABILITY
    st.markdown('<div class="card">', unsafe_allow_html=True)
    m = scan["scores"]["maintainability"]
    st.markdown("## Maintainability")
    st.markdown(f'<div class="barwrap"><div class="barfill" style="width:{m}%;"></div></div>', unsafe_allow_html=True)
    st.caption(f"Score: {m}")
    for it in scan["maintainability"].get("issues", []):
        issue_block(it["title"], it["severity"], it["details"])
        st.write("")
    st.markdown("</div>", unsafe_allow_html=True)

# -----------------------------
# MODAL (POPUP) LEAD + CALENDLY
# -----------------------------
if "show_modal" not in st.session_state:
    st.session_state["show_modal"] = False

@st.dialog("Unlock the report", width="large")
def unlock_modal():
    st.markdown("### Get the fix plan + fastest wins")
    st.caption("Tell me a bit about your app and I’ll review your scan and show you the quickest improvements first.")
    colA, colB = st.columns(2)

    with colA:
        name = st.text_input("Name", placeholder="Your name")
        email = st.text_input("Email", placeholder="you@company.com")
        role = st.selectbox("Your role", ["Founder", "Developer", "Product", "Ops", "Other"])
    with colB:
        timeline = st.selectbox("Timeline", ["ASAP (this week)", "Next 2 weeks", "This month", "Exploring"])
        notes = st.text_area("What should I know? (optional)", placeholder="e.g. marketplace, user files, paid plans, etc.")

    st.write("")
    if not st.session_state["lead_unlocked"]:
        if st.button("Unlock + Continue to booking", use_container_width=True):
            if not email.strip() or "@" not in email:
                st.error("Please enter a valid email to continue.")
                st.stop()
            st.session_state["lead_unlocked"] = True
            st.session_state["lead_step"] = "calendly"
            st.rerun()
    else:
        st.success("Unlocked ✅ Now pick a meeting time below.")

    if st.session_state["lead_unlocked"] and st.session_state["lead_step"] == "calendly":
        st.markdown("## Book your 30-minute meeting")
        st.caption("I’ll review your scan and point out the fastest wins first.")
        st.components.v1.iframe(CALENDLY_URL, height=760, scrolling=True)

# Open modal when user requests
if st.session_state.get("show_modal"):
    unlock_modal()
    st.session_state["show_modal"] = False
