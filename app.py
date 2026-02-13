import re
import time
import hashlib
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
from streamlit_modal import Modal


# ---------------------------
# CONFIG
# ---------------------------
CALENDLY_URL = "https://calendly.com/tassawarhussain/30min"
REQUEST_TIMEOUT = 12

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "AppAuditor/3.0 (+public-scan)"})


# ---------------------------
# PAGE SETUP + STYLES
# ---------------------------
st.set_page_config(page_title="App Auditor", page_icon="🧪", layout="wide")

st.markdown(
    """
<style>
:root{
  --card: rgba(255,255,255,0.06);
  --card2: rgba(255,255,255,0.04);
  --stroke: rgba(255,255,255,0.10);
  --muted: rgba(255,255,255,0.72);
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


def is_valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False


def env_base_from_inputs(app_url: str, app_id: str, env: str) -> str:
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


def build_evidence_lines(steps, probe=None):
    lines = []
    for (name, url, code, elapsed, err) in steps:
        ms = f"{int(elapsed*1000)}ms"
        if code is None:
            lines.append(f"{name}: ERROR ({err}) — {ms}")
        else:
            lines.append(f"{name}: {code} — {ms} — {url}")

    for pr in (probe or [])[:8]:
        s = pr.get("status")
        ms = f"{int(pr.get('elapsed',0)*1000)}ms"
        lines.append(f"Probe {pr['path']}: {s} — {ms}")

    return "\n".join(lines)[:4000]


# ---------------------------
# SEO CHECKS (PUBLIC ONLY)
# ---------------------------
def extract_meta(html: str, name: str):
    m = re.search(
        rf'<meta[^>]+name=["\']{re.escape(name)}["\'][^>]*content=["\']([^"\']*)["\']',
        html,
        re.I
    )
    return (m.group(1).strip() if m else "")


def extract_prop(html: str, prop: str):
    m = re.search(
        rf'<meta[^>]+property=["\']{re.escape(prop)}["\'][^>]*content=["\']([^"\']*)["\']',
        html,
        re.I
    )
    return (m.group(1).strip() if m else "")


def extract_link_rel(html: str, rel: str):
    m = re.search(
        rf'<link[^>]+rel=["\']{re.escape(rel)}["\'][^>]*href=["\']([^"\']+)["\']',
        html,
        re.I
    )
    return (m.group(1).strip() if m else "")


def h1_count(html: str):
    return len(re.findall(r"<h1\b", html, re.I))


def has_structured_data(html: str):
    if re.search(r'<script[^>]+type=["\']application/ld\+json["\']', html, re.I):
        return True
    if re.search(r'itemscope|itemtype=', html, re.I):
        return True
    return False


def image_alt_sample_stats(html: str, sample_limit: int = 30):
    imgs = re.findall(r"<img\b[^>]*>", html, re.I)
    imgs = imgs[:sample_limit]
    if not imgs:
        return 0, 0, 0
    with_alt = 0
    empty_alt = 0
    for tag in imgs:
        m = re.search(r'alt=["\']([^"\']*)["\']', tag, re.I)
        if m:
            with_alt += 1
            if m.group(1).strip() == "":
                empty_alt += 1
    return len(imgs), with_alt, empty_alt


def build_seo_findings(base: str, home_html: str, home_headers: dict):
    findings = []
    score = 100

    title = find_title(home_html)
    desc = extract_meta(home_html, "description")
    robots_meta = extract_meta(home_html, "robots")
    canonical = extract_link_rel(home_html, "canonical")
    og_title = extract_prop(home_html, "og:title")
    og_desc = extract_prop(home_html, "og:description")
    og_img = extract_prop(home_html, "og:image")
    tw_card = extract_meta(home_html, "twitter:card")
    h1s = h1_count(home_html)
    schema_ok = has_structured_data(home_html)
    img_n, img_with_alt, img_empty_alt = image_alt_sample_stats(home_html)

    robots_url = urljoin(base + "/", "robots.txt")
    sitemap_url = urljoin(base + "/", "sitemap.xml")
    r_code, _, r_txt, _, _, _ = safe_get(robots_url)
    s_code, _, s_txt, _, _, _ = safe_get(sitemap_url)

    x_robots = ""
    for hk, hv in (home_headers or {}).items():
        if hk.lower() == "x-robots-tag":
            x_robots = hv.strip()
            break

    if not title:
        findings.append(("High", "Missing <title> tag", "No title found on homepage HTML.", "Add a unique title (50–60 chars) describing the page + brand."))
        score -= 18
    elif len(title) < 10:
        findings.append(("Medium", "Title looks too short", f"Title: {title}", "Expand title to be descriptive (include key product keyword + brand)."))
        score -= 8

    if not desc:
        findings.append(("Medium", "Missing meta description", "No meta description found.", "Add a 140–160 char description that sells the value + includes keyword."))
        score -= 10
    elif len(desc) < 50:
        findings.append(("Low", "Meta description is very short", f"Description: {desc}", "Expand description to improve CTR on search results."))
        score -= 4

    if not canonical:
        findings.append(("Medium", "Missing canonical URL", "No rel=canonical found.", "Add canonical to avoid duplicate URL indexing issues."))
        score -= 8

    block_signals = []
    if robots_meta and ("noindex" in robots_meta.lower() or "nofollow" in robots_meta.lower()):
        block_signals.append(f'meta robots="{robots_meta}"')
    if x_robots and ("noindex" in x_robots.lower() or "nofollow" in x_robots.lower()):
        block_signals.append(f'X-Robots-Tag="{x_robots}"')
    if block_signals:
        findings.append(("High", "Indexing may be blocked", " | ".join(block_signals), "Remove noindex/nofollow on public pages you want to rank."))
        score -= 20

    if r_code != 200:
        findings.append(("Low", "robots.txt not found", f"GET {robots_url} → {r_code}", "Add robots.txt to control crawling and list your sitemap."))
        score -= 4
    else:
        if re.search(r"Disallow:\s*/\s*$", r_txt, re.I | re.M):
            findings.append(("Medium", "robots.txt may block all crawling", "robots.txt contains 'Disallow: /'", "Allow crawling for public marketing pages."))
            score -= 10

    if s_code != 200:
        findings.append(("Low", "sitemap.xml not found", f"GET {sitemap_url} → {s_code}", "Add sitemap.xml for better discovery (especially for many pages)."))
        score -= 4
    else:
        if "<urlset" not in (s_txt or ""):
            findings.append(("Info", "sitemap.xml exists but may not be standard", "sitemap.xml didn’t include <urlset> in first check.", "Verify it’s a valid XML sitemap."))

    if not (og_title and og_desc and og_img):
        findings.append(("Low", "OpenGraph tags incomplete", f"og:title={bool(og_title)}, og:description={bool(og_desc)}, og:image={bool(og_img)}", "Add OG tags for better link previews and CTR."))
        score -= 4
    if not tw_card:
        findings.append(("Info", "Twitter card not set", "twitter:card missing.", "Add twitter:card (summary_large_image) for better previews."))

    if h1s == 0:
        findings.append(("Medium", "No H1 found on homepage", "No <h1> tag detected.", "Add a single H1 describing your main offer (keyword + value)."))
        score -= 10
    elif h1s > 1:
        findings.append(("Low", "Multiple H1 tags detected", f"H1 count: {h1s}", "Prefer a single H1 per page for clarity."))
        score -= 4

    if not schema_ok:
        findings.append(("Low", "No structured data detected", "No JSON-LD / microdata found.", "Add JSON-LD (Organization, WebSite, Product/Service) for richer results."))
        score -= 4

    if img_n > 0:
        coverage = int((img_with_alt / max(1, img_n)) * 100)
        if coverage < 60:
            findings.append(("Low", "Many images missing alt text (sample)", f"Sampled {img_n} images, alt coverage ~{coverage}%", "Add alt text for accessibility + image SEO."))
            score -= 4
        if img_empty_alt > 5:
            findings.append(("Info", "Some images have empty alt", f"Empty alt count (sample): {img_empty_alt}", "Use empty alt only for decorative images; otherwise describe the image."))

    score = max(5, min(100, score))
    if not findings:
        findings.append(("Low", "No obvious SEO issues detected (public scan)", "Title, description, canonical, and crawling basics look fine.", "Consider adding structured data + improving content depth for competitive keywords."))

    bullets = [
        f"Title: {'present' if bool(title) else 'missing'}; Description: {'present' if bool(desc) else 'missing'}; Canonical: {'present' if bool(canonical) else 'missing'}",
        f"robots.txt: {'OK' if r_code==200 else 'missing'}; sitemap.xml: {'OK' if s_code==200 else 'missing'}",
        f"H1 tags: {h1s}; Structured data: {'found' if schema_ok else 'not found'}",
    ]

    return score, bullets, findings


def badge(sev: str):
    return f'<span class="badge sev-{sev}">{sev}</span>'


def section_header(title: str, score_value):
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


def render_items(items, gated: bool):
    for sev, title, evidence, fix in items:
        st.markdown(
            f"""
<div class="card2">
  <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
    {badge(sev)}
    <div style="font-weight:800;">{title}</div>
  </div>
  <div class="hr"></div>
  <div class="small"><b>Evidence:</b></div>
  <div class="evidence">{evidence}</div>
  <div style="height:10px;"></div>
  <div class="small"><b>Suggested fix:</b> {"(Unlock full fix plan in popup)" if gated else fix}</div>
</div>
""",
            unsafe_allow_html=True
        )
        st.write("")


# ---------------------------
# SCANS
# ---------------------------
def stable_cache_key(platform: str, app_url: str, app_id: str, env: str):
    s = f"{platform}|{normalize_url(app_url)}|{(app_id or '').strip()}|{env}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:18]


@st.cache_data(show_spinner=False)
def run_bubble_scan_cached(app_url: str, app_id: str, env: str, cache_key: str):
    base = env_base_from_inputs(app_url, app_id, env)
    if not base:
        return {"error": "Missing App URL or Bubble App ID."}

    steps = []

    home_url = base + "/"
    code, headers, html, _, elapsed, err = safe_get(home_url)
    steps.append(("Fetch homepage", home_url, code, elapsed, err))
    home_blocked = code in (401, 403)

    title = find_title(html) if (html and not home_blocked) else ((app_id.strip() if app_id else "Bubble App"))
    og_img = find_og_image(html, base) if (html and not home_blocked) else ""
    favicon = find_favicon(html, base) if (html and not home_blocked) else urljoin(base + "/", "favicon.ico")
    logo_url = og_img if og_img else favicon

    header_score, _, header_missing = score_headers(headers or {})

    meta_url = base + "/api/1.1/meta"
    m_code, _, _, m_json, m_elapsed, m_err = safe_get(meta_url)
    steps.append(("Fetch /api/1.1/meta", meta_url, m_code, m_elapsed, m_err))
    meta_exposed = (m_code == 200 and isinstance(m_json, dict))

    swagger_url = base + "/api/1.1/meta/swagger.json"
    s_code, _, _, s_json, s_elapsed, s_err = safe_get(swagger_url)
    steps.append(("Fetch swagger.json", swagger_url, s_code, s_elapsed, s_err))
    swagger_exposed = (s_code == 200 and isinstance(s_json, dict))

    swagger_paths = 0
    swagger_samples = []
    if swagger_exposed:
        swagger_paths, _, swagger_samples = extract_swagger_stats(s_json)

    admin_candidates = ["/admin", "/dashboard", "/settings", "/super_admin", "/superadmin", "/backend", "/login"]
    probe = probe_paths(base, admin_candidates)

    html_kb = int(len(html.encode("utf-8")) / 1024) if (html and not home_blocked) else None
    script_count = len(re.findall(r"<script\b", html or "", re.I)) if (html and not home_blocked) else None

    # SEO
    if home_blocked or not html:
        seo_score = 0
        seo_bullets = ["SEO checks limited because homepage HTML is not publicly accessible (401/403)."]
        seo_findings = [("Info", "SEO checks limited", f"GET {home_url} → {code}", "Make a public marketing page for accurate SEO checks.")]
    else:
        seo_score, seo_bullets, seo_findings = build_seo_findings(base, html, headers or {})

    # Scores
    sec = 100
    sec -= int((100 - header_score) * 0.45)
    if meta_exposed:
        sec -= 18
    if swagger_exposed:
        sec -= 12
    if home_blocked:
        sec += 6
    sec = max(5, min(100, sec))

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

    maint = 100
    if swagger_exposed:
        maint -= 10
    maint = max(10, min(100, maint))

    seo = seo_score

    # Key bullets
    key_bullets = [
        "This is a public scan (no API key). Private editor rules/workflows are not accessible.",
        "Public metadata + swagger exposure can reveal your API surface area.",
        f"Security headers missing: {', '.join(header_missing) if header_missing else 'none detected'}",
    ]
    if perf == 0:
        key_bullets.append("Performance snapshot limited because the homepage isn’t publicly accessible.")
    else:
        key_bullets.append(f"Homepage snapshot: ~{html_kb} KB HTML and ~{script_count} script tags.")
    key_bullets.extend(seo_bullets[:2])

    # Findings
    findings_security = []
    if meta_exposed:
        findings_security.append(("High", "Public /api/1.1/meta is accessible", f"GET {meta_url} → 200", "Restrict metadata exposure if it reveals sensitive structure."))
    if swagger_exposed:
        findings_security.append(("Medium", "Public swagger schema is accessible", f"GET {swagger_url} → 200 ({swagger_paths} paths)", "Ensure API auth is strict; hide swagger if not needed."))
    if header_missing:
        findings_security.append(("Medium", "Missing recommended security headers", "Missing: " + ", ".join(header_missing), "Add CSP/HSTS/XFO/Referrer/Permissions policies at CDN/proxy."))
    if not findings_security:
        findings_security.append(("Low", "No major public security red flags detected", "Public endpoints did not expose meta/swagger and headers look reasonable.", "Do a deeper audit if you handle sensitive data."))

    findings_perf = []
    if perf == 0:
        findings_perf.append(("Info", "Performance details limited", f"GET {home_url} → {code}", "Share a public page for deeper checks."))
    else:
        findings_perf.append(("Info", "Homepage payload snapshot", f"HTML ≈ {html_kb} KB, scripts ≈ {script_count}", "Reduce plugin bloat; defer heavy scripts; avoid workflows on load."))

    findings_maint = []
    if swagger_exposed and swagger_samples:
        findings_maint.append(("Info", "Public API surface snapshot (sample paths)", "Sample: " + ", ".join(swagger_samples[:10]) + ("..." if len(swagger_samples) > 10 else ""), "Document endpoints; standardize auth + naming patterns."))
    else:
        findings_maint.append(("Info", "Maintainability detail limited (public scan)", "No public swagger/meta available, or access restricted.", "Full audit needs editor access (workflows, data types, privacy rules)."))

    return {
        "platform": "Bubble",
        "base": base,
        "title": title,
        "logo_url": logo_url,
        "home_url": home_url,
        "steps": steps,
        "scores": {"security": sec, "performance": perf, "maintainability": maint, "seo": seo},
        "key_bullets": key_bullets,
        "findings": {
            "security": findings_security,
            "performance": findings_perf,
            "maintainability": findings_maint,
            "seo": seo_findings,
        },
        "evidence": build_evidence_lines(steps, probe=probe),
    }


@st.cache_data(show_spinner=False)
def run_lovable_scan_cached(app_url: str, cache_key: str):
    base = normalize_url(app_url)
    if not base or not is_valid_url(base):
        return {"error": "Please enter a valid Lovable app URL (must include domain)."}

    steps = []
    home_url = base + "/"
    code, headers, html, _, elapsed, err = safe_get(home_url)
    steps.append(("Fetch homepage", home_url, code, elapsed, err))
    home_blocked = code in (401, 403)

    title = find_title(html) if (html and not home_blocked) else "Lovable App"
    og_img = find_og_image(html, base) if (html and not home_blocked) else ""
    favicon = find_favicon(html, base) if (html and not home_blocked) else urljoin(base + "/", "favicon.ico")
    logo_url = og_img if og_img else favicon

    header_score, _, header_missing = score_headers(headers or {})

    html_kb = int(len(html.encode("utf-8")) / 1024) if (html and not home_blocked) else None
    script_count = len(re.findall(r"<script\b", html or "", re.I)) if (html and not home_blocked) else None

    # Public exposure probes (generic web)
    probe_paths_list = ["/.env", "/env", "/server-status", "/.git/config", "/sitemap.xml", "/robots.txt"]
    probe = probe_paths(base, probe_paths_list)

    # SEO
    if home_blocked or not html:
        seo_score = 0
        seo_bullets = ["SEO checks limited because homepage HTML is not publicly accessible (401/403)."]
        seo_findings = [("Info", "SEO checks limited", f"GET {home_url} → {code}", "Make sure your marketing page is public to validate SEO.")]
    else:
        seo_score, seo_bullets, seo_findings = build_seo_findings(base, html, headers or {})

    # Scores
    sec = 100
    sec -= int((100 - header_score) * 0.55)
    if home_blocked:
        sec += 4
    # If sensitive paths respond 200, reduce security
    exposed_hits = [p for p in probe if p.get("status") == 200]
    if exposed_hits:
        sec -= 18
    sec = max(5, min(100, sec))

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

    maint = 85  # Lovable: public scan can’t infer internal architecture
    seo = seo_score

    key_bullets = [
        "Lovable audit uses public web checks (headers, SEO, payload size).",
        f"Security headers missing: {', '.join(header_missing) if header_missing else 'none detected'}",
    ]
    if exposed_hits:
        key_bullets.append("Some sensitive/common files appear publicly accessible (needs review).")
    else:
        key_bullets.append("No obvious sensitive file exposure detected in basic probes.")
    if perf == 0:
        key_bullets.append("Performance snapshot limited because the homepage isn’t publicly accessible.")
    else:
        key_bullets.append(f"Homepage snapshot: ~{html_kb} KB HTML and ~{script_count} script tags.")
    key_bullets.extend(seo_bullets[:2])

    findings_security = []
    if header_missing:
        findings_security.append(("Medium", "Missing recommended security headers", "Missing: " + ", ".join(header_missing), "Add CSP/HSTS/XFO/Referrer/Permissions policies at CDN/proxy."))
    if exposed_hits:
        examples = ", ".join([e["path"] for e in exposed_hits[:5]])
        findings_security.append(("High", "Potential sensitive file exposure", f"200 OK on: {examples}", "Block access to config/debug files and review deployment rules."))
    if not findings_security:
        findings_security.append(("Low", "No major public security red flags detected", "Headers look reasonable and no obvious sensitive file exposure in basic probes.", "Consider deeper review if handling auth, payments, or PII."))

    findings_perf = []
    if perf == 0:
        findings_perf.append(("Info", "Performance details limited", f"GET {home_url} → {code}", "Make sure the marketing/home page is public for accurate checks."))
    else:
        findings_perf.append(("Info", "Homepage payload snapshot", f"HTML ≈ {html_kb} KB, scripts ≈ {script_count}", "Reduce heavy bundles; lazy-load non-critical components."))

    findings_maint = [
        ("Info", "Maintainability is limited in a public scan", "We can’t see internal components, data models, or build setup publicly.", "Share repo or staging access for a deeper architecture review.")
    ]

    return {
        "platform": "Lovable",
        "base": base,
        "title": title,
        "logo_url": logo_url,
        "home_url": home_url,
        "steps": steps,
        "scores": {"security": sec, "performance": perf, "maintainability": maint, "seo": seo},
        "key_bullets": key_bullets,
        "findings": {
            "security": findings_security,
            "performance": findings_perf,
            "maintainability": findings_maint,
            "seo": seo_findings,
        },
        "evidence": build_evidence_lines(steps, probe=probe),
    }


def run_scan(platform: str, app_url: str, app_id: str, env: str):
    ck = stable_cache_key(platform, app_url, app_id, env)
    if platform == "Bubble":
        return run_bubble_scan_cached(app_url, app_id, env, ck)
    return run_lovable_scan_cached(app_url, ck)


# ---------------------------
# HEADER
# ---------------------------
st.markdown("## App Auditor")
st.markdown('<div class="small">Pick a platform, run a public scan, then unlock fixes + book a call.</div>', unsafe_allow_html=True)
st.write("")


# ---------------------------
# INPUTS
# ---------------------------
platform = st.radio("Choose audit type", ["Bubble", "Lovable"], horizontal=True)

c1, c2, c3 = st.columns([0.44, 0.28, 0.28])

with c1:
    app_url = st.text_input("App URL", placeholder="yourapp.com or https://yourapp.bubbleapps.io")
with c2:
    if platform == "Bubble":
        app_id = st.text_input("Bubble App ID (recommended)", placeholder="yourapp-28503")
    else:
        app_id = ""
        st.text_input("Lovable App ID", value="Not required", disabled=True)
with c3:
    if platform == "Bubble":
        env = st.selectbox("Environment", ["live", "version-test"], index=0)
    else:
        env = "live"
        st.selectbox("Environment", ["live"], index=0, disabled=True)

run_btn = st.button("Run scan", type="primary", use_container_width=True)

fingerprint = stable_cache_key(platform, app_url, app_id, env)
if st.session_state.get("last_fingerprint") != fingerprint:
    st.session_state["lead_unlocked"] = False
    st.session_state["last_fingerprint"] = fingerprint

if "lead_step" not in st.session_state:
    st.session_state["lead_step"] = "form"   # form | calendly

if not run_btn and "last_scan" not in st.session_state:
    st.info("Choose Bubble or Lovable, enter the URL (Bubble: ID optional), then click **Run scan**.")
    st.stop()


# ---------------------------
# RUN SCAN
# ---------------------------
if run_btn or "last_scan" in st.session_state:
    base_url = normalize_url(app_url)
    if not base_url:
        st.error("Please enter the App URL.")
        st.stop()

    prog = st.progress(0)
    status = st.empty()
    status.info("Starting scan…")
    prog.progress(25)

    status.info("Fetching and analyzing public endpoints…")
    prog.progress(70)

    scan = run_scan(platform, app_url, app_id, env)
    if scan.get("error"):
        st.error(scan["error"])
        st.stop()

    prog.progress(100)
    status.success("Audit complete ✅")
    st.session_state["last_scan"] = scan
else:
    scan = st.session_state.get("last_scan")


# ---------------------------
# LAYOUT
# ---------------------------
L, R = st.columns([0.36, 0.64], gap="large")

with L:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    if scan.get("logo_url"):
        st.image(scan["logo_url"], width=72)

    st.markdown(f"### {scan.get('title','App')}")
    st.markdown(f'<div class="small">{scan.get("platform","")}</div>', unsafe_allow_html=True)
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

    s = scan["scores"]["security"]
    p = scan["scores"]["performance"]
    m = scan["scores"]["maintainability"]
    seo = scan["scores"]["seo"]

    k1, k2 = st.columns(2)
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

    k3, k4 = st.columns(2)
    with k3:
        st.markdown('<div class="kpi">', unsafe_allow_html=True)
        st.markdown("**Maintainability**")
        st.markdown(f"<h2 style='margin:0;'>{m}</h2>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with k4:
        st.markdown('<div class="kpi">', unsafe_allow_html=True)
        st.markdown("**SEO**")
        st.markdown(f"<h2 style='margin:0;'>{'N/A' if seo==0 else seo}</h2>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="hr"></div>', unsafe_allow_html=True)
    st.caption("Note: Public scans can’t see private editor settings, internal DB rules, or workflow logic.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    with st.expander("View evidence log"):
        st.code(scan.get("evidence", ""), language="text")

with R:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### Key risks and focus areas")
    for b in scan.get("key_bullets", [])[:8]:
        st.write(f"• {b}")
    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")

    unlocked = bool(st.session_state.get("lead_unlocked", False))
    gated = not unlocked

    section_header("Security", scan["scores"]["security"])
    st.write("")
    render_items(scan["findings"]["security"], gated=gated)

    section_header("Performance", scan["scores"]["performance"])
    st.write("")
    render_items(scan["findings"]["performance"], gated=gated)

    section_header("Maintainability", scan["scores"]["maintainability"])
    st.write("")
    render_items(scan["findings"]["maintainability"], gated=gated)

    section_header("SEO", scan["scores"]["seo"])
    st.write("")
    render_items(scan["findings"]["seo"], gated=gated)

    st.write("")
    open_popup = st.button("Unlock full fix plan + book a call", type="primary", use_container_width=True)


# ---------------------------
# MODAL POPUP (FORM OR CALENDLY, NOT BOTH)
# ---------------------------
modal = Modal(title="Unlock full Fix Plan + Book a 30-min call", key="unlock_modal", max_width=820)

if open_popup:
    modal.open()
    st.session_state["lead_step"] = "form" if not st.session_state.get("lead_unlocked", False) else "calendly"

if modal.is_open():
    with modal.container():
        st.components.v1.html(
            """
<script>
setTimeout(() => {
  const el = window.parent.document.querySelector('section.main');
  if(el) el.scrollTo({top: 0, behavior: 'smooth'});
}, 60);
</script>
""",
            height=0
        )

        if st.session_state.get("lead_step") == "form":
            st.markdown(
                """
<div class="cta">
  <h3 style="margin:0;">What you’ll get</h3>
  <div class="small" style="margin-top:8px;">
    A clear action plan: what to fix first, how to fix it, and what to ignore.
  </div>
  <div class="hr"></div>
  <div style="display:flex; gap:10px; flex-wrap:wrap;">
    <span class="pill">✅ Prioritized fix list</span>
    <span class="pill">✅ Security hardening checklist</span>
    <span class="pill">✅ Performance cleanup plan</span>
    <span class="pill">✅ SEO quick wins</span>
  </div>
</div>
""",
                unsafe_allow_html=True
            )
            st.write("")
            st.markdown("#### Enter details to unlock full fixes")

            with st.form("lead_form_modal", clear_on_submit=False):
                c1, c2 = st.columns(2)
                with c1:
                    name = st.text_input("Your name")
                    email = st.text_input("Email")
                    role = st.selectbox("Your role", ["Founder", "Developer", "Product", "Agency", "Other"])
                with c2:
                    company = st.text_input("Company (optional)")
                    timeline = st.selectbox("Timeline", ["ASAP (this week)", "This month", "Next 1–3 months", "Just exploring"])
                    notes = st.text_area("What should I know? (optional)", placeholder="e.g. auth, payments, user files, SEO goals, etc.")

                submitted = st.form_submit_button("Unlock + Continue to booking", type="primary", use_container_width=True)

            if submitted:
                st.session_state["lead_unlocked"] = True
                st.session_state["lead_step"] = "calendly"
                st.success("Unlocked ✅ Loading booking…")
                st.rerun()

        else:
            st.markdown("### Book your 30-minute meeting")
            st.markdown('<div class="small">I’ll review your scan and point out the fastest wins first.</div>', unsafe_allow_html=True)
            st.write("")

            st.components.v1.html(
                f"""
<div style="border:1px solid rgba(255,255,255,0.10); border-radius:18px; overflow:hidden; background: rgba(255,255,255,0.04);">
  <iframe src="{CALENDLY_URL}" width="100%" height="720" frameborder="0"></iframe>
</div>
""",
                height=760
            )

            c1, c2, c3 = st.columns([1, 1, 1])
            with c1:
                if st.button("Back", use_container_width=True):
                    st.session_state["lead_step"] = "form"
                    st.rerun()
            with c2:
                if st.button("Close", use_container_width=True):
                    modal.close()
            with c3:
                if st.button("Start over", use_container_width=True):
                    st.session_state["lead_unlocked"] = False
                    st.session_state["lead_step"] = "form"
                    modal.close()
