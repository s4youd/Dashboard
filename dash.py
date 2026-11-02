#!/usr/bin/env python3
"""
KeenDash — Ultimate Bug Bounty Prioritization Dashboard (v9.2 "Obsidian Pro")
Pre-Testing Intelligence Panel, premium dark theme, Phosphor Icons CDN,
VS Code–style notes tree, proper newline preview, working reset, full sidebar collapse.
Optional -k/--katana and -n/--nuclei recon enrichment. Autosaves to <domain>.json
next to the generated dashboard via the File System Access API (Chrome/Edge).
"""
import json, sys, os, base64, re, hashlib, argparse
from datetime import datetime
from collections import Counter, defaultdict
from urllib.parse import urlparse

# ========== Scoring & Classification ==========
TECH_SCORES = {
    "WordPress": 25, "wpBakery": 8, "WPML": 7, "Elementor": 10, "PHP": 5,
    "MySQL": 5, "Redis": 8, "Apache": 3, "Nginx": 2, "IIS": 10,
    "Microsoft ASP.NET": 8, "Windows Server": 10, "Cloudflare": 2,
    "HubSpot": 8, "Amazon S3": 12, "Amazon CloudFront": 8, "F5 BigIP": 20,
    "Citrix": 15, "Jenkins": 20, "Grafana": 15, "Zabbix": 15, "SAP": 18,
    "Harbor": 15, "GitLab": 18, "Tomcat": 10, "Spring": 12, "Django": 8,
    "Flask": 8, "Laravel": 10, "Drupal": 12, "Joomla": 12, "Basic": 15
}

HIGH_VALUE_KEYWORDS = [
    "admin", "api", "auth", "login", "portal", "dashboard", "panel", "internal",
    "staging", "dev", "test", "vpn", "gateway", "proxy", "jenkins", "gitlab",
    "grafana", "kibana", "zabbix", "exchange", "owa", "mail", "smtp", "ftp",
    "citrix", "sap", "oracle", "database", "db", "redis", "mongo", "elastic",
    "kafka", "docker", "kubernetes", "s3", "bucket", "cloud", "aws", "azure",
    "gcp", "payment", "billing", "checkout", "token", "secret", "config",
    "backup", "swagger", "docs", "graphql", "incident", "crm", "erp", "harbor",
    "registry", "monitor", "metric", "log"
]

STATUS_SCORES = {
    200: 40, 201: 35, 204: 25, 301: 15, 302: 15, 307: 10, 308: 15,
    401: 30, 403: 25, 404: 10, 405: 20, 409: 20, 500: 35, 502: 30, 503: 20, 504: 25
}

# ========== Optional Recon Enrichment (Katana crawl + Nuclei findings) ==========
KATANA_INTERESTING = [
    (".git/", "Exposed .git Directory"), (".env", "Exposed .env File"),
    (".svn/", "Exposed .svn Directory"), ("wp-admin", "WordPress Admin Panel"),
    ("wp-login", "WordPress Login"), ("wp-json", "WordPress REST API"),
    ("xmlrpc.php", "XML-RPC Endpoint"), ("swagger", "Swagger/OpenAPI Spec"),
    ("openapi", "OpenAPI Spec"), ("graphql", "GraphQL Endpoint"),
    ("actuator", "Spring Boot Actuator"), ("phpinfo", "phpinfo() Exposure"),
    ("server-status", "Apache Server Status"), (".bak", "Backup File Exposure"),
    (".sql", "SQL File Exposure"), (".zip", "Archive File Exposure"),
    (".tar", "Archive File Exposure"), (".yml", "Config File Exposure"),
    (".yaml", "Config File Exposure"), ("docker-compose", "Docker Compose Exposure"),
    ("id_rsa", "Private Key Exposure"), (".htaccess", "Htaccess Exposure"),
    ("web.config", "Web Config Exposure"), ("/admin", "Admin Path"),
    ("/console", "Console Path"), ("/debug", "Debug Endpoint"),
    ("/upload", "Upload Endpoint"), ("jwt", "JWT Reference"),
    ("token=", "Token in URL"), ("api_key", "API Key Reference"),
    ("secret", "Secret Reference"), ("/backup", "Backup Path"),
]

SEVERITY_SCORES = {"critical": 25, "high": 18, "medium": 10, "low": 5, "info": 2, "unknown": 2}


def normalize_host(value):
    """Turn a URL or bare host string into a lowercased, port-stripped host."""
    if not value:
        return ""
    v = str(value).strip()
    if "://" in v:
        try:
            v = urlparse(v).netloc
        except Exception:
            pass
    if "@" in v:
        v = v.split("@")[-1]
    if v.startswith("["):
        end = v.find("]")
        if end != -1:
            return v[:end + 1].lower()
    v = v.split(":")[0]
    return v.lower().strip(". ")


def parse_jsonl_generic(filepath):
    """Parse a JSON array or JSONL (one object per line) file into a list of dicts."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            return [data]
    except Exception:
        pass
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            if isinstance(d, dict):
                entries.append(d)
        except Exception:
            continue
    return entries


def parse_katana(filepath):
    """Parse katana JSONL crawl output into {host: {"urls": set, "hits": {label: set(urls)}}}."""
    entries = parse_jsonl_generic(filepath)
    result = defaultdict(lambda: {"urls": set(), "hits": defaultdict(set)})
    for e in entries:
        url = e.get("endpoint") or e.get("url")
        if not url:
            req = e.get("request") or {}
            if isinstance(req, dict):
                url = req.get("endpoint") or req.get("url")
        if not url:
            continue
        host = normalize_host(url)
        if not host:
            continue
        result[host]["urls"].add(url)
        low = url.lower()
        for kw, label in KATANA_INTERESTING:
            if kw in low:
                result[host]["hits"][label].add(url)
    return result


def parse_nuclei(filepath):
    """Parse nuclei JSONL output into {host: [finding, ...]}."""
    entries = parse_jsonl_generic(filepath)
    result = defaultdict(list)
    for e in entries:
        host_raw = e.get("host") or e.get("matched-at") or e.get("ip") or ""
        host = normalize_host(host_raw)
        if not host:
            continue
        info = e.get("info") if isinstance(e.get("info"), dict) else {}
        finding = {
            "id": e.get("template-id") or e.get("template") or "unknown",
            "name": info.get("name") or e.get("template-id") or "Finding",
            "severity": (info.get("severity") or "info").lower(),
            "matched_at": e.get("matched-at") or host_raw,
            "tags": info.get("tags") or [],
        }
        result[host].append(finding)
    return dict(result)


def enrich_with_recon(targets, katana_map=None, nuclei_map=None):
    """Merge optional katana crawl data and nuclei findings into built targets,
    boosting score/vulns/priority in place. Purely additive — safe to skip."""
    katana_map = katana_map or {}
    nuclei_map = nuclei_map or {}
    if not katana_map and not nuclei_map:
        return targets
    for t in targets:
        host = t["host"]
        changed = False
        kdata = katana_map.get(host)
        if kdata:
            urls = sorted(kdata["urls"])
            interesting = [
                {"label": lbl, "urls": sorted(u)[:10]}
                for lbl, u in kdata["hits"].items()
            ]
            t["katana"] = {"count": len(urls), "sample": urls[:200], "interesting": interesting}
            bonus = min(20, len(interesting) * 4)
            t["score"] = min(100, t["score"] + bonus)
            if t.get("score_breakdown") is not None:
                t["score_breakdown"]["recon"].append((f"Katana ({len(interesting)} patterns)", bonus, "Crawled URLs revealed sensitive paths — expanded attack surface with known endpoints to test"))
            for item in interesting:
                if item["label"] not in t["vulns"]:
                    t["vulns"].append(item["label"])
            changed = True
        ndata = nuclei_map.get(host)
        if ndata:
            seen = set()
            findings = []
            bonus = 0
            for f in ndata:
                key = (f["id"], f["name"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)
                bonus += SEVERITY_SCORES.get(f["severity"], 2)
                label = f"{f['name']} ({f['severity']})"
                if label not in t["vulns"]:
                    t["vulns"].append(label)
                if any(k in f["id"].lower() for k in ("ssl", "tls")) and "tls" not in t["cats"]:
                    t["cats"].append("tls")
            t["nuclei"] = findings[:200]
            capped = min(40, bonus)
            t["score"] = min(100, t["score"] + capped)
            if t.get("score_breakdown") is not None:
                t["score_breakdown"]["recon"].append((f"Nuclei ({len(findings)} findings)", capped, f"Nuclei confirmed {len(findings)} security findings — validated vulnerabilities requiring manual verification"))
            changed = True
        if changed:
            t["priority"] = priority_from_score(t["score"])
    return targets

def robust_parse_httpx(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()
    if not raw: return []
    # Skip KeenDash state exports (handled by load_data)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("KeenDash_state"):
            return []
        if isinstance(data, list): return data
        if isinstance(data, dict): return [data]
    except: pass
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line: continue
        try: entries.append(json.loads(line))
        except: continue
    return entries

def extract_host(entry):
    host = entry.get("host") or entry.get("input", "")
    if not host:
        url = entry.get("url") or entry.get("final_url", "")
        if url:
            try: host = urlparse(url).netloc
            except: pass
    return host

def extract_techs(entry):
    tech = entry.get("tech", [])
    if isinstance(tech, str): return [t.strip() for t in tech.split(",") if t.strip()]
    return tech if isinstance(tech, list) else []

def extract_ips(entry):
    ips = entry.get("a", [])
    if isinstance(ips, str): return [ips]
    return ips if isinstance(ips, list) else []

def classify_target(host, techs, title, url):
    c = f"{host.lower()} {' '.join(techs).lower()} {(title or '').lower()} {(url or '').lower()}"
    cats = []
    if any(k in c for k in ["vpn", "gateway", "sslvpn", "fortinet", "globalprotect", "checkpoint"]): cats.append("vpn")
    if any(k in c for k in ["wordpress", "wp-content", "drupal", "joomla"]): cats.append("cms")
    if any(k in host.lower() for k in ["api", "graphql", "rest"]) or any(k in c for k in ["/api/", "swagger"]): cats.append("api")
    if any(k in c for k in ["admin", "panel", "dashboard", "manage", "console"]): cats.append("admin")
    if any(k in c for k in ["mail", "smtp", "exchange", "owa", "webmail"]): cats.append("email")
    if any(k in c for k in ["cloud", "aws", "s3", "azure", "gcp", "oracle"]): cats.append("cloud")
    if any(k in c for k in ["jenkins", "gitlab", "ci", "cd", "deploy", "harbor"]): cats.append("cicd")
    if any(k in c for k in ["grafana", "zabbix", "kibana", "prometheus", "analytics"]): cats.append("monitoring")
    if any(k in c for k in ["mysql", "postgres", "mongo", "redis", "elastic", "database"]): cats.append("database")
    if any(k in c for k in ["auth", "login", "sso", "oauth", "saml", "keycloak"]): cats.append("auth")
    if not cats: cats.append("web")
    return cats

def detect_vulnerabilities(entry, techs, host, title, url):
    vulns = []
    s = entry.get("status_code", 0)
    c = f"{host} {' '.join(techs)} {title or ''} {url or ''}".lower()
    if "wordpress" in c: vulns += ["XSS (Stored)", "IDOR", "Plugin CVEs", "User Enumeration"]
    if any(k in c for k in ["api", "graphql"]): vulns += ["IDOR", "BOLA", "Mass Assignment"]
    if any(k in c for k in ["vpn", "gateway"]): vulns += ["Auth Bypass", "CVE Exploitation"]
    if any(k in c for k in ["login", "auth", "sso"]): vulns += ["Brute Force", "OAuth Misconfig"]
    if any(k in c for k in ["s3", "bucket", "cloud"]): vulns += ["SSRF", "Bucket Listing", "Cloud Metadata"]
    if any(k in c for k in ["exchange", "owa", "mail"]): vulns += ["NTLM Leak", "ProxyShell"]
    if any(k in c for k in ["jenkins", "ci"]): vulns += ["RCE (Script Console)", "Credential Dump"]
    if "f5" in c or "bigip" in c: vulns.append("CVE-2022-1388 (RCE)")
    if "citrix" in c: vulns.append("CVE-2019-19781 (Traversal)")
    if "grafana" in c: vulns.append("CVE-2021-43798 (Traversal)")
    if s == 200: vulns.append("Information Disclosure")
    if s == 401: vulns.append("Brute Force")
    if s == 403: vulns.append("403 Bypass")
    return list(dict.fromkeys(vulns))

def calculate_score(entry):
    """Calculate a prioritization score (0–100) with per-signal breakdown.

    Signals are grouped into weighted categories reflecting real-world bug-bounty
    triage priorities: access-control surface, technology exposure, content
    richness, naming-based heuristics, infrastructure posture, and reconnaissance
    enrichment.  Each signal records its label, points, and category so the
    frontend can render a transparent scoring breakdown.
    """
    breakdown = {
        "status": [], "tech": [], "content": [], "naming": [],
        "title": [], "infra": [], "recon": [],
    }
    host = extract_host(entry)
    techs = extract_techs(entry)
    status = entry.get("status_code", 0)
    words = entry.get("words", 0)
    title = (entry.get("title", "") or "").lower()
    cl = entry.get("content_length", 0)
    port = str(entry.get("port", ""))
    hl = host.lower()
    tech_lower = " ".join(t.lower() for t in techs)

    # ── Status code: access-control surface ──
    s_pts = STATUS_SCORES.get(status, 10)
    reasons = {
        200: "Fully accessible — confirms live endpoint, potential for direct interaction and data extraction",
        201: "Resource created — confirms write access or API functionality",
        204: "No content — endpoint accepted request, may have side effects worth exploring",
        301: "Permanent redirect — may leak internal paths or reveal app structure",
        302: "Temporary redirect — may expose auth-gated URLs behind redirect chain",
        307: "Temporary redirect — preserving method, potential redirect-based auth bypass",
        308: "Permanent redirect — preserving method, follow to find real endpoint",
        401: "Unauthorized — confirms auth exists, test for brute force, default creds, JWT issues",
        403: "Forbidden — access control present but may be bypassable (verb tampering, path traversal, IDOR)",
        404: "Not found — low signal, but custom 404 pages may leak server/framework info",
        405: "Method not allowed — confirms endpoint exists, try other HTTP methods (PUT, DELETE, PATCH)",
        409: "Conflict — may indicate stateful logic, potential for race conditions",
        500: "Server error — unhandled input may trigger crashes, SQLi, SSTI, or code execution",
        502: "Bad gateway — upstream failure, may indicate separate backend server (SSRF potential)",
        503: "Service unavailable — may reveal backend architecture, try when service recovers",
        504: "Gateway timeout — upstream timeout, potential DoS vector or slow desync attacks",
    }
    breakdown["status"].append((f"HTTP {status}", s_pts, reasons.get(status, f"Status code {status} — contributes to attack surface assessment")))

    # ── Technology stack ──
    tech_reasons = {
        "WordPress": "CMS target — test for plugin CVEs, WPScan, user enumeration, XML-RPC abuse",
        "PHP": "Server-side language — test for SQLi, file inclusion (LFI/RFI), deserialization, type juggling",
        "MySQL": "Database backend — test for SQL injection, privilege escalation, data exfiltration",
        "Redis": "In-memory DB — check for unauthenticated access, SSRF to Redis, command injection",
        "Apache": "Web server — test for path traversal, .htaccess bypass, mod_proxy SSRF",
        "Nginx": "Reverse proxy — test for path confusion, SSRF via upstream, request smuggling",
        "IIS": "Windows server — test for ASPX deserialization, web.config leak, NTLM relay",
        "Windows Server": "Windows host — test for SMB, RDP, WinRM, lateral movement vectors",
        "Microsoft ASP.NET": "Framework target — test for ViewState deserialization, padding oracle, SSRF",
        "Cloudflare": "CDN/WAF — origin IP may be exposed via DNS history,邮件 headers, or subdomains",
        "HubSpot": "SaaS platform — test for API key exposure, OAuth misconfig, data leakage",
        "Amazon S3": "Cloud storage — test for bucket listing, public read/write, metadata endpoints",
        "Amazon CloudFront": "CDN — find origin server, test for cache poisoning, origin header bypass",
        "F5 BigIP": "Load balancer — high-value CVE targets (CVE-2022-1388 RCE), test for iControl API",
        "Citrix": "Remote access — CVE-2019-19781 path traversal, test for session hijack, RCE",
        "Jenkins": "CI/CD server — script console RCE, credential dump, pipeline injection",
        "Grafana": "Monitoring — CVE-2021-43798 path traversal, test for unauthenticated dashboard access",
        "Zabbix": "Monitoring — test for SQLi in API, credential brute force, agent command injection",
        "SAP": "Enterprise app — high-value target, test for SAP-specific CVEs, default credentials",
        "Harbor": "Container registry — test for project enumeration, image pull, CVE-2020-16090",
        "GitLab": "Dev platform — test for repo enumeration, CI/CD pipeline abuse, SSRF (CVE-2021-22214)",
        "Tomcat": "App server — test for Manager app brute force, WAR file upload RCE",
        "Spring": "Java framework — test for Spring4Shell (CVE-2022-22965), SpEL injection",
        "Django": "Python framework — test for debug mode, ORM injection, CSRF bypass",
        "Flask": "Python framework — test for Jinja2 SSTI, debug mode info leak",
        "Laravel": "PHP framework — test for debug mode, env file exposure, deserialization (CVE-2021-3129)",
        "Drupal": "CMS — test for Drupalgeddon (CVE-2018-7600), module vulnerabilities",
        "Joomla": "CMS — test for known CVEs, SQLi in components, template disclosure",
        "Basic": "Basic auth detected — brute force credentials, test for default username/password combos",
        "Microsoft IIS": "Windows web server — test for shortname vulnerability, WebDAV, buffer overflow",
        "Express": "Node.js framework — test for prototype pollution, SSTI, JWT issues",
        "Docker": "Container platform — test for unauthenticated API, container escape, secret exposure",
        "Kubernetes": "Container orchestration — test for API server access, RBAC bypass, secret exposure",
    }
    for tech in techs:
        for known, pts in TECH_SCORES.items():
            if known.lower() in tech.lower():
                reason = tech_reasons.get(known, f"{known} technology detected — adds to attack surface")
                breakdown["tech"].append((known, pts, reason))
                break
    # Basic auth header detected
    if "Basic" in techs:
        breakdown["tech"].append(("Basic Auth", 10, "Basic authentication detected — weak credential scheme, brute force and default cred testing viable"))

    # ── Content richness: page complexity signals a real application ──
    if words > 10000:
        breakdown["content"].append(("Rich page (>10k words)", 15, "Complex application — significant functionality, forms, and attack surface to explore"))
    elif words > 5000:
        breakdown["content"].append(("Medium page (>5k words)", 12, "Moderate application — likely has multiple features and interactive elements"))
    elif words > 1000:
        breakdown["content"].append(("Page (>1k words)", 8, "Non-trivial content — not a stub page, contains real functionality"))
    elif words > 100:
        breakdown["content"].append(("Minimal page (>100 words)", 5, "Some content present — limited functionality but still worth checking"))
    if cl > 100000:
        breakdown["content"].append(("Large response (>100kB)", 10, "Heavy response — includes embedded JS/CSS, dynamic content, or API data"))
    elif cl > 50000:
        breakdown["content"].append(("Medium response (>50kB)", 7, "Substantial response — indicates real application logic"))
    elif cl > 10000:
        breakdown["content"].append(("Response >10kB", 5, "Moderate response size — some application logic present"))

    # ── Naming heuristics: keyword presence in hostname ──
    keyword_hits = [kw for kw in HIGH_VALUE_KEYWORDS if kw in hl]
    if keyword_hits:
        pts = len(keyword_hits) * 5
        breakdown["naming"].append((f"Keywords ({', '.join(keyword_hits[:5])})", pts, f"Hostname contains high-value keywords ({', '.join(keyword_hits[:3])}) — likely sensitive or internal endpoint"))
    if len(keyword_hits) > 5:
        breakdown["naming"].append(("10+ keywords", 15, "Hostname densely packed with keywords — very high probability of sensitive functionality"))

    # ── Subdomain prefix triggers ──
    triggers = [
        (["api.", ".api"], 10, "API surface", "API subdomain detected — test for IDOR, BOLA, mass assignment, injection, rate limiting"),
        (["auth.", "login.", "sso."], 10, "Auth surface", "Authentication endpoint — test for brute force, default creds, OAuth/SAML bypass, session fixation"),
        (["vpn.", "gateway."], 12, "VPN/Gateway", "VPN/gateway — high-value target, test for known CVEs, auth bypass, credential stuffing"),
        (["jenkins.", "gitlab.", "ci.", "drone."], 15, "CI/CD pipeline", "CI/CD server — potential RCE via build scripts, credential leakage, pipeline injection"),
        (["grafana.", "zabbix.", "kibana.", "prometheus.", "monitor."], 10, "Monitoring", "Monitoring platform — may expose internal metrics, credentials, infrastructure details"),
        (["admin.", "manage.", "panel.", "console."], 12, "Admin panel", "Admin interface — high-privilege target, test for auth bypass, default creds, IDOR"),
        (["internal.", "intranet.", "private."], 10, "Internal tool", "Internal tool — not meant for public access, likely has weaker security controls"),
        (["staging.", "stage.", "dev.", "test.", "qa.", "uat.", "sandbox."], 10, "Non-production env", "Non-production environment — often has weaker security, debug modes, test credentials"),
        (["legacy.", "old.", "v1.", "archive."], 8, "Legacy system", "Legacy system — likely unpatched, running deprecated software with known CVEs"),
        (["mail.", "smtp.", "exchange.", "owa.", "webmail."], 8, "Email", "Email server — test for NTLM leak, ProxyShell, open relay, credential brute force"),
        (["ftp.", "s3.", "bucket.", "minio."], 8, "File storage", "File storage — test for anonymous access, public listing, upload vulnerabilities"),
        (["db.", "database.", "mysql.", "redis.", "mongo.", "elastic."], 12, "Database", "Database endpoint — test for unauthenticated access, default creds, injection, data exfiltration"),
        (["sap.", "erp.", "crm."], 10, "Enterprise app", "Enterprise application — high-value target, test for business logic flaws, data exposure"),
        (["harbor.", "registry.", "docker."], 10, "Container registry", "Container registry — test for image pull, project enumeration, CVE-2020-16090"),
        (["swagger.", "docs.", "openapi."], 10, "API docs exposed", "API documentation exposed — reveals all endpoints, parameters, and data models for targeted attacks"),
        (["jira.", "confluence.", "wiki."], 8, "Dev tooling", "Dev tooling — may expose internal project details, credentials in tickets, CVEs"),
        (["grafana.", "kibana.", "splunk."], 8, "Observability", "Observability platform — may expose logs, metrics, internal infrastructure details"),
        (["keycloak.", "oauth.", "saml."], 8, "Identity provider", "Identity provider — central auth system, compromise here may grant access to everything"),
    ]
    for trig, pts, label, reason in triggers:
        if any(t in hl for t in trig):
            breakdown["naming"].append((label, pts, reason))

    # ── Title-based signals ──
    title_triggers = [
        (["admin", "dashboard", "panel", "console", "manager"], 8, "Admin interface", "Admin interface in title — high-privilege panel, test for auth bypass and default creds"),
        (["login", "sign in", "log in", "authenticate"], 6, "Login page", "Login page — entry point for brute force, credential stuffing, default creds, MFA bypass"),
        (["error", "exception", "traceback", "debug", "stack trace"], 10, "Error/debug exposure", "Error/debug info exposed — may leak framework version, file paths, SQL queries, stack traces"),
        (["swagger", "openapi", "graphql", "api"], 8, "API documentation", "API documentation in title — reveals endpoints, parameters, auth mechanisms"),
        (["phpinfo", "server-status", "server-info"], 12, "Server info exposed", "Server info page — leaks PHP config, modules, paths, environment variables, potentially secrets"),
        (["default", "welcome", "apache", "nginx"], 4, "Default page", "Default/server page — may indicate misconfiguration, check for hidden virtual hosts"),
        (["index of", "directory listing", "parent directory"], 12, "Directory listing", "Directory listing enabled — exposes file structure, potentially sensitive files and backups"),
    ]
    for triggers_list, pts, label, reason in title_triggers:
        if any(t in title for t in triggers_list):
            breakdown["title"].append((label, pts, reason))

    # ── Infrastructure signals ──
    if port and port not in ("", "80", "443", "8080", "8443"):
        breakdown["infra"].append((f"Non-standard port ({port})", 12, f"Non-standard port {port} — often internal/admin services exposed, may bypass security controls"))
    if port in ("8080", "8443", "8000", "9000", "3000", "5000"):
        breakdown["infra"].append((f"Dev port ({port})", 8, f"Development port {port} — likely dev server with weaker security, debug mode, or test data"))
    ips = extract_ips(entry)
    if len(ips) > 4:
        breakdown["infra"].append((f"Multi-IP ({len(ips)} addresses)", 5, f"Multiple IPs ({len(ips)}) — load-balanced or distributed, test all backends individually"))
    cdn_keywords = ["cloudflare", "akamai", "fastly", "cloudfront", "imperva", "sucuri", "aws waf"]
    for cdn in cdn_keywords:
        if cdn in tech_lower:
            breakdown["infra"].append((f"CDN/WAF ({cdn.title()})", -5, f"WAF/CDN detected ({cdn.title()}) — request filtering active, origin IP discovery needed"))
            break
    server = (entry.get("webserver", "") or "").lower()
    if server and any(v in server for v in ["apache/", "nginx/", "iis/", "tomcat/"]):
        breakdown["infra"].append(("Server version disclosure", 4, "Server version leaked in headers — enables targeted CVE research for exact version"))

    # ── Sum all signals, clamp to [0, 100] ──
    total = sum(pts for cat in breakdown.values() for _, pts, *_ in cat)
    total = max(0, min(100, total))
    return total, breakdown

def priority_from_score(score):
    if score >= 75: return "critical"
    if score >= 55: return "high"
    if score >= 35: return "medium"
    if score >= 20: return "low"
    return "info"

def generate_steps(target_dict):
    """Generate categorized pre-testing intelligence questions for every subdomain.
    Aggregated from: Ars0n Framework v2, R-s0n Bug_Bounty_Notes, HackTricks, XSS Rat 2026.
    """
    h = target_dict["host"].lower()
    techs = [t.lower() for t in target_dict["tech"]]
    st = target_dict["status"]
    tech_str = " ".join(techs)

    base = [
        ("recon", "Infrastructure", [
            "What ports are open and what services run on each?",
            "Is it cloud-hosted (AWS/GCP/Azure) or on-prem? Any cloud metadata endpoint reachable?",
            "Is there a WAF or reverse proxy in front? (Cloudflare, Akamai, Fastly, AWS WAF)",
            "What server software is running? (Nginx, Apache, IIS, Tomcat, custom)",
            "What OS and kernel version? Any known CVEs for this stack?",
            "Does it host multiple apps (vhosting)? Any shared infrastructure with other subdomains?",
            "Are there non-HTTP services on open ports? (SSH, RDP, DB, Redis, MongoDB)",
            "What are all resolved IPs? Any unusual DNS records (TXT, MX, SPF, DMARC)?",
        ]),
        ("stack", "Tech Stack", [
            "What languages and frameworks power this app? (PHP, Node.js, Python, Java, .NET, Go, Ruby)",
            "What CMS or platform? (WordPress, Drupal, Joomla, Laravel, Django, Spring)",
            "What third-party libraries or packages? Any known CVEs for their versions?",
            "Are there custom JavaScript libraries? Any client-side framework? (React, Angular, Vue)",
            "What database backend? (MySQL, PostgreSQL, MongoDB, Redis, Oracle)",
            "Is source code publicly available? (GitHub, GitLab, open-source repo)",
        ]),
        ("surface", "Attack Surface", [
            "What is the primary function of this subdomain? (API, admin portal, marketing, internal tool)",
            "Is it production, staging, dev, or QA? Any debug panels or test data exposed?",
            "What are all accessible endpoints? (robots.txt, sitemap.xml, .env, .git, swagger, GraphQL)",
            "Are there file upload features? What types accepted and where stored?",
            "Are there API endpoints? REST or GraphQL? Any introspection or documentation exposed?",
            "Are WebSockets used? Any Server-Sent Events or long-polling endpoints?",
            "What HTTP methods allowed? (GET, POST, PUT, DELETE, PATCH, OPTIONS)",
            "Does this subdomain interact with other internal services? (SSRF potential)",
        ]),
        ("auth", "Auth & Session", [
            "Is there authentication? What type? (Form, OAuth SSO, SAML, JWT, API key, mTLS)",
            "How is session established and maintained? (Cookie, JWT, token in header, session ID)",
            "What user roles exist? (admin, user, viewer, API, service account)",
            "How are users identified in requests? (user_id param, JWT claim, cookie, header)",
            "Is there 2FA or MFA? Can it be bypassed or enumerated?",
            "Is there rate limiting on login, password reset, or registration?",
            "Is there a password reset or account recovery flow? How does it work?",
            "Are there default or weak credentials? (admin:admin, test:test)",
        ]),
        ("security", "Security Headers", [
            "Is there a Content Security Policy? What directives? Any weaknesses?",
            "Is CORS configured? What origins, methods, and credentials are allowed?",
            "Are security headers present? (X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy)",
            "Is there a CAPTCHA or anti-bot mechanism? Can it be bypassed?",
            "How does the app handle special characters and encoding? (UTF-8, URL-encode, double-encode)",
            "Can you trigger error messages? What info is leaked? (stack traces, DB errors, paths)",
            "Is input validation client-side only, server-side, or both?",
            "Are there any interesting HTTP headers? (X-Powered-By, Server, custom auth headers)",
        ]),
        ("logic", "Business Logic", [
            "What data does this subdomain handle? (PII, financial, credentials, internal docs)",
            "What CRUD operations are available? Which are most sensitive?",
            "Are there multi-step workflows? (registration, checkout, approval chain, password reset)",
            "Are there time-sensitive operations? (token expiry, session timeout, race conditions)",
            "Is there a payment or billing flow? Can amounts, currencies, or quantities be manipulated?",
            "Are there import or export features? What formats? (CSV, XML, JSON, YAML)",
            "Are there notification features? (email, SMS, webhook) Any injection points?",
        ]),
    ]

    # ── Tech-specific bonus questions ──
    if any("wordpress" in t for t in techs) or "wordpress" in tech_str:
        base.append(("tech-wp", "WordPress", [
            "Is XML-RPC enabled? Can it be used for brute force or SSRF?",
            "Are there user enumeration vectors? (/author/, /wp-json/wp/v2/users)",
            "What plugins are installed? Any known vulnerabilities?",
            "Is the wp-config.php or .htaccess accessible?",
        ]))

    if any(k in h for k in ["api", "graphql", "rest"]) or "graphql" in tech_str:
        base.append(("tech-api", "API", [
            "Is there API documentation or Swagger/OpenAPI spec exposed?",
            "Are there rate limits on API endpoints? Can they be bypassed?",
            "For GraphQL: is introspection enabled? What mutations are available?",
            "Are there BOLA or IDOR vectors? (object IDs in URL, body, or headers)",
            "Is mass assignment possible? (sending extra fields in PUT/POST)",
        ]))

    if any(k in h for k in ["vpn", "gateway", "sslvpn", "fortinet", "globalprotect"]):
        base.append(("tech-vpn", "VPN", [
            "What VPN product and version? Any known CVEs?",
            "Are there default credentials? (admin/admin, admin/password)",
            "Is the portal accessible without authentication? What info leaks?",
        ]))

    if any(k in h for k in ["jenkins", "gitlab", "ci", "cd", "harbor", "registry"]):
        base.append(("tech-cicd", "CI/CD", [
            "Is the dashboard accessible without authentication?",
            "Are there script console or build-execution features?",
            "Are API tokens or credentials stored in plain text?",
        ]))

    if any(k in h for k in ["grafana", "zabbix", "kibana", "prometheus", "monitor"]):
        base.append(("tech-mon", "Monitoring", [
            "Are default credentials active? (admin:admin, admin:grafana)",
            "Is there unauthenticated data source access?",
            "Are there known path traversal or SSRF CVEs for this version?",
        ]))

    if any(k in h for k in ["s3", "bucket", "cloudfront", "cloud"]) or "s3" in tech_str:
        base.append(("tech-cloud", "Cloud", [
            "Is the storage bucket publicly readable or writable?",
            "Can cloud metadata be accessed via SSRF? (169.254.169.254, IMDSv2 bypass)",
            "Are there dangling DNS records pointing to deleted cloud resources?",
        ]))

    if any(k in h for k in ["exchange", "owa", "mail", "smtp", "webmail"]):
        base.append(("tech-mail", "Email", [
            "Is NTLM authentication enabled? Can hashes be harvested?",
            "Are there ProxyShell or ProxyLogon vulnerabilities for this version?",
            "Is there an open mail relay or SMTP misconfiguration?",
        ]))

    # ── Status-specific questions ──
    if st == 401:
        base.append(("status-401", "401 Auth", [
            "What authentication scheme? (Basic, Digest, Bearer, NTLM)",
            "Can default credentials authenticate? (admin:admin, test:test, root:root)",
            "Can 401 be bypassed via headers? (X-Forwarded-For, X-Original-URL)",
        ]))

    if st == 403:
        base.append(("status-403", "403 Forbidden", [
            "Can 403 be bypassed? (HTTP method change, path traversal, headers)",
            "Does X-Original-URL or X-Rewrite-URL bypass the restriction?",
            "Can double-encoding or path normalization tricks bypass?",
        ]))

    if st == 200:
        base.append(("status-200", "Active 200", [
            "What hidden endpoints exist? (robots.txt, sitemap, .env, .git, .svn)",
            "Are there admin panels or management interfaces accessible?",
            "Is there directory listing enabled anywhere?",
            "What parameters does each endpoint accept? Any reflected input?",
        ]))

    # Flatten: each item is "category_key|Category Label|Question text"
    steps = []
    for cat_key, cat_name, questions in base:
        for q in questions:
            steps.append(f"{cat_key}|{cat_name}|{q}")

    return steps

def build_targets(entries):
    host_map = {}
    for e in entries:
        h = extract_host(e)
        if not h: continue
        if h not in host_map or e.get("words", 0) > host_map[h].get("words", 0):
            host_map[h] = e
    targets = []
    for host, entry in host_map.items():
        techs = extract_techs(entry)
        title = entry.get("title", "") or ""
        url = entry.get("url", "")
        status = entry.get("status_code", 0)
        words = entry.get("words", 0)
        cl = entry.get("content_length", 0)
        ips = extract_ips(entry)
        ip = entry.get("host_ip", ips[0] if ips else "")
        port = entry.get("port", "")
        location = entry.get("location", "")
        score, score_breakdown = calculate_score(entry)
        priority = priority_from_score(score)
        cats = classify_target(host, techs, title, url)
        vulns = detect_vulnerabilities(entry, techs, host, title, url)
        steps = generate_steps({"host": host, "tech": techs, "status": status})
        desc_parts = []
        if status == 200:
            if words > 1000: desc_parts.append(f"Active app ({words:,} words)")
            elif words > 100: desc_parts.append(f"Page ({words} words)")
            else: desc_parts.append("Minimal content")
        elif status in (301, 302): desc_parts.append(f"Redirects to {location or 'external'}")
        elif status == 401: desc_parts.append("Auth required")
        elif status == 403: desc_parts.append("Forbidden")
        elif status in (500, 502, 503): desc_parts.append(f"Server error ({status})")
        if techs: desc_parts.append(f"Stack: {', '.join(techs[:5])}")
        desc = ". ".join(desc_parts) + "." if desc_parts else "No details."
        targets.append({
            "host": host, "url": url, "ip": ip, "port": port, "status": status,
            "tech": techs, "title": title, "words": words, "cl": cl, "location": location,
            "score": score, "priority": priority, "cats": cats, "vulns": vulns,
            "steps": steps, "desc": desc, "ips": ips, "score_breakdown": score_breakdown
        })
    targets.sort(key=lambda t: t["score"], reverse=True)
    return targets

def build_ip_map(targets):
    m = defaultdict(lambda: {"hosts": [], "ports": set(), "techs": set()})
    for t in targets:
        for ip in t["ips"]:
            if ip:
                m[ip]["hosts"].append(t["host"])
                if t["port"]: m[ip]["ports"].add(str(t["port"]))
                for tech in t["tech"]: m[ip]["techs"].add(tech)
    return dict(sorted(m.items(), key=lambda x: -len(x[1]["hosts"])))

def load_data(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()
    if raw.startswith('<!DOCTYPE html>') or raw.startswith('<html'):
        match_state = re.search(r'<script id="app-state" type="application/json">(.*?)</script>', raw, re.DOTALL)
        match_targets = re.search(r'<script id="initial-targets" type="application/json">(.*?)</script>', raw, re.DOTALL)
        if match_state and match_targets:
            try:
                state = json.loads(match_state.group(1))
                targets_b64 = match_targets.group(1)
                targets = json.loads(base64.b64decode(targets_b64).decode('utf-8'))
                print("[*] Extracted state from existing HTML Dashboard.")
                return targets, state, True
            except Exception as e:
                print(f"[!] Failed to parse embedded state: {e}")
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("KeenDash_state"):
            print("[*] Detected KeenDash State Export. Restoring...")
            return data.get("targets", []), data.get("state", {}), True
    except: pass
    entries = robust_parse_httpx(filepath)
    if not entries: return [], {}, False
    targets = build_targets(entries)
    return targets, {}, False

def generate_html(targets, ip_map, saved_state, input_file):
    prios = Counter(t["priority"] for t in targets)
    cats = Counter(c for t in targets for c in t["cats"])
    all_vulns = Counter(v for t in targets for v in t["vulns"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    fname = os.path.basename(input_file)

    # Derive output name from input: calendly.json -> calendly.html
    out_base = re.sub(r'(_state)?\.(json|html)$', '', fname, flags=re.IGNORECASE)
    out_html_name = out_base + '.html'

    dash_id = hashlib.md5(fname.encode()).hexdigest()[:12]

    vuln_targets = defaultdict(list)
    for t in targets:
        for v in t.get("vulns", []):
            vuln_targets[v].append(t["host"])

    cat_order = ["web", "vpn", "api", "cms", "email", "cloud", "cicd", "monitoring", "admin", "auth", "database"]
    cat_label = {"web": "Web", "vpn": "VPN", "api": "API", "cms": "CMS", "email": "Email",
                 "cloud": "Cloud", "cicd": "CI/CD", "monitoring": "Monitor", "admin": "Admin",
                 "auth": "Auth", "database": "DB"}
    cat_buttons = ""
    for c in cat_order:
        if cats.get(c, 0):
            cat_buttons += f'<button class="cat-btn" data-cat="{c}" onclick="filterByCategory(`{c}`, this)">{cat_label.get(c, c)} ({cats[c]})</button>'

    vuln_rows = ""
    for v, cnt in all_vulns.most_common(50):
        severity = "sv-c" if any(k in v.lower() for k in ["rce", "bypass", "traversal"]) else \
                   "sv-h" if any(k in v.lower() for k in ["idor", "ssrf", "xss", "injection"]) else \
                   "sv-m" if any(k in v.lower() for k in ["misconfig", "disclosure"]) else "sv-l"
        targets_list = vuln_targets.get(v, [])
        targets_html = "".join(f'<li><a href="https://{h}" target="_blank">{h}</a></li>' for h in targets_list[:50])
        if len(targets_list) > 50: targets_html += f'<li style="color:var(--text-muted)">+{len(targets_list)-50} more...</li>'
        vuln_rows += f'''
        <div class="vuln-card">
            <div class="vuln-header" onclick="this.parentElement.classList.toggle('expanded')">
                <span class="vuln-dot {severity}"></span>
                <span class="vuln-name">{v}</span>
                <span class="vuln-count">{cnt} target{"s" if cnt != 1 else ""}</span>
                <i class="ph ph-caret-right vuln-arrow"></i>
            </div>
            <div class="vuln-body"><ul>{targets_html}</ul></div>
        </div>'''

    ip_rows = ""
    for ip, d in ip_map.items():
        ports = ", ".join(sorted(d["ports"])) or "-"
        hosts_links = " ".join(f'<a href="https://{h}" target="_blank">{h}</a>' for h in d["hosts"][:5])
        if len(d["hosts"]) > 5: hosts_links += f' <span class="im">+{len(d["hosts"])-5}</span>'
        ip_rows += f'<div class="ipr"><div class="ia"><i class="ph ph-network" style="margin-right:6px"></i>{ip}</div><div class="im2">{len(d["hosts"])} host{"s" if len(d["hosts"]) != 1 else ""} · {ports}</div><div class="ih">{hosts_links}</div></div>\n'

    targets_b64 = base64.b64encode(json.dumps(targets, ensure_ascii=False).encode("utf-8")).decode("ascii")
    state_json = json.dumps(saved_state, ensure_ascii=False)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KeenDash — {out_base}</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect width=%22100%22 height=%22100%22 rx=%2222%22 fill=%22%231e2024%22 stroke=%22%235b8def%22 stroke-width=%224%22/><text x=%2250%22 y=%2254%22 font-size=%2264%22 text-anchor=%22middle%22 dominant-baseline=%22middle%22>👾</text></svg>">
<!-- Phosphor Icons CDN -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@phosphor-icons/web@2.1.1/src/regular/style.css">
<!-- Marked.js for markdown rendering -->
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<!-- CodeMirror -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/theme/material-darker.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/markdown/markdown.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/xml/xml.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/javascript/javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/python/python.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/sql/sql.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/css/css.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/htmlmixed/htmlmixed.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/clike/clike.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/shell/shell.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/addon/edit/continuelist.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ============================================
   Obsidian Pro — Premium Dark Palette
   ============================================ */
:root {{
  --bg-root:      #111214;
  --bg-elevated:  #17181b;
  --bg-surface:   #1e2024;
  --bg-sidebar:   #17181b;
  --border:       #2b2d33;
  --border-light: #202226;
  --text-primary: #e9eaee;
  --text-secondary:#9ba0aa;
  --text-muted:   #62666f;
  --accent:       #5b8def;
  --accent-hover: #77a1f2;
  --accent-subtle:rgba(91,141,239,0.15);
  --danger:       #f0616d;
  --danger-subtle:rgba(240,97,109,0.12);
  --success:      #3fcf8e;
  --success-subtle:rgba(63,207,142,0.12);
  --warning:      #e8b84b;
  --warning-subtle:rgba(232,184,75,0.12);
  --p-critical:   #f0616d;
  --p-high:       #ef9c5c;
  --p-medium:     #e8b84b;
  --p-low:        #3fcf8e;
  --p-info:       #5b8def;
  --font-ui:      'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono:    'JetBrains Mono', 'Consolas', 'Courier New', monospace;
  --radius:       6px;
  --transition:   0.15s ease;
  --shadow-sm:    0 1px 2px rgba(0,0,0,0.24);
  --shadow-md:    0 4px 16px rgba(0,0,0,0.28);
}}

/* ============================================
   Reset & Base
   ============================================ */
* {{ margin:0; padding:0; box-sizing:border-box; }}
html, body {{
  font-family: var(--font-ui);
  background: var(--bg-root);
  color: var(--text-primary);
  font-size: 13px;
  height: 100vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}}

/* Scrollbar */
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{ background: rgba(121,121,121,0.35); border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: rgba(121,121,121,0.55); }}

@keyframes fadeIn {{ from {{ opacity:0 }} to {{ opacity:1 }} }}

/* ============================================
   Top Bar (same layout as original)
   ============================================ */
.top-bar {{
  height: 64px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-light);
  display: flex;
  align-items: center;
  padding: 0 16px;
  gap: 16px;
  flex-shrink: 0;
  z-index: 100;
}}
.brand {{
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 700;
  font-size: 14px;
  color: var(--text-primary);
  letter-spacing: 0.5px;
}}
.brand i {{ font-size: 20px; color: var(--accent); }}
.nav-tabs {{ display: flex; gap: 2px; flex: 1; overflow-x: auto; }}
.nav-tab {{
  padding: 6px 14px;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  position: relative;
}}
.nav-tab:hover {{ color: var(--text-primary); background: rgba(255,255,255,0.04); }}
.nav-tab.active {{ color: var(--accent); background: var(--accent-subtle); }}
.nav-tab .close-btn {{
  margin-left: 6px;
  width: 18px; height: 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  opacity: 0;
  transition: var(--transition);
}}
.nav-tab:hover .close-btn {{ opacity: 0.5; }}
.nav-tab .close-btn:hover {{ opacity: 1; background: var(--danger-subtle); color: var(--danger); }}
.tab-dot {{ width: 8px; height: 8px; border-radius: 50%; background: var(--accent); }}

.nav-actions {{ display: flex; gap: 6px; align-items: center; }}
.btn-action {{
  padding: 5px 12px;
  border-radius: var(--radius);
  font-size: 12px;
  font-weight: 500;
  background: transparent;
  color: var(--text-secondary);
  border: 1px solid var(--border);
  cursor: pointer;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 5px;
  height: 30px;
}}
.btn-action:hover {{ color: var(--text-primary); border-color: var(--text-muted); background: rgba(255,255,255,0.04); }}
.btn-action.primary {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.btn-action.primary:hover {{ background: var(--accent-hover); }}

.save-status {{ font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 5px; }}
.status-dot {{ width: 7px; height: 7px; border-radius: 50%; }}
.status-dot.green {{ background: var(--success); box-shadow: 0 0 6px var(--success); }}
.status-dot.yellow {{ background: var(--warning); box-shadow: 0 0 6px var(--warning); }}
.status-dot.gray {{ background: var(--text-muted); }}
.status-dot.blue {{ background: var(--accent); box-shadow: 0 0 6px var(--accent); }}

/* ============================================
   Viewport
   ============================================ */
.viewport {{ flex: 1; overflow: hidden; position: relative; }}

/* ============================================
   Stats Grid
   ============================================ */
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 8px; margin-bottom: 16px; }}
.stat-card {{
  padding: 12px 16px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-light);
  border-radius: var(--radius);
  text-align: center;
  transition: var(--transition);
  box-shadow: var(--shadow-sm);
}}
.stat-card:hover {{ background: var(--bg-surface); }}
.stat-val {{ font-size: 22px; font-weight: 700; margin-bottom: 2px; font-family: var(--font-mono); }}
.stat-lbl {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}

/* ============================================
   Toolbar
   ============================================ */
.toolbar {{ display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; align-items: center; }}
.toolbar input, .toolbar select {{
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-primary);
  padding: 5px 10px;
  border-radius: var(--radius);
  font-size: 12px;
  font-family: inherit;
  outline: none;
  transition: var(--transition);
  height: 28px;
}}
.toolbar input:focus, .toolbar select:focus {{ border-color: var(--accent); }}
.toolbar input {{ width: 200px; }}
.toolbar select {{ min-width: 120px; }}
.btn-sm {{
  padding: 4px 10px;
  border-radius: var(--radius);
  font-size: 11px;
  font-weight: 500;
  background: var(--bg-surface);
  color: var(--text-secondary);
  border: 1px solid var(--border);
  cursor: pointer;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 4px;
  height: 28px;
}}
.btn-sm:hover {{ color: var(--text-primary); border-color: var(--text-muted); }}
.btn-sm.danger {{ color: var(--danger); }}
.btn-sm.danger:hover {{ background: var(--danger-subtle); }}
.btn-sm.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.btn-sm.active:hover {{ color: #fff; }}

/* ============================================
   Category Filter
   ============================================ */
.cat-filter {{ display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 16px; }}
.cat-btn {{
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 11px;
  cursor: pointer;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 4px;
  height: 24px;
}}
.cat-btn:hover {{ color: var(--text-primary); border-color: var(--text-muted); }}
.cat-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}

/* ============================================
   Target Cards
   ============================================ */
.card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 8px; }}
.t-card {{
  background: var(--bg-elevated);
  border: 1px solid var(--border-light);
  border-radius: var(--radius);
  padding: 14px;
  position: relative;
  overflow: hidden;
  transition: var(--transition);
  box-shadow: var(--shadow-sm);
}}
.t-card:hover {{ border-color: var(--border); background: var(--bg-surface); box-shadow: var(--shadow-md); transform: translateY(-1px); }}
.t-card::before {{ content:''; position:absolute; left:0; top:0; bottom:0; width:3px; }}
.t-card.p-crit::before {{ background: var(--p-critical); }}
.t-card.p-high::before {{ background: var(--p-high); }}
.t-card.p-med::before {{ background: var(--p-medium); }}
.t-card.p-low::before {{ background: var(--p-low); }}
.t-card.p-info::before {{ background: var(--p-info); }}

.t-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }}
.t-host {{
  font-size: 13px; font-weight: 600; color: var(--text-primary);
  text-decoration: none; font-family: var(--font-mono); word-break: break-all;
}}
.t-host:hover {{ color: var(--p-info); }}
.t-score {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 10px; font-family: var(--font-mono); }}
.s-crit {{ background: rgba(244,71,71,0.15); color: var(--p-critical); }}
.s-high {{ background: rgba(206,145,120,0.15); color: var(--p-high); }}
.s-med  {{ background: rgba(220,220,170,0.15); color: var(--p-medium); }}
.s-low  {{ background: rgba(106,153,85,0.15); color: var(--p-low); }}
.s-info {{ background: rgba(86,156,214,0.15); color: var(--p-info); }}

.t-meta {{ font-size: 11px; color: var(--text-muted); margin-bottom: 6px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
.t-desc {{ font-size: 12px; line-height: 1.5; color: var(--text-secondary); margin-bottom: 8px; }}
.t-title {{
  font-size: 11px; color: var(--text-secondary); margin-bottom: 6px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}}
.tags {{ display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }}
.tag {{
  font-size: 10px; padding: 2px 6px; border-radius: 3px; font-weight: 500;
  background: var(--bg-root); color: var(--text-secondary); border: 1px solid var(--border-light);
}}
.tag.tech {{ color: var(--p-info); border-color: rgba(91,141,239,0.3); }}
.tag.vuln {{ color: var(--p-critical); border-color: rgba(240,97,109,0.3); }}
.tag.testing {{ color: var(--success); border-color: rgba(63,207,142,0.3); }}
.tag.recon {{ color: var(--warning); border-color: rgba(232,184,75,0.3); }}

.t-actions {{ display: flex; gap: 4px; flex-wrap: wrap; }}
.t-action {{
  padding: 3px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 500;
  background: var(--bg-root);
  color: var(--text-secondary);
  border: 1px solid var(--border-light);
  cursor: pointer;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 3px;
}}
.t-action:hover {{ color: var(--text-primary); border-color: var(--border); }}
.t-action.active {{ color: var(--accent); border-color: var(--accent); background: var(--accent-subtle); }}
.t-action.active i {{ transform: rotate(180deg); }}
.t-action i {{ transition: transform 0.3s ease; }}
.t-action i {{ font-size: 12px; }}

/* ============================================
   Scoring Detail Panel (toggle via chart-bar button)
   ============================================ */
.score-detail {{
  overflow: hidden;
  max-height: 0;
  opacity: 0;
  transition: opacity 0.3s ease, margin 0.3s ease, padding 0.3s ease;
  margin-top: 0;
  padding-top: 0;
  border-top: 0px solid transparent;
}}
.score-detail.open {{
  opacity: 1;
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border-light);
}}
.detail-total {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 11px;
  font-weight: 600;
  color: var(--text-secondary);
  padding: 0 2px 8px;
}}
.detail-cat {{
  margin-bottom: 8px;
}}
.detail-cat:last-child {{ margin-bottom: 0; }}
.detail-cat-header {{
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 10px;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
  padding: 3px 0 2px;
  border-bottom: 1px solid var(--border-light);
  margin-bottom: 4px;
}}
.detail-cat-header span:first-of-type {{ flex: 1; }}
.detail-cat-total {{
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-secondary);
  background: var(--bg-root);
  padding: 1px 5px;
  border-radius: 3px;
  font-weight: 600;
}}
.detail-signal {{
  padding: 4px 0 4px 18px;
  border-bottom: 1px dashed var(--border-light);
}}
.detail-signal:last-child {{ border-bottom: none; }}
.detail-signal-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
}}
.detail-label {{
  font-size: 11px;
  font-weight: 500;
  color: var(--text-secondary);
}}
.detail-pts {{
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
}}
.detail-reason {{
  font-size: 10px;
  color: var(--text-muted);
  margin-top: 2px;
  line-height: 1.4;
  font-style: italic;
}}

/* ============================================
   Testing Workspace (same layout)
   ============================================ */
.testing-workspace {{ display: flex; height: 100%; overflow: hidden; }}
.testing-sidebar {{
  width: 240px;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border-light);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  transition: width 0.2s ease;
  overflow: hidden;
}}
.testing-sidebar.collapsed {{ width: 0; border-right: none; }}
.testing-sidebar-header {{
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-light);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
  font-size: 11px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  color: var(--text-secondary);
  flex-shrink: 0;
  white-space: nowrap;
}}
.testing-sidebar-header .toggle-btn {{
  cursor: pointer;
  color: var(--text-muted);
  font-size: 14px;
  transition: var(--transition);
  display: flex;
  align-items: center;
}}
.testing-sidebar-header .toggle-btn:hover {{ color: var(--text-primary); }}
.testing-host-list {{ flex: 1; overflow-y: auto; padding: 4px 0; }}
.testing-host-item {{
  padding: 5px 14px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  transition: background 0.1s;
  border-left: 2px solid transparent;
  color: var(--text-secondary);
  white-space: nowrap;
  font-family: var(--font-mono);
}}
.testing-host-item:hover {{ background: rgba(255,255,255,0.03); }}
.testing-host-item.active {{ background: var(--accent-subtle); color: var(--text-primary); border-left-color: var(--accent); }}
.testing-host-item .host-name {{ flex: 1; overflow: hidden; text-overflow: ellipsis; color: inherit; text-decoration: none; font-family: var(--font-mono); font-size: 12px; }}
.testing-host-item .host-name:hover {{ color: var(--accent); text-decoration: underline; }}
.testing-host-item .prio-dot {{ width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }}

.testing-toggle-btn {{
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 24px;
  height: 48px;
  background: var(--bg-sidebar);
  border: 1px solid var(--border-light);
  border-left: none;
  border-radius: 0 6px 6px 0;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  color: var(--text-muted);
  font-size: 12px;
  z-index: 10;
  transition: all 0.2s ease;
}}
.testing-toggle-btn:hover {{ color: var(--accent); background: var(--bg-surface); }}
.testing-toggle-btn i {{ transition: transform 0.2s ease; }}

.testing-main {{
  flex: 1;
  overflow-y: auto;
  padding: 16px 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  background: var(--bg-root);
  min-height: 0;
}}

/* ============================================
   Workspace Sections
   ============================================ */
.workspace-section {{
  background: var(--bg-elevated);
  border: 1px solid var(--border-light);
  border-radius: var(--radius);
  overflow: hidden;
}}
.ws-header {{
  padding: 8px 12px;
  display: flex;
  align-items: center;
  gap: 8px;
  border-bottom: 1px solid var(--border-light);
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  background: var(--bg-surface);
}}
.ws-header i {{ font-size: 14px; }}
.ws-header .ws-title {{ flex: 1; }}
.ws-body {{ padding: 6px 12px; }}

/* ============================================
   Checklist
   ============================================ */
.check-item {{
  padding: 4px 0;
  font-size: 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-secondary);
  transition: color 0.1s;
}}
.check-item:hover {{ color: var(--text-primary); }}
.check-box {{
  width: 16px; height: 16px;
  border: 1px solid var(--border);
  border-radius: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  flex-shrink: 0;
  transition: all 0.1s;
  color: transparent;
}}
.check-item.done .check-box {{
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}}
.check-item.done {{ color: var(--text-muted); text-decoration: line-through; }}
.check-del {{
  margin-left: auto;
  opacity: 0;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 14px;
  transition: opacity 0.1s;
  display: flex;
  align-items: center;
}}
.check-item:hover .check-del {{ opacity: 0.5; }}
.check-del:hover {{ opacity: 1 !important; color: var(--danger); }}

.add-form {{ display: flex; gap: 6px; margin-top: 8px; }}
.add-form input {{
  flex: 1;
  background: var(--bg-root);
  border: 1px solid var(--border);
  color: var(--text-primary);
  padding: 5px 8px;
  border-radius: var(--radius);
  font-size: 12px;
  outline: none;
  font-family: var(--font-mono);
  height: 26px;
}}
.add-form input:focus {{ border-color: var(--accent); }}
.add-form button {{
  background: var(--accent);
  color: #fff;
  border: none;
  padding: 0 12px;
  border-radius: var(--radius);
  cursor: pointer;
  font-weight: 600;
  font-size: 12px;
  height: 26px;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 4px;
}}
.add-form button:hover {{ background: var(--accent-hover); }}

/* ============================================
   Pre-Testing Intelligence Panel
   ============================================ */
.pt-panel {{ border: 1px solid var(--border-light); display: flex; flex-direction: column; max-height: 55vh; }}
.pt-body {{ padding: 0; overflow-y: auto; flex: 1; min-height: 0; }}

.pt-section {{ border-bottom: 1px solid var(--border-light); }}
.pt-section:last-child {{ border-bottom: none; }}

.pt-section-header {{
  padding: 10px 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  background: var(--bg-surface);
  user-select: none;
  transition: background 0.15s ease;
}}
.pt-section-header:hover {{ background: rgba(255,255,255,0.04); }}
.pt-section-header .pt-cat-icon {{
  width: 18px; height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}}
.pt-section-header .pt-cat-icon i {{ font-size: 14px; color: var(--text-muted); }}
.pt-section-header .pt-cat-label {{
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  flex: 1;
}}
.pt-section-header .pt-cat-arrow {{
  font-size: 10px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
  flex-shrink: 0;
}}
.pt-section.expanded .pt-cat-arrow {{ transform: rotate(90deg); }}
.pt-section-header .pt-cat-count {{
  font-size: 10px;
  color: var(--text-muted);
  background: var(--bg-root);
  padding: 2px 8px;
  border-radius: 10px;
  flex-shrink: 0;
}}

.pt-section-body {{
  display: none;
  padding: 0;
  background: var(--bg-elevated);
}}
.pt-section.expanded .pt-section-body {{ display: block; }}

.pt-question-item {{
  border-bottom: 1px solid rgba(60,60,60,0.3);
  transition: background 0.15s ease;
}}
.pt-question-item:last-child {{ border-bottom: none; }}

.pt-question-header {{
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 16px;
  cursor: pointer;
  user-select: none;
  transition: background 0.1s ease;
  width: 100%;
}}
.pt-question-header:hover {{ background: rgba(255,255,255,0.02); }}

.pt-status-indicator {{
  width: 20px;
  height: 20px;
  min-width: 20px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  transition: all 0.2s ease;
  border: 1.5px solid var(--border);
  color: transparent;
  background: var(--bg-root);
  margin-top: 1px;
  flex-shrink: 0;
}}
.pt-question-item.answered .pt-status-indicator {{
  background: var(--success);
  border-color: var(--success);
  color: #fff;
  box-shadow: 0 0 6px rgba(106,153,85,0.3);
}}

.pt-question-text {{
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.55;
  flex: 1;
  transition: color 0.15s ease;
}}
.pt-question-item.answered .pt-question-text {{
  color: var(--text-muted);
}}

.pt-question-chevron {{
  font-size: 10px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
  flex-shrink: 0;
  margin-top: 3px;
}}
.pt-question-item.open .pt-question-chevron {{ transform: rotate(180deg); }}

.pt-answer-panel {{
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.25s ease;
  background: var(--bg-root);
}}
.pt-question-item.open .pt-answer-panel {{
  max-height: 220px;
}}

.pt-answer-wrap {{
  padding: 0 16px 12px 48px;
}}

.pt-answer-input {{
  width: 100%;
  min-height: 56px;
  max-height: 120px;
  background: var(--bg-surface);
  border: 1px solid var(--border-light);
  color: var(--text-primary);
  padding: 8px 12px;
  border-radius: 4px;
  font-size: 12px;
  outline: none;
  font-family: var(--font-mono);
  line-height: 1.5;
  resize: vertical;
  transition: border-color 0.15s ease;
}}
.pt-answer-input:focus {{ border-color: var(--accent); }}
.pt-answer-input::placeholder {{ color: var(--text-muted); font-style: italic; }}

.pt-progress-bar {{
  width: 80px;
  height: 5px;
  background: var(--bg-root);
  border-radius: 3px;
  overflow: hidden;
  flex-shrink: 0;
}}
.pt-progress-fill {{
  height: 100%;
  border-radius: 3px;
  transition: width 0.4s ease;
}}

.pt-add-form {{
  display: flex;
  gap: 6px;
  padding: 12px 16px;
  border-top: 1px solid var(--border-light);
  background: var(--bg-surface);
}}
.pt-add-form input {{
  flex: 1;
  background: var(--bg-root);
  border: 1px solid var(--border);
  color: var(--text-primary);
  padding: 6px 10px;
  border-radius: var(--radius);
  font-size: 12px;
  outline: none;
  font-family: var(--font-mono);
  height: 28px;
}}
.pt-add-form input:focus {{ border-color: var(--accent); }}
.pt-add-form button {{
  background: var(--accent);
  color: #fff;
  border: none;
  padding: 0 14px;
  border-radius: var(--radius);
  cursor: pointer;
  font-weight: 600;
  font-size: 12px;
  height: 28px;
  transition: var(--transition);
  display: flex;
  align-items: center;
  gap: 4px;
}}
.pt-add-form button:hover {{ background: var(--accent-hover); }}

/* ============================================
   Links List
   ============================================ */
.links-list {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  font-size: 12px;
}}
.link-del {{
  color: var(--text-muted);
  cursor: pointer;
  font-size: 14px;
  opacity: 0;
  transition: opacity 0.1s;
  display: flex;
}}

/* ============================================
   Vuln Cards
   ============================================ */
.vuln-card {{
  background: var(--bg-elevated);
  border: 1px solid var(--border-light);
  border-radius: var(--radius);
  margin-bottom: 6px;
  overflow: hidden;
  transition: border-color 0.15s;
}}
.vuln-card:hover {{ border-color: var(--border); }}
.vuln-header {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  cursor: pointer;
  user-select: none;
}}
.vuln-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
.sv-c {{ background: var(--p-critical); box-shadow: 0 0 8px var(--p-critical); }}
.sv-h {{ background: var(--p-high); box-shadow: 0 0 8px var(--p-high); }}
.sv-m {{ background: var(--p-medium); box-shadow: 0 0 8px var(--p-medium); }}
.sv-l {{ background: var(--p-low); box-shadow: 0 0 8px var(--p-low); }}
.vuln-name {{ flex: 1; font-size: 13px; font-weight: 600; }}
.vuln-count {{ font-size: 11px; color: var(--text-muted); background: var(--bg-root); padding: 2px 8px; border-radius: 8px; }}
.vuln-arrow {{ transition: transform 0.2s; color: var(--text-muted); font-size: 10px; }}
.vuln-card.expanded .vuln-arrow {{ transform: rotate(90deg); }}
.vuln-body {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease; background: var(--bg-root); }}
.vuln-card.expanded .vuln-body {{ max-height: 600px; }}
.vuln-body ul {{ list-style: none; padding: 12px 14px; columns: 3; column-gap: 16px; }}
.vuln-body li {{ padding: 3px 0; font-size: 12px; font-family: var(--font-mono); break-inside: avoid; }}
.vuln-body a {{ color: var(--p-info); text-decoration: none; }}
.vuln-body a:hover {{ text-decoration: underline; }}

/* ============================================
   IP Map
   ============================================ */
.ipr {{
  padding: 12px 14px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-light);
  border-radius: var(--radius);
  margin-bottom: 6px;
}}
.ia {{ font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--p-info); margin-bottom: 4px; display: flex; align-items: center; }}
.im2 {{ font-size: 11px; color: var(--text-muted); margin-bottom: 6px; }}
.ih a {{ font-size: 12px; color: var(--text-primary); text-decoration: none; margin-right: 10px; font-family: var(--font-mono); }}
.ih a:hover {{ color: var(--p-info); }}

/* ============================================
   Sidebar Tabs
   ============================================ */
.sidebar-tabs {{
  display: flex;
  flex-shrink: 0;
  border-bottom: 1px solid var(--border-light);
  background: var(--bg-sidebar);
}}
.sidebar-tab {{
  flex: 1;
  padding: 8px 4px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  cursor: pointer;
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-family: var(--font-ui);
  transition: var(--transition);
  border-bottom: 2px solid transparent;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
}}
.sidebar-tab:hover {{ color: var(--text-secondary); background: rgba(255,255,255,0.02); }}
.sidebar-tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.sidebar-tab i {{ font-size: 14px; }}
.sidebar-tab-content {{ display: none; flex: 1; overflow-y: auto; }}
.sidebar-tab-content.active {{ display: block; }}

/* Pre-Testing Questions in sidebar */
/* ============================================
   Questions Panel (full-screen accordion)
   ============================================ */
.questions-panel {{
  flex: 1;
  display: flex !important;
  flex-direction: column;
  overflow: hidden;
  min-height: 0;
  background: var(--bg-root);
}}
.questions-top-bar {{
  height: 40px;
  min-height: 40px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-light);
  display: flex;
  align-items: center;
  padding: 0 12px;
  gap: 12px;
  flex-shrink: 0;
}}
.questions-title {{
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}}
.questions-title i {{ font-size: 14px; color: var(--accent); }}
.questions-progress {{
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
}}
.q-progress-bar {{
  width: 100px;
  height: 4px;
  background: var(--bg-root);
  border-radius: 2px;
  overflow: hidden;
}}
.q-progress-fill {{
  height: 100%;
  border-radius: 2px;
  transition: width 0.4s ease;
}}
.q-progress-label {{
  font-size: 10px;
  font-weight: 600;
  min-width: 70px;
  text-align: right;
  font-family: var(--font-mono);
}}
.questions-body {{
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  min-height: 0;
  padding: 0;
}}
.q-section {{
  border-bottom: 1px solid var(--border-light);
}}
.q-section:last-child {{ border-bottom: none; }}
.q-section-header {{
  padding: 8px 14px;
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  background: var(--bg-surface);
  user-select: none;
  transition: background 0.12s ease;
  position: sticky;
  top: 0;
  z-index: 2;
}}
.q-section-header:hover {{ background: rgba(255,255,255,0.04); }}
.q-cat-icon i {{ font-size: 14px; color: var(--accent); opacity: 0.7; }}
.q-cat-label {{
  flex: 1;
  font-size: 11px;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}
.q-cat-count {{
  font-size: 10px;
  color: var(--text-muted);
  background: var(--bg-root);
  padding: 1px 8px;
  border-radius: 10px;
  font-family: var(--font-mono);
}}
.q-cat-arrow {{
  font-size: 10px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
}}
.q-section.expanded .q-cat-arrow {{ transform: rotate(90deg); }}
.q-section-body {{
  display: none;
  padding: 0;
  background: var(--bg-root);
}}
.q-section.expanded .q-section-body {{ display: block; }}

/* ── Question Item (accordion) ── */
.q-item {{
  border-bottom: 1px solid rgba(60,60,60,0.2);
  transition: background 0.12s ease;
}}
.q-item:last-child {{ border-bottom: none; }}
.q-item:hover {{ background: rgba(255,255,255,0.015); }}
.q-item.answered {{ background: rgba(106,153,85,0.04); }}
.q-item-header {{
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 14px;
  cursor: pointer;
  user-select: none;
  transition: background 0.08s ease;
}}
.q-item-header:hover {{ background: rgba(255,255,255,0.02); }}

/* Status dot — checkmark indicator */
.q-status-dot {{
  width: 18px;
  height: 18px;
  min-width: 18px;
  border-radius: 50%;
  border: 1.5px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  transition: all 0.2s ease;
  color: transparent;
  background: var(--bg-root);
  margin-top: 2px;
  flex-shrink: 0;
}}
.q-item.answered .q-status-dot {{
  background: var(--success);
  border-color: var(--success);
  color: #fff;
  box-shadow: 0 0 8px rgba(106,153,85,0.3);
}}

/* Question text — always readable, no strike-through */
.q-item-text {{
  font-size: 13px;
  color: var(--text-primary);
  line-height: 1.5;
  flex: 1;
  transition: color 0.15s ease;
}}
/* Subtle indicator for answered — slight opacity, not strike */
.q-item.answered .q-item-text {{ color: var(--text-primary); }}

/* Chevron for accordion expand */
.q-item-chevron {{
  font-size: 10px;
  color: var(--text-muted);
  transition: transform 0.2s ease;
  flex-shrink: 0;
  margin-top: 4px;
}}
.q-item.open .q-item-chevron {{ transform: rotate(180deg); }}

/* Answer area — smooth expand/collapse */
.q-answer-area {{
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.25s ease;
  background: var(--bg-root);
}}
.q-item.open .q-answer-area {{ max-height: 200px; }}
.q-answer-input {{
  width: 100%;
  min-height: 56px;
  max-height: 140px;
  background: var(--bg-surface);
  border: 1px solid var(--border-light);
  color: var(--text-primary);
  padding: 8px 12px;
  border-radius: var(--radius);
  font-size: 12px;
  outline: none;
  font-family: var(--font-mono);
  line-height: 1.5;
  resize: vertical;
  transition: border-color 0.15s ease;
  margin: 0 14px 10px 42px;
  width: calc(100% - 56px);
}}
.q-answer-input:focus {{ border-color: var(--accent); box-shadow: 0 0 0 1px rgba(0,122,204,0.15); }}
.q-answer-input::placeholder {{ color: var(--text-muted); font-style: italic; }}
.q-add-form {{
  display: flex;
  gap: 6px;
  padding: 8px 12px;
  border-top: 1px solid var(--border-light);
  background: var(--bg-elevated);
  flex-shrink: 0;
}}
.q-add-form input {{
  flex: 1;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  color: var(--text-primary);
  padding: 5px 10px;
  border-radius: var(--radius);
  font-size: 12px;
  outline: none;
  font-family: var(--font-mono);
  height: 26px;
}}
.q-add-form input:focus {{ border-color: var(--accent); }}

/* ============================================
   Editor Sidebar (same structure, refined)
   ============================================ */
.editor-sidebar {{
  width: 300px;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border-light);
  transition: width 0.2s ease;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}}
.sidebar-wrapper {{
  display: flex;
  position: relative;
  height: 100%;
  flex-shrink: 0;
}}
.sidebar-wrapper.collapsed .editor-sidebar {{ width: 0; border-right: none; }}
.sidebar-wrapper.collapsed .resize-handle {{ display: none; }}
.sidebar-toggle {{
  position: absolute;
  right: -14px;
  top: 50%;
  transform: translateY(-50%);
  width: 28px; height: 28px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  z-index: 10;
  color: var(--text-muted);
  font-size: 12px;
  transition: all 0.2s;
  box-shadow: 0 2px 8px rgba(0,0,0,0.35);
}}
.sidebar-toggle:hover {{ color: var(--accent); border-color: var(--accent); }}
.sidebar-wrapper.collapsed .sidebar-toggle {{ right: -36px; }}
.resize-handle {{
  width: 4px;
  cursor: col-resize;
  background: transparent;
  position: absolute;
  right: 0;
  top: 0;
  bottom: 0;
  z-index: 5;
  transition: background 0.2s;
}}
.resize-handle:hover, .resize-handle.active {{ background: var(--accent); }}

.sidebar-content {{ flex: 1; overflow-y: auto; padding: 0; }}

/* ============================================
   VS Code–style Notes Tree
   ============================================ */
.tree-section {{ border-bottom: 1px solid var(--border-light); }}
.tree-section summary {{
  list-style: none;
  cursor: pointer;
  padding: 8px 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  font-size: 10px;
  letter-spacing: 0.5px;
  user-select: none;
  transition: background 0.1s;
}}
.tree-section summary:hover {{ background: rgba(255,255,255,0.03); color: var(--text-primary); }}
.tree-section summary::-webkit-details-marker {{ display: none; }}
.tree-section summary::after {{
  content: '';
  display: inline-block;
  width: 12px; height: 12px;
  background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%236a6a6a'%3E%3Cpath d='M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6z'/%3E%3C/svg%3E") no-repeat center;
  background-size: contain;
  transition: transform 0.15s;
}}
.tree-section[open] summary::after {{ transform: rotate(90deg); }}
.tree-section .sb-content {{ padding: 4px 0 8px 0; }}

/* Tree items — VS Code Explorer style */
.tree-item {{
  display: flex;
  align-items: center;
  padding: 0 8px 0 0;
  height: 22px;
  cursor: pointer;
  font-size: 13px;
  transition: background 0.08s;
  user-select: none;
  position: relative;
  white-space: nowrap;
}}
.tree-item:hover {{ background: rgba(255,255,255,0.04); }}
.tree-item.active {{ background: var(--accent-subtle); color: var(--accent); }}
.tree-item.tree-root-folder {{
  font-weight: 700;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.6px;
  color: var(--text-muted);
  height: 22px;
  cursor: default;
}}
.tree-item.tree-root-folder:hover {{ background: transparent; }}
.tree-item.tree-root-folder .item-icon {{ opacity: 0.7; }}
.tree-item .twistie {{
  width: 16px; height: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  color: var(--text-muted);
  flex-shrink: 0;
  transition: transform 0.1s;
}}
.tree-item .twistie.open {{ transform: rotate(90deg); }}
.tree-item .twistie.hidden {{ visibility: hidden; }}
.tree-item .item-icon {{
  width: 16px; height: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 3px;
  font-size: 14px;
  flex-shrink: 0;
}}
.tree-item .item-icon.folder {{ color: var(--warning); }}
.tree-item .item-icon.note {{ color: var(--text-muted); }}
.tree-item .item-label {{ flex: 1; overflow: hidden; text-overflow: ellipsis; }}
.tree-item .item-actions {{ display: none; gap: 1px; margin-left: 2px; }}
.tree-item:hover .item-actions {{ display: flex; }}
.tree-item .item-act {{
  width: 18px; height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  color: var(--text-muted);
  font-size: 12px;
  border-radius: 2px;
  transition: var(--transition);
  border: none;
  background: none;
}}
.tree-item .item-act:hover {{ background: var(--bg-surface); color: var(--text-primary); }}
.tree-item .item-act.danger:hover {{ color: var(--danger); }}

.tree-children {{ display: none; }}
.tree-children.open {{ display: block; }}

/* Depth indentation — VS Code style */
.tree-item[data-depth="0"] {{ padding-left: 8px; }}
.tree-item[data-depth="1"] {{ padding-left: 20px; }}
.tree-item[data-depth="2"] {{ padding-left: 36px; }}
.tree-item[data-depth="3"] {{ padding-left: 52px; }}
.tree-item[data-depth="4"] {{ padding-left: 68px; }}

.tree-rename-input {{
  background: var(--bg-root);
  border: 1px solid var(--accent);
  color: var(--text-primary);
  font-size: 13px;
  padding: 1px 4px;
  border-radius: 2px;
  outline: none;
  font-family: var(--font-ui);
  width: calc(100% - 40px);
}}

/* Context Menu */
.ctx-menu {{
  position: fixed;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 4px;
  min-width: 180px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  z-index: 3000;
  display: none;
  animation: fadeIn 0.1s;
}}
.ctx-menu.open {{ display: block; }}
.ctx-item {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  font-size: 12px;
  color: var(--text-secondary);
  border-radius: 4px;
  cursor: pointer;
  transition: background 0.1s;
  border: none;
  background: none;
  width: 100%;
  font-family: var(--font-ui);
}}
.ctx-item:hover {{ background: var(--accent-subtle); color: var(--text-primary); }}
.ctx-item i {{ font-size: 14px; width: 16px; text-align: center; flex-shrink: 0; }}
.ctx-item.danger:hover {{ background: var(--danger-subtle); color: var(--danger); }}
.ctx-sep {{ height: 1px; background: var(--border-light); margin: 4px 0; }}

/* ============================================
   Target Intelligence Data Rows
   ============================================ */
.data-row {{
  padding: 5px 14px;
  font-size: 11px;
  display: flex;
  justify-content: space-between;
  gap: 12px;
  border-bottom: 1px solid var(--border-light);
}}
.data-row:last-child {{ border-bottom: none; }}
.data-lbl {{ color: var(--text-muted); font-weight: 500; }}
.data-val {{ color: var(--text-primary); font-family: var(--font-mono); text-align: right; word-break: break-all; max-width: 60%; }}
.data-val a {{ color: var(--p-info); text-decoration: none; }}
.data-val.list {{ display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; }}
.mini-tag {{
  font-size: 9px; padding: 2px 6px;
  background: var(--bg-root); border-radius: 3px;
  color: var(--text-secondary); border: 1px solid var(--border-light);
}}

/* ============================================
   Editor Main Area
   ============================================ */
.editor-main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-root); }}
.editor-note-panel {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }}
.editor-questions-panel {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-root); min-height: 0; }}
.editor-toolbar {{
  height: 36px;
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-light);
  display: flex;
  align-items: center;
  padding: 0 8px;
  gap: 2px;
  flex-shrink: 0;
}}
.md-btn {{
  width: 28px; height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 3px;
  background: transparent;
  border: none;
  color: var(--text-secondary);
  transition: var(--transition);
  font-size: 13px;
  cursor: pointer;
  font-family: var(--font-mono);
  font-weight: 600;
}}
.md-btn:hover {{ background: var(--bg-surface); color: var(--text-primary); }}
.editor-title {{
  margin-left: auto;
  font-size: 12px;
  color: var(--text-secondary);
  font-family: var(--font-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}

.editor-mode-tabs {{
  display: flex;
  background: var(--bg-elevated);
  flex-shrink: 0;
  border-bottom: 1px solid var(--border-light);
}}
.mode-tab {{
  padding: 6px 16px;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-family: var(--font-ui);
  transition: var(--transition);
  border-bottom: 1px solid transparent;
}}
.mode-tab:hover {{ color: var(--text-secondary); }}
.mode-tab.active {{ color: var(--text-primary); border-bottom-color: var(--accent); }}

/* CodeMirror */
.editor-content {{ flex: 1; overflow: hidden; position: relative; }}
.CodeMirror {{
  height: 100% !important;
  font-family: var(--font-mono) !important;
  font-size: 13px !important;
  line-height: 1.6 !important;
  background: var(--bg-root) !important;
  color: var(--text-primary) !important;
}}
.CodeMirror-gutters {{ background: var(--bg-root) !important; border-right: 1px solid var(--border-light) !important; }}
.CodeMirror-linenumber {{ color: var(--text-muted) !important; font-size: 11px !important; }}
.CodeMirror-cursor {{ border-left: 1px solid var(--text-secondary) !important; }}
.CodeMirror-selected {{ background: rgba(38,79,120,0.4) !important; }}
.CodeMirror-activeline-background {{ background: rgba(255,255,255,0.03) !important; }}
/* Markdown tokens */
.cm-header {{ color: #569cd6 !important; font-weight: 700; }}
.cm-strong {{ color: #d7ba7d !important; }}
.cm-em {{ color: #c586c0 !important; }}
.cm-link {{ color: #4ec9b0 !important; }}
.cm-url {{ color: #6a9955 !important; }}
.cm-quote {{ color: #608b4e !important; font-style: italic; }}
.cm-strikethrough {{ text-decoration: line-through; }}
/* Code block / inline code — base green, overridden by nested modes inside fences */
.cm-comment {{ color: #6a9955 !important; }}
/* VS Code Dark+ — nested language tokens inside fenced code blocks */
.cm-keyword {{ color: #c586c0 !important; }}
.cm-atom {{ color: #569cd6 !important; }}
.cm-number {{ color: #b5cea8 !important; }}
.cm-def {{ color: #dcdcaa !important; }}
.cm-variable {{ color: #9cdcfe !important; }}
.cm-variable-2 {{ color: #9cdcfe !important; }}
.cm-variable-3, .cm-type {{ color: #4ec9b0 !important; }}
.cm-property {{ color: #9cdcfe !important; }}
.cm-operator {{ color: #d4d4d4 !important; }}
.cm-string {{ color: #ce9178 !important; }}
.cm-string-2 {{ color: #ce9178 !important; }}
.cm-meta {{ color: #569cd6 !important; }}
.cm-builtin {{ color: #4ec9b0 !important; }}
.cm-qualifier {{ color: #d7ba7d !important; }}
.cm-bracket {{ color: #808080 !important; }}
.cm-tag {{ color: #569cd6 !important; }}
.cm-attribute {{ color: #9cdcfe !important; }}
.cm-error {{ color: #f44747 !important; }}
.cm-negative {{ color: #d7ba7d !important; }}
.cm-positive {{ color: #6a9955 !important; }}
.cm-invalidchar {{ color: #f44747 !important; }}

/* Preview Pane */
.preview-pane {{
  position: absolute;
  inset: 0;
  background: var(--bg-root);
  padding: 24px 32px;
  overflow-y: auto;
  font-size: 14px;
  line-height: 1.7;
  color: var(--text-primary);
  display: none;
}}
.preview-pane.active {{ display: block; }}
.preview-pane h1 {{ font-size: 2em; margin: 0 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
.preview-pane h2 {{ font-size: 1.5em; margin: 20px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border-light); }}
.preview-pane h3 {{ font-size: 1.2em; margin: 16px 0 8px; }}
.preview-pane h4 {{ font-size: 1.1em; margin: 14px 0 6px; color: var(--text-secondary); }}
.preview-pane p {{ margin-bottom: 12px; }}
.preview-pane code {{
  background: var(--bg-surface);
  padding: 2px 6px;
  border-radius: 3px;
  font-family: var(--font-mono);
  font-size: 13px;
  color: #ce9178;
}}
.preview-pane pre {{
  background: var(--bg-surface);
  padding: 14px 16px;
  border-radius: var(--radius);
  overflow-x: auto;
  border: 1px solid var(--border-light);
  margin: 12px 0;
}}
.preview-pane pre code {{ background: none; border: none; padding: 0; color: var(--text-primary); }}
.preview-pane blockquote {{
  border-left: 3px solid var(--accent);
  margin: 12px 0;
  padding: 8px 16px;
  background: var(--accent-subtle);
  color: var(--text-secondary);
  border-radius: 0 var(--radius) var(--radius) 0;
}}
.preview-pane a {{ color: var(--p-info); }}
.preview-pane ul, .preview-pane ol {{ margin: 8px 0; padding-left: 24px; }}
.preview-pane li {{ margin-bottom: 4px; }}
.preview-pane hr {{ border: none; border-top: 1px solid var(--border); margin: 20px 0; }}
.preview-pane table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
.preview-pane th, .preview-pane td {{ border: 1px solid var(--border); padding: 8px 12px; text-align: left; }}
.preview-pane th {{ background: var(--bg-surface); font-weight: 600; }}

/* Status Bar */
.status-bar {{
  height: 22px;
  background: var(--bg-elevated);
  border-top: 1px solid var(--border-light);
  font-size: 11px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  color: var(--text-muted);
  flex-shrink: 0;
}}

/* Modals */
.mod-bg {{
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}}
.mod-bg.open {{ display: flex; animation: fadeIn 0.15s; }}
.mod {{
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 20px;
  width: 400px;
  max-width: 90vw;
  box-shadow: 0 2px 16px rgba(0,0,0,0.4);
}}
.mod h3 {{ font-size: 14px; margin-bottom: 10px; color: var(--text-primary); }}
.mod p {{ font-size: 13px; color: var(--text-secondary); margin-bottom: 16px; line-height: 1.5; }}
.mod input {{
  width: 100%;
  background: var(--bg-root);
  border: 1px solid var(--border);
  color: var(--text-primary);
  padding: 8px 10px;
  border-radius: var(--radius);
  font-size: 13px;
  margin-bottom: 10px;
  outline: none;
  font-family: inherit;
}}
.mod input:focus {{ border-color: var(--accent); }}
.mod-acts {{ display: flex; gap: 8px; justify-content: flex-end; }}

/* Toast */
.toast {{
  position: fixed;
  bottom: 16px;
  right: 16px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  color: var(--text-primary);
  padding: 8px 16px;
  border-radius: var(--radius);
  font-size: 12px;
  opacity: 0;
  transform: translateY(10px);
  transition: var(--transition);
  pointer-events: none;
  z-index: 2000;
  box-shadow: 0 2px 12px rgba(0,0,0,0.35);
  display: flex;
  align-items: center;
  gap: 6px;
}}
.toast.show {{ opacity: 1; transform: translateY(0); }}

/* Empty States */
.empty {{ text-align: center; padding: 48px; color: var(--text-muted); font-size: 13px; }}
.empty i {{ font-size: 36px; margin-bottom: 12px; display: block; opacity: 0.4; }}
.empty-notes {{ padding: 8px 14px; color: var(--text-muted); font-size: 11px; font-style: italic; }}

/* View container */
.view-container {{ padding: 20px 24px; height: 100%; overflow-y: auto; }}
.section-title {{
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 8px;
}}
.section-title i {{ font-size: 18px; color: var(--accent); }}
</style>
</head>
<body>

<!-- ===== TOP BAR ===== -->
<header class="top-bar">
 <div class="brand">
  <img src="https://avatars.githubusercontent.com/u/212823433?s=400&u=cf6999ae50fc524333b6a06c13c15809017e1281&v=4" alt="KeenDash Logo" style="width:56px;height:56px;border-radius:9px;object-fit:cover;">
  KeenDash
 </div>
 <nav class="nav-tabs" id="nav-tabs"></nav>
 <div class="nav-actions">
  <div class="save-status" id="save-status" title="target.json is saved next to this HTML file"><span class="status-dot gray"></span><span id="save-status-label">Not linked</span></div>
  <button class="btn-action" id="save-json-btn" onclick="handleSaveClick()" title="Link and autosave target.json">
   <i class="ph ph-floppy-disk"></i>
   <span id="save-btn-label">Link target.json</span>
  </button>
  <button class="btn-action primary" onclick="openAddModal()" title="Add Target">
   <i class="ph ph-plus"></i>
   Add Target
  </button>
 </div>
</header>

<main class="viewport" id="viewport"></main>

<!-- ===== MODALS ===== -->
<div id="addModal" class="mod-bg">
 <div class="mod">
  <h3><i class="ph ph-plus-circle" style="margin-right:8px"></i>Add Custom Target</h3>
  <input id="newHost" placeholder="subdomain.example.com">
  <input id="newUrl" placeholder="https://... (optional)">
  <div class="mod-acts">
   <button class="btn-action" onclick="closeModal('addModal')">Cancel</button>
   <button class="btn-action primary" onclick="addCustomSubdomain()">Add to Testing</button>
  </div>
 </div>
</div>

<div id="confirmModal" class="mod-bg">
 <div class="mod">
  <h3 id="confirmTitle">Confirm</h3>
  <p id="confirmMsg">Are you sure?</p>
  <div class="mod-acts">
   <button class="btn-action" onclick="closeModal('confirmModal')">Cancel</button>
   <button class="btn-action" style="background:var(--danger);color:#fff;border-color:var(--danger)" id="confirmBtn">Delete</button>
  </div>
 </div>
</div>

<div id="toast" class="toast"></div>

<script id="initial-targets" type="application/json">{targets_b64}</script>
<script id="app-state" type="application/json">{state_json}</script>

<script>
// ========== STATE ==========
const OUT_HTML_NAME = '{out_html_name}';
const rawTargets = JSON.parse(atob(document.getElementById('initial-targets').textContent));
let T = rawTargets.slice();
let M = Object.fromEntries(T.map(t => [t.host, t]));

let hiddenHosts = [];   // soft-hidden hosts: removed from Targets view, recoverable in the "Hidden" list
let purgedHosts = [];   // permanently deleted hosts: fully removed from data, not recoverable
let showHiddenOnly = false;
let testingHosts = [];
let selectedTestingHost = null;

// Notes: tree structure with folders and files
let notes = {{}};
let activeNote = {{}};
let openFolders = {{}};
let checklistState = {{}};
let customSteps = {{}};
let hiddenSteps = {{}};
let pretestingAnswers = {{}};
let ptOpenSections = {{}};
let openQuestions = {{}};  // tracks which single question is open per host
let cmInstances = {{}};
let sidebarWidths = {{}};
let sidebarCollapsed = {{}};
let sidebarActiveTab = {{}};
let testingSidebarCollapsed = false;
let generalNotesContent = '';

const GENERAL_NOTES_TEMPLATE = `# General Notes

## Scope
-

## Rules of Engagement
-

## Testing Approach
-

## Key Findings
-

## Notes
-`;

// ========== PRE-TESTING STEP GENERATOR (client-side mirror of Python) ==========
function generatePretestingSteps(host, techs, status) {{
  let h = (host||'').toLowerCase();
  let techStr = (techs||[]).join(' ').toLowerCase();
  let steps = [];

  // Universal categories
  steps.push('recon|Infrastructure|What ports are open and what services run on each?');
  steps.push('recon|Infrastructure|Is it cloud-hosted (AWS/GCP/Azure) or on-prem? Any cloud metadata endpoint reachable?');
  steps.push('recon|Infrastructure|Is there a WAF or reverse proxy in front? (Cloudflare, Akamai, Fastly, AWS WAF)');
  steps.push('recon|Infrastructure|What server software is running? (Nginx, Apache, IIS, Tomcat, custom)');
  steps.push('recon|Infrastructure|What OS and kernel version? Any known CVEs for this stack?');
  steps.push('recon|Infrastructure|Does it host multiple apps (vhosting)? Any shared infrastructure with other subdomains?');
  steps.push('recon|Infrastructure|Are there non-HTTP services on open ports? (SSH, RDP, DB, Redis, MongoDB)');
  steps.push('recon|Infrastructure|What are all resolved IPs? Any unusual DNS records (TXT, MX, SPF, DMARC)?');

  steps.push('stack|Tech Stack|What languages and frameworks power this app? (PHP, Node.js, Python, Java, .NET, Go, Ruby)');
  steps.push('stack|Tech Stack|What CMS or platform? (WordPress, Drupal, Joomla, Laravel, Django, Spring)');
  steps.push('stack|Tech Stack|What third-party libraries or packages? Any known CVEs for their versions?');
  steps.push('stack|Tech Stack|Are there custom JavaScript libraries? Any client-side framework? (React, Angular, Vue)');
  steps.push('stack|Tech Stack|What database backend? (MySQL, PostgreSQL, MongoDB, Redis, Oracle)');
  steps.push('stack|Tech Stack|Is source code publicly available? (GitHub, GitLab, open-source repo)');

  steps.push('surface|Attack Surface|What is the primary function of this subdomain? (API, admin portal, marketing, internal tool)');
  steps.push('surface|Attack Surface|Is it production, staging, dev, or QA? Any debug panels or test data exposed?');
  steps.push('surface|Attack Surface|What are all accessible endpoints? (robots.txt, sitemap.xml, .env, .git, swagger, GraphQL)');
  steps.push('surface|Attack Surface|Are there file upload features? What types accepted and where stored?');
  steps.push('surface|Attack Surface|Are there API endpoints? REST or GraphQL? Any introspection or documentation exposed?');
  steps.push('surface|Attack Surface|Are WebSockets used? Any Server-Sent Events or long-polling endpoints?');
  steps.push('surface|Attack Surface|What HTTP methods allowed? (GET, POST, PUT, DELETE, PATCH, OPTIONS)');
  steps.push('surface|Attack Surface|Does this subdomain interact with other internal services? (SSRF potential)');

  steps.push('auth|Auth & Session & Session|Is there authentication? What type? (Form, OAuth SSO, SAML, JWT, API key, mTLS)');
  steps.push('auth|Auth & Session & Session|How is session established and maintained? (Cookie, JWT, token in header, session ID)');
  steps.push('auth|Auth & Session & Session|What user roles exist? (admin, user, viewer, API, service account)');
  steps.push('auth|Auth & Session & Session|How are users identified in requests? (user_id param, JWT claim, cookie, header)');
  steps.push('auth|Auth & Session & Session|Is there 2FA or MFA? Can it be bypassed or enumerated?');
  steps.push('auth|Auth & Session & Session|Is there rate limiting on login, password reset, or registration?');
  steps.push('auth|Auth & Session & Session|Is there a password reset or account recovery flow? How does it work?');
  steps.push('auth|Auth & Session & Session|Are there default or weak credentials? (admin:admin, test:test)');

  steps.push('security|Security Headers|Is there a Content Security Policy? What directives? Any weaknesses?');
  steps.push('security|Security Headers|Is CORS configured? What origins, methods, and credentials are allowed?');
  steps.push('security|Security Headers|Are security headers present? (X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy)');
  steps.push('security|Security Headers|Is there a CAPTCHA or anti-bot mechanism? Can it be bypassed?');
  steps.push('security|Security Headers|How does the app handle special characters and encoding? (UTF-8, URL-encode, double-encode)');
  steps.push('security|Security Headers|Can you trigger error messages? What info is leaked? (stack traces, DB errors, paths)');
  steps.push('security|Security Headers|Is input validation client-side only, server-side, or both?');
  steps.push('security|Security Headers|Are there any interesting HTTP headers? (X-Powered-By, Server, custom auth headers)');

  steps.push('logic|Business Logic|What data does this subdomain handle? (PII, financial, credentials, internal docs)');
  steps.push('logic|Business Logic|What CRUD operations are available? Which are most sensitive?');
  steps.push('logic|Business Logic|Are there multi-step workflows? (registration, checkout, approval chain, password reset)');
  steps.push('logic|Business Logic|Are there time-sensitive operations? (token expiry, session timeout, race conditions)');
  steps.push('logic|Business Logic|Is there a payment or billing flow? Can amounts, currencies, or quantities be manipulated?');
  steps.push('logic|Business Logic|Are there import or export features? What formats? (CSV, XML, JSON, YAML)');
  steps.push('logic|Business Logic|Are there notification features? (email, SMS, webhook) Any injection points?');

  // Tech-specific
  if (['wordpress','wp-content'].some(k => techStr.includes(k))) {{
    steps.push('tech-wp|WordPress|Is XML-RPC enabled? Can it be used for brute force or SSRF?');
    steps.push('tech-wp|WordPress|Are there user enumeration vectors? (/author/, /wp-json/wp/v2/users)');
    steps.push('tech-wp|WordPress|What plugins are installed? Any known vulnerabilities?');
    steps.push('tech-wp|WordPress|Is the wp-config.php or .htaccess accessible?');
  }}
  if (['api','graphql','rest'].some(k => h.includes(k)) || techStr.includes('graphql')) {{
    steps.push('tech-api|API|Is there API documentation or Swagger/OpenAPI spec exposed?');
    steps.push('tech-api|API|Are there rate limits on API endpoints? Can they be bypassed?');
    steps.push('tech-api|API|For GraphQL: is introspection enabled? What mutations are available?');
    steps.push('tech-api|API|Are there BOLA or IDOR vectors? (object IDs in URL, body, or headers)');
    steps.push('tech-api|API|Is mass assignment possible? (sending extra fields in PUT/POST)');
  }}
  if (['vpn','gateway','sslvpn'].some(k => h.includes(k))) {{
    steps.push('tech-vpn|VPN|What VPN product and version? Any known CVEs?');
    steps.push('tech-vpn|VPN|Are there default credentials?');
    steps.push('tech-vpn|VPN|Is the portal accessible without authentication?');
  }}
  if (['jenkins','gitlab','ci','cd','harbor'].some(k => h.includes(k))) {{
    steps.push('tech-cicd|CI/CD|Is the dashboard accessible without authentication?');
    steps.push('tech-cicd|CI/CD|Are there script console or build-execution features?');
    steps.push('tech-cicd|CI/CD|Are API tokens or credentials stored in plain text?');
  }}
  if (['grafana','zabbix','kibana','prometheus','monitor'].some(k => h.includes(k))) {{
    steps.push('tech-mon|Monitoring|Are default credentials active? (admin:admin, admin:grafana)');
    steps.push('tech-mon|Monitoring|Is there unauthenticated data source access?');
    steps.push('tech-mon|Monitoring|Are there known path traversal or SSRF CVEs for this version?');
  }}
  if (['s3','bucket','cloudfront'].some(k => h.includes(k)) || techStr.includes('s3')) {{
    steps.push('tech-cloud|Cloud|Is the storage bucket publicly readable or writable?');
    steps.push('tech-cloud|Cloud|Can cloud metadata be accessed via SSRF?');
    steps.push('tech-cloud|Cloud|Are there dangling DNS records pointing to deleted cloud resources?');
  }}

  // Status-specific
  if (status === 401) {{
    steps.push('status-401|401 Auth|What authentication scheme? (Basic, Digest, Bearer, NTLM)');
    steps.push('status-401|401 Auth|Can default credentials authenticate?');
    steps.push('status-401|401 Auth|Can 401 be bypassed via headers? (X-Forwarded-For, X-Original-URL)');
  }}
  if (status === 403) {{
    steps.push('status-403|403 Forbidden|Can 403 be bypassed? (HTTP method change, path traversal, headers)');
    steps.push('status-403|403 Forbidden|Does X-Original-URL or X-Rewrite-URL bypass the restriction?');
    steps.push('status-403|403 Forbidden|Can double-encoding or path normalization tricks bypass?');
  }}
  if (status === 200) {{
    steps.push('status-200|Active 200|What hidden endpoints exist? (robots.txt, sitemap, .env, .git, .svn)');
    steps.push('status-200|Active 200|Are there admin panels or management interfaces accessible?');
    steps.push('status-200|Active 200|What parameters does each endpoint accept? Any reflected input?');
  }}

  return steps;
}}

let activeView = 'targets';
let openEditorTabs = [];

// ========== NOTES TREE HELPERS ==========
// Each note is independent — like a separate .md file.
// Base structure: "Notes" root folder with one default note inside.

let suppressEditorSync = false;  // prevents cm change event from overwriting during init

function addNoteItem(host, title, content, type, parentId) {{
  let id = 'n' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
  notes[host] = notes[host] || [];
  notes[host].push({{ id, title, content: content || '', type, parentId, ts: Date.now() }});
  return id;
}}

function getNoteChildren(host, parentId) {{
  return (notes[host] || []).filter(n => n.parentId === parentId);
}}

function getNoteById(host, nid) {{
  return (notes[host] || []).find(n => n.id === nid);
}}

function findRootFolder(host) {{
  return (notes[host] || []).find(n => n.type === 'folder' && n.parentId === null);
}}

function ensureDefaultRoot(host) {{
  if (!notes[host] || notes[host].length === 0) {{
    notes[host] = [];
    // Create root "Notes" folder
    let rootId = addNoteItem(host, 'Notes', '', 'folder', null);
    // Create one default note inside it
    addNoteItem(host, 'note', '', 'file', rootId);
    // Create "General Notes" folder with shared base template
    let genFolderId = addNoteItem(host, 'General Notes', '', 'folder', null);
    addNoteItem(host, 'general', generalNotesContent || GENERAL_NOTES_TEMPLATE, 'file', genFolderId);
    openFolders[host] = [rootId, genFolderId];
  }} else {{
    // Migration: if root items exist but none is a folder, wrap them in a "Notes" folder
    let rootItems = getNoteChildren(host, null);
    if (rootItems.length > 0 && !rootItems.some(n => n.type === 'folder')) {{
      let rootId = addNoteItem(host, 'Notes', '', 'folder', null);
      for (let item of rootItems) {{
        item.parentId = rootId;
      }}
    }}
    // Ensure "General Notes" folder exists
    let hasGeneral = (notes[host] || []).some(n => n.type === 'folder' && n.title === 'General Notes');
    if (!hasGeneral) {{
      let genFolderId = addNoteItem(host, 'General Notes', '', 'folder', null);
      addNoteItem(host, 'general', generalNotesContent || GENERAL_NOTES_TEMPLATE, 'file', genFolderId);
      // Open the General Notes folder by default
      let open = openFolders[host] || [];
      if (!open.includes(genFolderId)) {{ open.push(genFolderId); openFolders[host] = open; }}
    }}
  }}
}}

function renderNotesTree(host) {{
  ensureDefaultRoot(host);
  const container = document.getElementById('notes-tree-' + host);
  if (!container) return;
  const root = findRootFolder(host);
  if (!root) return;

  // Render ALL root-level items: "Notes" folder + any additional root folders
  const rootItems = getNoteChildren(host, null);
  let html = '';

  for (const item of rootItems) {{
    if (item.id === root.id) {{
      // Default "Notes" folder — rendered with special root style (always open, no twistie)
      html += renderRootFolder(host, item);
    }} else if (item.type === 'folder') {{
      // Additional root folders — rendered with normal twistie
      const isOpen = (openFolders[host] || []).includes(item.id);
      html += renderFolderTree(host, item, 0);
    }}
  }}

  container.innerHTML = html;
}}

function renderRootFolder(host, folder) {{
  const childFolders = getNoteChildren(host, folder.id).filter(n => n.type === 'folder');
  const childFiles = getNoteChildren(host, folder.id).filter(n => n.type === 'file');

  let html = '';
  // Root folder header — no twistie, always open, VS Code section style
  html += '<div class="tree-item tree-root-folder" data-id="' + folder.id + '" data-host="' + host + '" data-depth="0" data-type="folder">';
  html += '<span class="twistie hidden"></span>';  // spacer
  html += '<span class="item-icon folder"><i class="ph ph-folder"></i></span>';
  html += '<span class="item-label">' + escHtml(folder.title) + '</span>';
  html += '<div class="item-actions">';
  html += '<button class="item-act" data-action="add-file" data-host="' + host + '" data-nid="' + folder.id + '" title="New Note"><i class="ph ph-plus"></i></button>';
  html += '<button class="item-act" data-action="add-subfolder" data-host="' + host + '" data-nid="' + folder.id + '" title="New Subfolder"><i class="ph ph-folder-plus"></i></button>';
  html += '<button class="item-act" data-action="add-root-folder" data-host="' + host + '" title="New Root Folder"><i class="ph ph-folders"></i></button>';
  html += '</div></div>';

  // Children — always visible (root is never collapsed)
  if (childFiles.length > 0 || childFolders.length > 0) {{
    html += '<div class="tree-children open">';
    for (const file of childFiles) html += renderFileItem(host, file, 1);
    for (const subfolder of childFolders) html += renderFolderTree(host, subfolder, 1);
    html += '</div>';
  }} else {{
    html += '<div class="empty-notes">No notes yet</div>';
  }}

  return html;
}}

function renderFolderTree(host, folder, depth) {{
  const isOpen = (openFolders[host] || []).includes(folder.id);
  const isActive = activeNote[host] === folder.id;
  const childFolders = getNoteChildren(host, folder.id).filter(n => n.type === 'folder');
  const childFiles = getNoteChildren(host, folder.id).filter(n => n.type === 'file');
  const allChildren = [...childFolders, ...childFiles];

  let html = '';

  // Folder row
  html += '<div class="tree-item' + (isActive ? ' active' : '') + '" data-id="' + folder.id + '" data-host="' + host + '" data-depth="' + depth + '" data-type="folder">';

  // Twistie
  html += '<span class="twistie' + (isOpen ? ' open' : '') + '" data-action="toggle-folder" data-host="' + host + '" data-nid="' + folder.id + '"><i class="ph ph-caret-right"></i></span>';

  // Icon
  html += '<span class="item-icon folder"><i class="ph ' + (isOpen ? 'ph-folder-open' : 'ph-folder') + '"></i></span>';

  // Label
  html += '<span class="item-label">' + escHtml(folder.title) + '</span>';

  // Actions (only rename + delete for root folder)
  html += '<div class="item-actions">';
  html += '<button class="item-act" data-action="add-file" data-host="' + host + '" data-nid="' + folder.id + '" title="New Note"><i class="ph ph-plus"></i></button>';
  html += '<button class="item-act" data-action="add-subfolder" data-host="' + host + '" data-nid="' + folder.id + '" title="New Folder"><i class="ph ph-folder-plus"></i></button>';
  if (folder.parentId !== null) {{
    html += '<button class="item-act" data-action="rename-item" data-host="' + host + '" data-nid="' + folder.id + '" title="Rename"><i class="ph ph-pencil-simple"></i></button>';
    html += '<button class="item-act danger" data-action="delete-item" data-host="' + host + '" data-nid="' + folder.id + '" title="Delete"><i class="ph ph-trash"></i></button>';
  }}
  html += '</div></div>';

  // Children container
  if (allChildren.length > 0) {{
    html += '<div class="tree-children' + (isOpen ? ' open' : '') + '" id="children-' + folder.id + '">';
    // Render child files
    for (const file of childFiles) {{
      html += renderFileItem(host, file, depth + 1);
    }}
    // Render child folders recursively
    for (const subfolder of childFolders) {{
      html += renderFolderTree(host, subfolder, depth + 1);
    }}
    html += '</div>';
  }}

  return html;
}}

function renderFileItem(host, file, depth) {{
  const isActive = activeNote[host] === file.id;
  let html = '';
  html += '<div class="tree-item' + (isActive ? ' active' : '') + '" data-id="' + file.id + '" data-host="' + host + '" data-depth="' + depth + '" data-type="file">';

  // Spacer for alignment (no twistie for files)
  html += '<span class="twistie hidden"></span>';

  // Icon
  html += '<span class="item-icon note"><i class="ph ph-file-text"></i></span>';

  // Label
  html += '<span class="item-label">' + escHtml(file.title) + '</span>';

  // Actions (only rename + delete)
  html += '<div class="item-actions">';
  html += '<button class="item-act" data-action="rename-item" data-host="' + host + '" data-nid="' + file.id + '" title="Rename"><i class="ph ph-pencil-simple"></i></button>';
  html += '<button class="item-act danger" data-action="delete-item" data-host="' + host + '" data-nid="' + file.id + '" title="Delete"><i class="ph ph-trash"></i></button>';
  html += '</div></div>';

  return html;
}}

function toggleFolder(host, fid) {{
  let open = openFolders[host] || [];
  const idx = open.indexOf(fid);
  if (idx >= 0) open.splice(idx, 1); else open.push(fid);
  openFolders[host] = open;
  saveState();
  renderNotesTree(host);
}}

function addFileInFolder(host, folderId) {{
  const id = addNoteItem(host, 'untitled', '', 'file', folderId);
  let open = openFolders[host] || [];
  if (!open.includes(folderId)) {{ open.push(folderId); openFolders[host] = open; }}
  saveState();
  renderNotesTree(host);
  // Select the new note and auto-rename
  activeNote[host] = id;
  saveState();
  loadNoteIntoEditor(host, id);
  setTimeout(() => startRename(host, id), 100);
}}

function addSubFolder(host, folderId) {{
  const id = addNoteItem(host, 'New Folder', '', 'folder', folderId);
  let open = openFolders[host] || [];
  if (!open.includes(folderId)) {{ open.push(folderId); openFolders[host] = open; }}
  saveState();
  renderNotesTree(host);
  setTimeout(() => startRename(host, id), 50);
}}

function addRootFolder(host) {{
  ensureDefaultRoot(host);
  const id = addNoteItem(host, 'New Folder', '', 'folder', null);
  saveState();
  renderNotesTree(host);
  // Open the root folder to show the new folder
  const root = findRootFolder(host);
  if (root) {{
    let open = openFolders[host] || [];
    if (!open.includes(root.id)) {{ open.push(root.id); openFolders[host] = open; }}
  }}
  setTimeout(() => startRename(host, id), 80);
}}

function selectNote(host, nid) {{
  activeNote[host] = nid;
  saveState();
  renderNotesTree(host);
  loadNoteIntoEditor(host, nid);
}}

function loadNoteIntoEditor(host, nid) {{
  const note = getNoteById(host, nid);
  if (!note) return;
  const cm = cmInstances[host];
  if (!cm) return;
  suppressEditorSync = true;
  cm.setValue(note.content || '');
  cm.clearHistory();
  suppressEditorSync = false;
  cm.refresh();
  const titleEl = document.getElementById('editor-title-' + host);
  if (titleEl) titleEl.textContent = note.title;
  updateStatusBar(host);
  updateNoteCount();
}}

function startRename(host, nid) {{
  const treeItem = document.querySelector('.tree-item[data-id="' + nid + '"]');
  if (!treeItem) return;
  const labelEl = treeItem.querySelector('.item-label');
  if (!labelEl || labelEl.querySelector('input')) return;
  const note = getNoteById(host, nid);
  if (!note) return;

  const input = document.createElement('input');
  input.type = 'text';
  input.value = note.title;
  input.className = 'tree-rename-input';
  labelEl.innerHTML = '';
  labelEl.appendChild(input);
  input.focus();
  input.select();
  input.addEventListener('click', e => e.stopPropagation());

  const finish = () => {{
    const newTitle = input.value.trim();
    // Prevent empty/folder-conflict titles
    if (newTitle) {{
      // Check for duplicate names at same level
      const siblings = (notes[host] || []).filter(n => n.parentId === note.parentId && n.id !== note.id);
      const dup = siblings.find(s => s.title.toLowerCase() === newTitle.toLowerCase());
      if (dup) {{
        showToast('A note with this name already exists');
        note.title = newTitle; // still rename to avoid data loss
      }} else {{
        note.title = newTitle;
      }}
    }}
    saveState();
    renderNotesTree(host);
    if (activeNote[host] === nid) {{
      const titleEl = document.getElementById('editor-title-' + host);
      if (titleEl) titleEl.textContent = note.title;
    }}
  }};
  input.addEventListener('blur', finish);
  input.addEventListener('keydown', e => {{
    if (e.key === 'Enter') {{ e.preventDefault(); input.blur(); }}
    if (e.key === 'Escape') {{ input.value = note.title; input.blur(); }}
  }});
}}

function confirmDeleteItem(host, nid) {{
  const item = getNoteById(host, nid);
  if (!item) return;
  // Don't allow deleting the root "Notes" folder
  if (item.type === 'folder' && item.parentId === null) {{
    showToast('Cannot delete root Notes folder');
    return;
  }}
  const label = item.type === 'folder' ? 'Delete Folder' : 'Delete Note';
  const msg = item.type === 'folder'
    ? 'Delete this folder and all its contents?'
    : 'Delete this note? This cannot be undone.';
  confirmAction(label, msg, () => {{
    deleteItemAndChildren(host, nid);
    if (activeNote[host] === nid) {{
      activeNote[host] = null;
      // Select first available file
      const allFiles = (notes[host] || []).filter(n => n.type === 'file');
      if (allFiles.length) {{
        selectNote(host, allFiles[0].id);
      }} else {{
        const cm = cmInstances[host];
        if (cm) {{ suppressEditorSync = true; cm.setValue(''); suppressEditorSync = false; }}
        const titleEl = document.getElementById('editor-title-' + host);
        if (titleEl) titleEl.textContent = 'No note selected';
      }}
    }}
    saveState();
    renderNotesTree(host);
    updateNoteCount();
  }});
}}

function deleteItemAndChildren(host, parentId) {{
  // Collect all descendant IDs first (BFS), then delete all in one pass.
  // This avoids the bug of modifying notes[host] while iterating.
  let toDelete = new Set();
  let queue = [parentId];
  while (queue.length > 0) {{
    let current = queue.shift();
    toDelete.add(current);
    let children = (notes[host] || []).filter(n => n.parentId === current);
    for (let child of children) queue.push(child.id);
  }}
  notes[host] = (notes[host] || []).filter(n => !toDelete.has(n.id));
}}

function updateNoteCount() {{
  let count = 0;
  for (const h in notes) count += (notes[h] || []).filter(n => n.type === 'file').length;
  const el = document.getElementById('status-notes');
  if (el) el.textContent = count + ' notes';
}}

// Context menu
let ctxMenuTarget = null;

function showContextMenu(host, nid, x, y) {{
  closeContextMenu();
  const item = getNoteById(host, nid);
  if (!item) return;
  ctxMenuTarget = {{ host, nid }};

  let menu = document.getElementById('ctx-menu');
  if (!menu) {{
    menu = document.createElement('div');
    menu.id = 'ctx-menu';
    menu.className = 'ctx-menu';
    menu.addEventListener('click', (e) => {{
      const btn = e.target.closest('.ctx-item');
      if (!btn) return;
      const action = btn.dataset.ctxact;
      if (action && ctxMenuTarget) {{
        closeContextMenu();
        const {{ host: h, nid: n }} = ctxMenuTarget;
        if (action === 'add-file') addFileInFolder(h, n);
        else if (action === 'add-subfolder') addSubFolder(h, n);
        else if (action === 'rename-item') startRename(h, n);
        else if (action === 'delete-item') confirmDeleteItem(h, n);
      }}
    }});
    document.body.appendChild(menu);
  }}

  let html = '';
  if (item.type === 'folder') {{
    html += '<button class="ctx-item" data-ctxact="add-file"><i class="ph ph-plus"></i>New Note</button>';
    html += '<button class="ctx-item" data-ctxact="add-subfolder"><i class="ph ph-folder-plus"></i>New Subfolder</button>';
    html += '<div class="ctx-sep"></div>';
    if (item.parentId !== null) {{
      html += '<button class="ctx-item" data-ctxact="rename-item"><i class="ph ph-pencil-simple"></i>Rename</button>';
      html += '<div class="ctx-sep"></div>';
      html += '<button class="ctx-item danger" data-ctxact="delete-item"><i class="ph ph-trash"></i>Delete Folder</button>';
    }}
  }} else {{
    html += '<button class="ctx-item" data-ctxact="rename-item"><i class="ph ph-pencil-simple"></i>Rename</button>';
    html += '<div class="ctx-sep"></div>';
    html += '<button class="ctx-item danger" data-ctxact="delete-item"><i class="ph ph-trash"></i>Delete Note</button>';
  }}

  menu.innerHTML = html;
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  menu.classList.add('open');

  // Adjust if off-screen
  const rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth) menu.style.left = (x - rect.width) + 'px';
  if (rect.bottom > window.innerHeight) menu.style.top = (y - rect.height) + 'px';
}}

function closeContextMenu() {{
  const menu = document.getElementById('ctx-menu');
  if (menu) menu.classList.remove('open');
  ctxMenuTarget = null;
}}

// ========== INIT & SAVE ==========
function loadInitialState() {{
  try {{
    const el = document.getElementById('app-state');
    if (el && el.textContent.trim()) {{
      const d = JSON.parse(el.textContent);
      // 'hidden' is the current key; fall back to the legacy 'deleted' key from
      // older exports so previously-hidden targets aren't unexpectedly restored.
      hiddenHosts = d.hidden || d.deleted || [];
      purgedHosts = d.purged || [];
      testingHosts = d.testing || [];
      notes = d.notes || {{}};
      activeNote = d.activeNote || {{}};
      openFolders = d.openFolders || {{}};
      checklistState = d.checklist || {{}};
      customSteps = d.customSteps || {{}};
      hiddenSteps = d.hiddenSteps || {{}};
      pretestingAnswers = d.pretestingAnswers || {{}};
      ptOpenSections = d.ptOpenSections || {{}};
      openQuestions = d.openQuestions || {{}};
            sidebarWidths = d.sidebarWidths || {{}};
      sidebarCollapsed = d.sidebarCollapsed || {{}};
      sidebarActiveTab = d.sidebarActiveTab || {{}};
      testingSidebarCollapsed = d.testingSidebarCollapsed || false;
      generalNotesContent = d.generalNotesContent || '';
      const custom = d.custom || [];
      for (let c of custom) {{
        if (!M[c.host]) {{
          let nt = {{ host:c.host, url:c.url, ip:'-', port:'-', status:0, tech:[], title:'', words:0, cl:0, score:0, priority:'info', cats:['web'], vulns:[], steps: generatePretestingSteps(c.host, [], 0), desc:'Custom target', ips:[], score_breakdown:{{}} }};
          T.push(nt); M[nt.host] = nt;
        }}
      }}
    }}
  }} catch(e) {{ console.error('state load:', e); }}
  // Actually remove permanently-deleted hosts from the working set (bug fix:
  // deletion used to only hide a host from view — it stayed in T/M forever and
  // could resurface after a resume). This purge is authoritative going forward.
  if (purgedHosts.length) {{
    T = T.filter(t => !purgedHosts.includes(t.host));
    M = Object.fromEntries(T.map(t => [t.host, t]));
    hiddenHosts = hiddenHosts.filter(h => !purgedHosts.includes(h));
  }}
  // Ensure every host that has state has a default root
  let allKnownHosts = new Set([...testingHosts, ...openEditorTabs, ...Object.keys(notes)]);
  for (let h of allKnownHosts) {{
    ensureDefaultRoot(h);
  }}
  // Ensure activeNote points to a file, not a folder or deleted item
  for (let h in activeNote) {{
    const item = getNoteById(h, activeNote[h]);
    if (!item || item.type !== 'file') {{
      const firstFile = (notes[h] || []).find(n => n.type === 'file');
      activeNote[h] = firstFile ? firstFile.id : null;
    }}
  }}
  // Migration: if generalNotesContent is empty, try to load from existing general notes
  if (!generalNotesContent) {{
    for (let h in notes) {{
      const genNote = (notes[h] || []).find(n => n.title === 'general' && n.type === 'file');
      if (genNote && genNote.content) {{
        generalNotesContent = genNote.content;
        break;
      }}
    }}
  }}
  // Default sidebar tab to 'notes' for all hosts
  for (let h of allKnownHosts) {{
    if (!sidebarActiveTab[h]) sidebarActiveTab[h] = 'notes';
  }}
}}

function saveState() {{
  const state = {{
    hidden: hiddenHosts, purged: purgedHosts, testing: testingHosts, notes: notes,
    activeNote: activeNote, openFolders: openFolders,
    checklist: checklistState, customSteps: customSteps,
    hiddenSteps: hiddenSteps,
    pretestingAnswers: pretestingAnswers,
    ptOpenSections: ptOpenSections,
    openQuestions: openQuestions,
    sidebarWidths: sidebarWidths, sidebarCollapsed: sidebarCollapsed,
    sidebarActiveTab: sidebarActiveTab,
    testingSidebarCollapsed: testingSidebarCollapsed,
    generalNotesContent: generalNotesContent,
    custom: T.filter(t => t.desc === 'Custom target').map(t => ({{host: t.host, url: t.url}}))
  }};
  document.getElementById('app-state').textContent = JSON.stringify(state);
  queueAutosave();
}}

// ========== NAVIGATION ==========
const svgTargets = '<i class="ph ph-squares-four" style="width:14px;height:14px;font-size:14px"></i>';
const svgVulns   = '<i class="ph ph-shield-warning" style="width:14px;height:14px;font-size:14px"></i>';
const svgIPs     = '<i class="ph ph-network" style="width:14px;height:14px;font-size:14px"></i>';
const svgTesting = '<i class="ph ph-flask" style="width:14px;height:14px;font-size:14px"></i>';

function renderNav() {{
  const nav = document.getElementById('nav-tabs');
  nav.innerHTML = '';
  const tabs = [
    {{ id:'targets', label:'Targets', icon:svgTargets }},
    {{ id:'vulns',   label:'Vulns',   icon:svgVulns }},
    {{ id:'ips',     label:'IP Map',  icon:svgIPs }},
    {{ id:'testing', label:'Testing', icon:svgTesting }}
  ];
  tabs.forEach(t => {{
    const el = document.createElement('button');
    el.className = 'nav-tab' + (activeView === t.id ? ' active' : '');
    el.innerHTML = t.icon + ' ' + t.label;
    el.onclick = () => switchView(t.id);
    nav.appendChild(el);
  }});
  openEditorTabs.forEach(host => {{
    const el = document.createElement('button');
    el.className = 'nav-tab' + (activeView === 'editor-' + host ? ' active' : '');
    el.innerHTML = '<span class="tab-dot"></span> ' + escHtml(host) + ' <span class="close-btn" onclick="event.stopPropagation();closeEditorTab(this)">×</span>';
    el.onclick = () => switchView('editor-' + host);
    nav.appendChild(el);
  }});
}}

function switchView(viewId) {{
  activeView = viewId;
  if (viewId.startsWith('editor-') && !openEditorTabs.includes(viewId.replace('editor-',''))) openEditorTabs.push(viewId.replace('editor-',''));
  renderNav();
  renderViewport();
}}

function closeEditorTab(el) {{
  let host = typeof el === 'string' ? el : (el.dataset.value || activeView.replace('editor-',''));
  openEditorTabs = openEditorTabs.filter(h => h !== host);
  if (activeView === 'editor-' + host) activeView = openEditorTabs.length ? 'editor-' + openEditorTabs[openEditorTabs.length-1] : 'testing';
  if (cmInstances[host]) {{ try {{ cmInstances[host].toTextArea(); }} catch(e) {{}} delete cmInstances[host]; }}
  const wrapper = document.getElementById('view-wrapper-editor-' + host);
  if (wrapper) wrapper.remove();
  renderNav();
  renderViewport();
}}

function renderViewport() {{
  const vp = document.getElementById('viewport');
  Array.from(vp.children).forEach(c => c.style.display = 'none');
  let wrapperId = 'view-wrapper-' + activeView;
  let wrapper = document.getElementById(wrapperId);
  if (!wrapper) {{
    wrapper = document.createElement('div');
    wrapper.id = wrapperId;
    wrapper.style.position = 'absolute';
    wrapper.style.inset = '0';
    wrapper.style.overflow = 'hidden';
    vp.appendChild(wrapper);
    if (activeView === 'targets') renderTargetsView(wrapper);
    else if (activeView === 'vulns') renderVulnsView(wrapper);
    else if (activeView === 'ips') renderIPsView(wrapper);
    else if (activeView === 'testing') renderTestingView(wrapper);
    else if (activeView.startsWith('editor-')) renderEditorView(wrapper, activeView.replace('editor-',''));
  }} else {{
    // Re-render views whose content can change from outside a full nav
    // switch (hide/unhide/delete, add/remove-testing, etc). These are all
    // cheap, stateless rebuilds from T — only editor tabs are skipped here
    // since they hold live CodeMirror instances that must not be recreated.
    if (activeView === 'targets') renderTargetsView(wrapper);
    else if (activeView === 'testing') renderTestingView(wrapper);
    else if (activeView === 'vulns') renderVulnsView(wrapper);
    else if (activeView === 'ips') renderIPsView(wrapper);
  }}
  if (activeView.startsWith('editor-')) {{
    wrapper.style.display = 'flex';
    let host = activeView.replace('editor-','');
    if (cmInstances[host]) setTimeout(() => cmInstances[host].refresh(), 50);
  }} else if (activeView === 'testing') {{
    wrapper.style.display = 'flex';
  }} else {{
    wrapper.style.display = 'block';
    wrapper.style.overflowY = 'auto';
  }}
}}

// ========== TARGETS VIEW ==========
function renderTargetsView(vp) {{
  // Save filter state before re-creating DOM (fix: filters persist across actions)
  const _savedSearch = document.getElementById('searchInput')?.value || '';
  const _savedPrio = document.getElementById('prioFilter')?.value || 'all';
  const _savedSort = document.getElementById('sortSelect')?.value || 'score-desc';
  const _savedStatus = document.getElementById('statusFilter')?.value || 'all';
  const _savedCat = currentCategory || 'all';
  const prios = {{}};
  T.forEach(t => {{ if(!hiddenHosts.includes(t.host)) prios[t.priority] = (prios[t.priority]||0)+1; }});
  vp.innerHTML =
  '<div class="view-container">' +
   '<div class="section-title"><i class="ph ' + (showHiddenOnly ? 'ph-eye-slash' : 'ph-squares-four') + '"></i>' + (showHiddenOnly ? 'Hidden Targets' : 'Targets') + '</div>' +
   '<div class="stats-grid">' +
    '<div class="stat-card"><div class="stat-val" style="color:var(--p-critical)">' + (prios.critical||0) + '</div><div class="stat-lbl">Critical</div></div>' +
    '<div class="stat-card"><div class="stat-val" style="color:var(--p-high)">' + (prios.high||0) + '</div><div class="stat-lbl">High</div></div>' +
    '<div class="stat-card"><div class="stat-val" style="color:var(--p-medium)">' + (prios.medium||0) + '</div><div class="stat-lbl">Medium</div></div>' +
    '<div class="stat-card"><div class="stat-val" style="color:var(--p-low)">' + (prios.low||0) + '</div><div class="stat-lbl">Low</div></div>' +
    '<div class="stat-card"><div class="stat-val" style="color:var(--p-info)">' + (prios.info||0) + '</div><div class="stat-lbl">Info</div></div>' +
   '</div>' +
   '<div class="toolbar">' +
    '<input type="text" id="searchInput" placeholder="Search hosts, tech, title..." oninput="filterTargets()">' +
    '<select id="sortSelect" onchange="filterTargets()">' +
     '<option value="score-desc">Score: High → Low</option>' +
     '<option value="score-asc">Score: Low → High</option>' +
     '<option value="alpha">Name A–Z</option>' +
     '<option value="status">Status: 2xx → 5xx</option>' +
    '</select>' +
    '<select id="prioFilter" onchange="filterTargets()">' +
     '<option value="all">All priorities</option>' +
     '<option value="critical">Critical</option><option value="high">High</option>' +
     '<option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>' +
    '</select>' +
    '<select id="statusFilter" onchange="filterTargets()">' +
     '<option value="all">All statuses</option>' +
     '<option value="2xx">2xx Success</option><option value="3xx">3xx Redirect</option>' +
     '<option value="4xx">4xx Error</option><option value="5xx">5xx Server Error</option>' +
     '<option value="200">200 OK</option><option value="301">301 Moved</option>' +
     '<option value="401">401 Unauthorized</option><option value="403">403 Forbidden</option>' +
     '<option value="500">500 Error</option>' +
    '</select>' +
    (showHiddenOnly ? '' : '<button class="btn-sm" onclick="copyFilteredTargets()" title="Copy filtered hostnames"><i class="ph ph-copy"></i> Copy All</button>') +
    (showHiddenOnly ? '' : '<button class="btn-sm danger" onclick="hideFilteredTargets()" title="Hide all filtered targets"><i class="ph ph-eye-slash"></i> Hide All</button>') +
    '<button class="btn-sm' + (showHiddenOnly ? ' active' : '') + '" id="hiddenToggleBtn" onclick="toggleHiddenView()"><i class="ph ph-eye-slash"></i> Hidden (' + hiddenHosts.length + ')</button>' +
    (showHiddenOnly ? '<button class="btn-sm" onclick="unhideAll()"><i class="ph ph-arrow-counter-clockwise"></i> Unhide All</button>' : '') +
   '</div>' +
   '<div class="cat-filter">' + cat_buttons_html + '</div>' +
   '<div id="targetsList" class="card-grid"></div>' +
   '<div id="emptyTargets" class="empty" style="display:none">' + (showHiddenOnly ? '<i class="ph ph-eye-slash"></i>No hidden targets.' : '<i class="ph ph-magnifying-glass"></i>No targets match filters.') + '</div>' +
  '</div>';
  // Restore filter state after re-creating DOM
  const _restoreSearch = document.getElementById('searchInput');
  const _restorePrio = document.getElementById('prioFilter');
  const _restoreSort = document.getElementById('sortSelect');
  const _restoreStatus = document.getElementById('statusFilter');
  if (_restoreSearch) _restoreSearch.value = _savedSearch;
  if (_restorePrio) _restorePrio.value = _savedPrio;
  if (_restoreSort) _restoreSort.value = _savedSort;
  if (_restoreStatus) _restoreStatus.value = _savedStatus;
  // Restore category button active state
  if (_savedCat !== 'all') {{
    document.querySelectorAll('.cat-btn').forEach(function(b) {{
      if (b.dataset.cat === _savedCat) b.classList.add('active');
    }});
  }}
  currentCategory = _savedCat;
  filterTargets();
}}

const cat_buttons_html = '{cat_buttons}';

let currentCategory = 'all';
function filterByCategory(cat, btn) {{
  if (currentCategory === cat) {{
    currentCategory = 'all';
    document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
  }} else {{
    currentCategory = cat;
    document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }}
  filterTargets();
}}

function filterTargets() {{
  let search = (document.getElementById('searchInput')?.value || '').toLowerCase();
  let prio = document.getElementById('prioFilter')?.value || 'all';
  let sort = document.getElementById('sortSelect')?.value || 'score-desc';
  let statusF = document.getElementById('statusFilter')?.value || 'all';
  let cat = currentCategory || 'all';
  let filtered = showHiddenOnly
    ? T.filter(t => hiddenHosts.includes(t.host))
    : T.filter(t => !hiddenHosts.includes(t.host));
  filtered = filtered.filter(t => {{
    if (prio !== 'all' && t.priority !== prio) return false;
    if (cat !== 'all' && !(t.cats || []).includes(cat)) return false;
    if (search) {{
      let hay = (t.host + ' ' + (t.title||'') + ' ' + (t.tech||[]).join(' ') + ' ' + (t.ip||'')).toLowerCase();
      if (!hay.includes(search)) return false;
    }}
    if (statusF !== 'all') {{
      if (statusF === '2xx' && (t.status < 200 || t.status >= 300)) return false;
      else if (statusF === '3xx' && (t.status < 300 || t.status >= 400)) return false;
      else if (statusF === '4xx' && (t.status < 400 || t.status >= 500)) return false;
      else if (statusF === '5xx' && t.status < 500) return false;
      else if (['200','301','401','403','500'].includes(statusF) && t.status !== parseInt(statusF)) return false;
    }}
    return true;
  }});
  if (sort === 'score-desc') filtered.sort((a,b) => b.score - a.score);
  else if (sort === 'score-asc') filtered.sort((a,b) => a.score - b.score);
  else if (sort === 'alpha') filtered.sort((a,b) => a.host.localeCompare(b.host));
  else if (sort === 'status') {{
    const group = s => {{ if (s<200) return 0; if (s<300) return 1; if (s<400) return 2; if (s<500) return 3; return 4; }};
    filtered.sort((a,b) => {{ let ga=group(a.status), gb=group(b.status); if (ga!==gb) return ga-gb; return b.score - a.score; }});
  }}
  const list = document.getElementById('targetsList');
  const empty = document.getElementById('emptyTargets');
  if (list) list.innerHTML = filtered.map(t => targetCard(t, showHiddenOnly)).join('');
  if (empty) {{
    empty.style.display = filtered.length ? 'none' : 'block';
    empty.innerHTML = showHiddenOnly
      ? '<i class="ph ph-eye-slash"></i>No hidden targets.'
      : '<i class="ph ph-magnifying-glass"></i>No targets match filters.';
  }}
}}

function toggleHiddenView() {{
  showHiddenOnly = !showHiddenOnly;
  const wrapper = document.getElementById('view-wrapper-targets');
  if (wrapper) renderTargetsView(wrapper);
}}

function getStatusBadge(status) {{
  let color = 'var(--text-muted)', bg = 'var(--bg-surface)';
  if (status >= 200 && status < 300) {{ color = 'var(--success)'; bg = 'rgba(106,153,85,0.15)'; }}
  else if (status >= 300 && status < 400) {{ color = 'var(--p-info)'; bg = 'rgba(86,156,214,0.15)'; }}
  else if (status === 401 || status === 403) {{ color = 'var(--warning)'; bg = 'rgba(220,220,170,0.15)'; }}
  else if (status >= 400 && status < 500) {{ color = 'var(--p-high)'; bg = 'rgba(206,145,120,0.15)'; }}
  else if (status >= 500) {{ color = 'var(--danger)'; bg = 'rgba(244,71,71,0.15)'; }}
  return '<span style="background:'+bg+';color:'+color+';padding:1px 6px;border-radius:3px;font-weight:600;font-size:10px;font-family:var(--font-mono)">'+(status||'—')+'</span>';
}}

function targetCard(t, hiddenView) {{
  let techs = (t.tech||[]).slice(0,3).map(tech => '<span class="tag tech">'+escHtml(tech)+'</span>').join('');
  let vulns = (t.vulns||[]).slice(0,2).map(v => '<span class="tag vuln">'+escHtml(v)+'</span>').join('');
  let pc = t.priority ? t.priority[0] : 'i';
  let statusBadge = getStatusBadge(t.status);
  let testingBadge = testingHosts.includes(t.host) ? '<span class="tag testing"><i class="ph ph-flask" style="font-size:9px;margin-right:2px"></i>Testing</span>' : '';
  let reconBadge = '';
  if (t.katana && t.katana.count) reconBadge += '<span class="tag recon" title="Crawled URLs (katana)"><i class="ph ph-tree-structure" style="font-size:9px;margin-right:2px"></i>'+t.katana.count+'</span>';
  if (t.nuclei && t.nuclei.length) reconBadge += '<span class="tag recon" title="Nuclei findings"><i class="ph ph-bug" style="font-size:9px;margin-right:2px"></i>'+t.nuclei.length+'</span>';
  let hostUrl = t.url || ('https://' + t.host);
  let hostLink = '<a href="'+escAttr(hostUrl)+'" target="_blank" rel="noopener" class="t-host">'+escHtml(t.host)+'</a>';

  // ── Detailed breakdown panel (hidden by default, toggled by button) ──
  let breakdown = t.score_breakdown || {{}};
  let catMeta = {{
    status:  {{ icon: 'ph-flag',               color: 'var(--p-info)',     label: 'Status Code' }},
    tech:    {{ icon: 'ph-stack',               color: 'var(--p-medium)',   label: 'Technology' }},
    content: {{ icon: 'ph-files',               color: 'var(--text-secondary)', label: 'Content' }},
    naming:  {{ icon: 'ph-magnifying-glass',    color: 'var(--p-high)',     label: 'Naming' }},
    title:   {{ icon: 'ph-text-aa',             color: 'var(--p-low)',      label: 'Title' }},
    infra:   {{ icon: 'ph-buildings',           color: 'var(--accent)',     label: 'Infrastructure' }},
    recon:   {{ icon: 'ph-radar',               color: 'var(--warning)',    label: 'Recon' }},
  }};
  let detailRows = '';
  for (let cat in catMeta) {{
    let items = breakdown[cat] || [];
    if (!items.length) continue;
    let catTotal = 0;
    let rows = items.map(item => {{
      let label = item[0], pts = item[1], reason = item[2] || '';
      catTotal += pts;
      let ptsColor = pts >= 0 ? 'var(--success)' : 'var(--danger)';
      let sign = pts >= 0 ? '+' : '';
      return '<div class="detail-signal">' +
        '<div class="detail-signal-header"><span class="detail-label">'+escHtml(label)+'</span><span class="detail-pts" style="color:'+ptsColor+'">'+sign+pts+'</span></div>' +
        (reason ? '<div class="detail-reason">'+escHtml(reason)+'</div>' : '') +
      '</div>';
    }}).join('');
    detailRows += '<div class="detail-cat">' +
      '<div class="detail-cat-header"><i class="ph '+catMeta[cat].icon+'" style="font-size:12px;color:'+catMeta[cat].color+'"></i><span>'+catMeta[cat].label+'</span><span class="detail-cat-total">'+(catTotal>=0?'+':'')+catTotal+'</span></div>' +
      rows + '</div>';
  }}
  let totalColor = t.score >= 75 ? 'var(--p-critical)' : t.score >= 55 ? 'var(--p-high)' : t.score >= 35 ? 'var(--p-medium)' : 'var(--p-low)';
  let detailPanel = '<div class="score-detail" id="sd-'+escAttr(t.host)+'">' +
    '<div class="detail-total"><span>Score Breakdown</span><span style="color:'+totalColor+';font-weight:700;font-size:14px">'+t.score+'<span style="font-size:10px;color:var(--text-muted)">/100</span></span></div>' +
    detailRows + '</div>';

  let actions = hiddenView ?
    ('<button class="t-action" data-action="copy-clip" data-value="'+escAttr(t.host)+'"><i class="ph ph-copy"></i></button>' +
     '<button class="t-action" data-action="unhide-target" data-value="'+escAttr(t.host)+'"><i class="ph ph-eye"></i></button>' +
     '<button class="t-action" data-action="delete-target" data-value="'+escAttr(t.host)+'" title="Permanently delete" style="color:var(--danger)"><i class="ph ph-trash"></i></button>')
    :
    ('<button class="t-action" data-action="copy-clip" data-value="'+escAttr(t.host)+'" title="Copy hostname"><i class="ph ph-copy"></i></button>' +
     '<button class="t-action" data-action="add-testing" data-value="'+escAttr(t.host)+'" title="Add to testing"><i class="ph ph-plus"></i></button>' +
     '<button class="t-action" data-action="toggle-detail" data-value="'+escAttr(t.host)+'" title="Full scoring breakdown"><i class="ph ph-chart-bar"></i></button>' +
     '<button class="t-action" data-action="hide-target" data-value="'+escAttr(t.host)+'" title="Hide (recoverable)"><i class="ph ph-eye-slash"></i></button>' +
     '<button class="t-action" data-action="delete-target" data-value="'+escAttr(t.host)+'" title="Permanently delete" style="color:var(--danger)"><i class="ph ph-trash"></i></button>');
  return    '<div class="t-card p-'+pc+'">' +
   '<div class="t-head">' +
    hostLink +
    '<span class="t-score s-'+pc+'">'+t.score+'</span>' +
   '</div>' +
   '<div class="t-meta">' +
    '<span>'+statusBadge+'</span>' +
    '<span><i class="ph ph-globe" style="font-size:10px"></i> '+(t.ip||'—')+'</span>' +
    '<span><i class="ph ph-text-t" style="font-size:10px"></i> '+(t.words||0).toLocaleString()+'w</span>' +
   '</div>' +
   (t.title ? '<div class="t-title" title="'+escAttr(t.title)+'">"'+escHtml(t.title)+'"</div>' : '') +
   '<div class="t-desc">'+escHtml(t.desc)+'</div>' +
   '<div class="tags">'+techs+vulns+testingBadge+reconBadge+'</div>' +
   detailPanel +
   '<div class="t-actions">' + actions + '</div>' +
  '</div>';
}}

// ========== VULNS VIEW ==========
const vuln_rows_html = `{vuln_rows}`;
function renderVulnsView(vp) {{
  vp.innerHTML = '<div class="view-container">' +
   '<div class="section-title"><i class="ph ph-shield-warning"></i>Vulnerability Classes</div>' +
   vuln_rows_html +
   (vuln_rows_html === '' ? '<div class="empty"><i class="ph ph-shield-check"></i>No vulnerabilities detected.</div>' : '') +
  '</div>';
}}

// ========== IP MAP VIEW ==========
const ip_rows_html = `{ip_rows}`;
function renderIPsView(vp) {{
  vp.innerHTML = '<div class="view-container">' +
   '<div class="section-title"><i class="ph ph-network"></i>IP Map</div>' +
   ip_rows_html +
   (ip_rows_html === '' ? '<div class="empty"><i class="ph ph-network"></i>No IP data available.</div>' : '') +
  '</div>';
}}

// ========== TESTING WORKSPACE ==========
function renderTestingView(vp) {{
  let testTargets = T.filter(t => testingHosts.includes(t.host) && !hiddenHosts.includes(t.host));
  let selected = selectedTestingHost && testingHosts.includes(selectedTestingHost) ? selectedTestingHost : (testTargets.length ? testTargets[0].host : null);
  selectedTestingHost = selected;

  let sidebarClass = testingSidebarCollapsed ? 'collapsed' : '';
  let toggleIcon = testingSidebarCollapsed ? 'ph-caret-double-right' : 'ph-caret-double-left';
  let hostItems = testTargets.map(t => {{
    let pc = t.priority === 'critical' ? 'crit' : t.priority === 'high' ? 'high' : t.priority === 'medium' ? 'med' : t.priority === 'low' ? 'low' : 'info';
    let prioColor = 'var(--p-' + pc + ')';
    // Calculate checklist progress
    let defaultSteps = t.steps || [];
    let custom = customSteps[t.host] || [];
    let checks = checklistState[t.host] || {{}};
    // Count categorized questions (pipe-delimited) and legacy steps
    let totalQ = 0, doneQ = 0;
    defaultSteps.forEach(s => {{
      totalQ++;
      if (checks[s]) doneQ++;
    }});
    custom.forEach(s => {{
      totalQ++;
      if (checks[s]) doneQ++;
    }});
    let progress = totalQ ? Math.round(doneQ / totalQ * 100) : 0;
    let progressLabel = totalQ > 0 ? '<span style="font-size:10px;color:var(--text-muted);margin-left:auto">' + progress + '%</span>' : '';
    return '<div class="testing-host-item' + (t.host === selected ? ' active' : '') + '" data-host="' + escAttr(t.host) + '" data-action="select-host" data-value="'+escAttr(t.host)+'" onclick="selectTestingHost(this)"><span class="prio-dot" style="background:' + prioColor + '"></span><a href="'+escAttr(t.url||'https://'+t.host)+'" target="_blank" rel="noopener" class="host-name" onclick="event.stopPropagation()">'+ escHtml(t.host) + '</a>' + progressLabel + '</div>';
  }}).join('');

  let mainHtml = '';
  if (selected) {{
    mainHtml = renderTestingTargetWorkspace(selected);
  }} else {{
    mainHtml = '<div class="empty"><i class="ph ph-flask"></i>No targets in testing workspace.<br>Add targets from the Targets view.</div>';
  }}

  vp.innerHTML =
  '<div class="testing-workspace">' +
   '<div class="testing-sidebar '+sidebarClass+'" id="testing-sidebar">' +
    '<div class="testing-sidebar-header">' +
     '<span>TARGETS ('+testTargets.length+')</span>' +
    '</div>' +
    '<div class="testing-host-list" id="testing-host-list">' + hostItems + '</div>' +
   '</div>' +
   '<button class="testing-toggle-btn" onclick="toggleTestingSidebar()"><i class="ph '+toggleIcon+'"></i></button>' +
   '<div class="testing-main" id="testing-main-content">' + mainHtml + '</div>' +
  '</div>';
  attachTestingEvents();
}}

function renderTestingTargetWorkspace(host) {{
  let t = M[host] || {{}};
  let defaultSteps = t.steps || [];
  let custom = customSteps[host] || [];
  let checks = checklistState[host] || {{}};
  let answers = pretestingAnswers[host] || {{}};

  // Parse categorized steps
  let categories = {{}};
  let catOrder = [];
  defaultSteps.forEach(step => {{
    if (step.includes('|')) {{
      let parts = step.split('|');
      let catKey = parts[0];
      let catName = parts[1];
      let question = parts[2];
      if (!categories[catKey]) {{
        categories[catKey] = {{ name: catName, questions: [] }};
        catOrder.push(catKey);
      }}
      categories[catKey].questions.push(question);
    }}
  }});

  if (custom.length) {{
    categories['_custom'] = {{ name: 'Custom', questions: custom.slice() }};
    catOrder.push('_custom');
  }}

  // Progress
  let totalQ = 0, answeredQ = 0;
  catOrder.forEach(ck => {{
    categories[ck].questions.forEach(q => {{
      totalQ++;
      if (checks[q]) answeredQ++;
    }});
  }});
  let progress = totalQ ? Math.round(answeredQ / totalQ * 100) : 0;
  let progressColor = progress >= 75 ? 'var(--success)' : progress >= 50 ? 'var(--warning)' : 'var(--p-critical)';

  // Map category key to Phosphor icon
  const catIconMap = {{
    'recon': 'ph-buildings',
    'stack': 'ph-wrench',
    'surface': 'ph-crosshair',
    'auth': 'ph-lock-key',
    'security': 'ph-shield',
    'logic': 'ph-puzzle-piece',
    'tech-wp': 'ph-pencil-simple',
    'tech-api': 'ph-lightning',
    'tech-vpn': 'ph-lock-simple',
    'tech-cicd': 'ph-hammer',
    'tech-mon': 'ph-chart-bar',
    'tech-cloud': 'ph-cloud',
    'tech-mail': 'ph-envelope',
    'status-401': 'ph-key',
    'status-403': 'ph-prohibit',
    'status-200': 'ph-check-circle',
    '_custom': 'ph-tag',
  }};

  // Build section HTML
  let sectionsHtml = '';
  catOrder.forEach(ck => {{
    let cat = categories[ck];
    if (!cat.questions.length) return;
    let isExpanded = (ptOpenSections[host] || []).includes(ck);
    let doneCount = cat.questions.filter(q => checks[q]).length;
    let iconClass = catIconMap[ck] || 'ph-file-text';

    let itemsHtml = cat.questions.map(q => {{
      let isAnswered = checks[q];
      let answer = answers[q] || '';
      let isOpen = openQuestions[host] === q;
      let escapedQ = escAttr(q);
      return '<div class="pt-question-item'+(isAnswered?' answered':'')+(isOpen?' open':'')+'" data-q="'+escapedQ+'">' +
        '<div class="pt-question-header" data-action="pt-toggle" data-q="'+escapedQ+'">' +
          '<div class="pt-status-indicator">'+(isAnswered?'<i class="ph ph-check" style="font-size:11px"></i>':'')+'</div>' +
          '<span class="pt-question-text">'+escHtml(q)+'</span>' +
          '<i class="ph ph-caret-down pt-question-chevron"></i>' +
        '</div>' +
        '<div class="pt-answer-panel">' +
          '<div class="pt-answer-wrap">' +
            '<textarea class="pt-answer-input" data-action="pt-answer" data-q="'+escapedQ+'" placeholder="Type your finding... (Enter to save, Shift+Enter for new line)">'+escHtml(answer)+'</textarea>' +
          '</div>' +
        '</div>' +
      '</div>';
    }}).join('');

    sectionsHtml += '<div class="pt-section'+(isExpanded?' expanded':'')+'" data-cat="'+ck+'">' +
      '<div class="pt-section-header" data-action="pt-section-toggle" data-cat="'+ck+'">' +
        '<span class="pt-cat-icon"><i class="ph '+iconClass+'"></i></span>' +
        '<span class="pt-cat-label">'+escHtml(cat.name)+'</span>' +
        '<span class="pt-cat-count">'+doneCount+'/'+cat.questions.length+'</span>' +
        '<i class="ph ph-caret-right pt-cat-arrow"></i>' +
      '</div>' +
      '<div class="pt-section-body">' + itemsHtml + '</div>' +
    '</div>';
  }});

  let vulnTags = (t.vulns||[]).map(v => '<span class="tag vuln">'+escHtml(v)+'</span>').join('');

  let reconHtml = '';
  if ((t.katana && t.katana.count) || (t.nuclei && t.nuclei.length)) {{
    let katanaBlock = '';
    if (t.katana && t.katana.count) {{
      let interestingHtml = (t.katana.interesting||[]).map(item => {{
        let urlsHtml = item.urls.map(u => '<li><a href="'+escAttr(u)+'" target="_blank">'+escHtml(u)+'</a></li>').join('');
        return '<div class="vuln-card"><div class="vuln-header" onclick="this.parentElement.classList.toggle(&quot;expanded&quot;)">' +
          '<span class="vuln-dot sv-h"></span><span class="vuln-name">'+escHtml(item.label)+'</span>' +
          '<span class="vuln-count">'+item.urls.length+'</span><i class="ph ph-caret-right vuln-arrow"></i></div>' +
          '<div class="vuln-body"><ul>'+urlsHtml+'</ul></div></div>';
      }}).join('');
      katanaBlock = '<div style="margin-bottom:10px">' +
        '<div style="font-size:11px;color:var(--text-muted);margin-bottom:6px"><i class="ph ph-tree-structure"></i> '+t.katana.count+' crawled URLs (katana)</div>' +
        (interestingHtml || '<div style="font-size:12px;color:var(--text-muted)">No interesting endpoint patterns matched.</div>') +
        '</div>';
    }}
    let nucleiBlock = '';
    if (t.nuclei && t.nuclei.length) {{
      let rows = t.nuclei.slice(0,50).map(f => {{
        let sevClass = f.severity === 'critical' ? 'sv-c' : f.severity === 'high' ? 'sv-h' : f.severity === 'medium' ? 'sv-m' : 'sv-l';
        return '<div class="vuln-card"><div class="vuln-header" onclick="this.parentElement.classList.toggle(&quot;expanded&quot;)">' +
          '<span class="vuln-dot '+sevClass+'"></span><span class="vuln-name">'+escHtml(f.name)+'</span>' +
          '<span class="vuln-count">'+escHtml(f.severity)+'</span><i class="ph ph-caret-right vuln-arrow"></i></div>' +
          '<div class="vuln-body"><ul><li>'+escHtml(f.matched_at||'')+'</li></ul></div></div>';
      }}).join('');
      nucleiBlock = '<div><div style="font-size:11px;color:var(--text-muted);margin-bottom:6px"><i class="ph ph-bug"></i> '+t.nuclei.length+' nuclei findings</div>' + rows + '</div>';
    }}
    reconHtml = '<div class="workspace-section">' +
      '<div class="ws-header"><i class="ph ph-radar"></i><span class="ws-title">Recon Intel (Katana / Nuclei)</span></div>' +
      '<div class="ws-body">' + katanaBlock + nucleiBlock + '</div>' +
     '</div>';
  }}

  return '' +
   '<div class="workspace-section">' +
    '<div class="ws-header"><i class="ph ph-target"></i><a href="'+escAttr(t.url||'https://'+host)+'" target="_blank" rel="noopener" style="color:var(--text-primary);text-decoration:none;font-size:12px;font-weight:600">'+escHtml(host)+'</a>' +
     '<span style="font-size:11px;font-weight:700;color:var(--p-info)">'+t.score+'</span>' +
     getStatusBadge(t.status) +
    '</div>' +
    '<div class="ws-body" style="font-size:12px;color:var(--text-muted);display:flex;gap:12px;flex-wrap:wrap">' +
     '<span><i class="ph ph-globe" style="font-size:11px"></i> '+(t.ip||'—')+'</span>' +
     '<span><i class="ph ph-text-t" style="font-size:11px"></i> '+(t.words||0).toLocaleString()+' words</span>' +
     '<span><i class="ph ph-hard-drives" style="font-size:11px"></i> '+(t.cl||0).toLocaleString()+' B</span>' +
     '<span><i class="ph ph-plugs" style="font-size:11px"></i> '+(t.port||'—')+'</span>' +
    '</div>' +
   '</div>' +
   reconHtml +
   '<div class="workspace-section pt-panel">' +
    '<div class="ws-header">' +
     '<i class="ph ph-clipboard-text"></i>' +
     '<span class="ws-title">Pre-Testing Intelligence</span>' +
     '<div class="pt-progress-bar"><div class="pt-progress-fill" style="width:'+progress+'%;background:'+progressColor+'"></div></div>' +
     '<span style="font-size:11px;font-weight:700;color:'+progressColor+';min-width:36px;text-align:right">'+progress+'%</span>' +
     '<button class="btn-sm" data-action="pt-expand-all" style="margin-left:6px"><i class="ph ph-arrows-out-line-vertical"></i></button>' +
     '<button class="btn-sm" data-action="pt-collapse-all"><i class="ph ph-arrows-in-line-vertical"></i></button>' +
    '</div>' +
    '<div class="pt-body">' +
     sectionsHtml +
     '<div class="pt-add-form">' +
      '<input type="text" id="custom-step-input" placeholder="Add custom question...">' +
      '<button data-action="add-custom-check"><i class="ph ph-plus"></i></button>' +
     '</div>' +
    '</div>' +
   '</div>' +
   '<div class="workspace-section">' +
    '<div class="ws-header"><i class="ph ph-shield-warning"></i><span class="ws-title">Suggested Vulnerabilities</span></div>' +
    '<div class="ws-body"><div class="tags">'+(vulnTags||'<span style="color:var(--text-muted);font-size:12px">None detected</span>')+'</div></div>' +
   '</div>' +
   '<div style="display:flex;gap:6px;justify-content:flex-end">' +
    '<button class="btn-sm" data-action="open-editor" data-value="'+host+'"><i class="ph ph-notebook"></i> Full Editor</button>' +
    '<button class="btn-sm danger" data-action="remove-testing" data-value="'+host+'"><i class="ph ph-minus-circle"></i> Remove</button>' +
   '</div>';
}}

function attachTestingEvents() {{
  const main = document.getElementById('testing-main-content');
  if (!main) return;
  const host = selectedTestingHost;
  if (!host) return;

  if (!pretestingAnswers[host]) pretestingAnswers[host] = {{}};
  if (!ptOpenSections[host]) ptOpenSections[host] = [];

  main.addEventListener('click', e => {{
    const btn = e.target.closest('[data-action]');
    if (!btn) return;

    // Toggle single question accordion — NO re-render, just DOM toggle
    if (btn.dataset.action === 'pt-toggle') {{
      const q = btn.dataset.q;
      const item = btn.closest('.pt-question-item');
      if (!item) return;

      if (openQuestions[host] === q) {{
        // Close: remove classes, clear openQuestions
        delete openQuestions[host];
        item.classList.remove('open');
      }} else {{
        // Close any previously open question
        const prevOpen = main.querySelector('.pt-question-item.open');
        if (prevOpen) prevOpen.classList.remove('open');
        // Open this one
        openQuestions[host] = q;
        item.classList.add('open');
      }}
      saveState();

      // Focus the textarea if opening
      setTimeout(() => {{
        const ta = item.querySelector('.pt-answer-input');
        if (ta) {{
          ta.focus();
          // Scroll the textarea into view within the panel
          ta.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
        }}
      }}, 120);
    }}

    // Toggle category section expand/collapse — NO re-render
    if (btn.dataset.action === 'pt-section-toggle') {{
      const cat = btn.dataset.cat;
      const section = btn.closest('.pt-section');
      if (!section) return;
      let open = ptOpenSections[host] || [];
      const idx = open.indexOf(cat);
      if (idx >= 0) {{
        open.splice(idx, 1);
        section.classList.remove('expanded');
      }} else {{
        open.push(cat);
        section.classList.add('expanded');
      }}
      ptOpenSections[host] = open;
      saveState();
    }}

    // Expand all sections — NO re-render
    if (btn.dataset.action === 'pt-expand-all') {{
      ptOpenSections[host] = [];
      main.querySelectorAll('.pt-section').forEach(s => {{
        s.classList.add('expanded');
        ptOpenSections[host].push(s.dataset.cat);
      }});
      saveState();
    }}

    // Collapse all sections — NO re-render
    if (btn.dataset.action === 'pt-collapse-all') {{
      ptOpenSections[host] = [];
      main.querySelectorAll('.pt-section').forEach(s => s.classList.remove('expanded'));
      main.querySelectorAll('.pt-question-item.open').forEach(q => q.classList.remove('open'));
      delete openQuestions[host];
      saveState();
    }}

    // Add custom question
    if (btn.dataset.action === 'add-custom-check') {{
      const input = document.getElementById('custom-step-input');
      if (input && input.value.trim()) {{
        if (!customSteps[host]) customSteps[host] = [];
        customSteps[host].push(input.value.trim());
        input.value = '';
        saveState();
        renderMainContent();
      }}
    }}

    // Reset all
    if (btn.dataset.action === 'reset-checklist') {{
      checklistState[host] = {{}};
      hiddenSteps[host] = [];
      customSteps[host] = [];
      pretestingAnswers[host] = {{}};
      ptOpenSections[host] = [];
      openQuestions[host] = null;
      saveState();
      renderMainContent();
      showToast('Pre-testing reset');
    }}
  }});

  // Enter on textarea: save + collapse. Shift+Enter: new line.
  main.addEventListener('keydown', e => {{
    if (e.target.classList.contains('pt-answer-input') && e.key === 'Enter' && !e.shiftKey) {{
      e.preventDefault();
      const q = e.target.dataset.q;
      const val = e.target.value;

      // Save answer
      if (!pretestingAnswers[host]) pretestingAnswers[host] = {{}};
      pretestingAnswers[host][q] = val;

      // Mark as answered if has content
      if (!checklistState[host]) checklistState[host] = {{}};
      const isAnswered = val.trim().length > 0;
      checklistState[host][q] = isAnswered;

      // Close current question — DOM only, no re-render
      const item = e.target.closest('.pt-question-item');
      if (item) {{
        item.classList.remove('open');
        if (isAnswered) item.classList.add('answered');
        else item.classList.remove('answered');
        // Update status indicator
        const indicator = item.querySelector('.pt-status-indicator');
        if (indicator) {{
          indicator.innerHTML = isAnswered ? '<i class="ph ph-check" style="font-size:11px"></i>' : '';
        }}
      }}
      if (openQuestions[host] === q) delete openQuestions[host];

      saveState();

      // Update category counts and progress bar dynamically
      updateTestingQuestionCounts(host);
    }}
    // Shift+Enter = new line in textarea — let it work naturally (no preventDefault)
  }});

  // Custom step input Enter key
  const stepInput = document.getElementById('custom-step-input');
  if (stepInput) {{
    stepInput.addEventListener('keydown', e => {{
      if (e.key === 'Enter') {{
        e.preventDefault();
        if (e.target.value.trim()) {{
          if (!customSteps[host]) customSteps[host] = [];
          customSteps[host].push(e.target.value.trim());
          e.target.value = '';
          saveState();
          renderMainContent();
        }}
      }}
    }});
  }}
}}

function selectTestingHost(el) {{
  let host = typeof el === 'string' ? el : (el.dataset.value || selectedTestingHost);
  selectedTestingHost = host;
  renderTestingView(document.getElementById('view-wrapper-testing'));
}}

function toggleTestingSidebar() {{
  testingSidebarCollapsed = !testingSidebarCollapsed;
  saveState();
  renderTestingView(document.getElementById('view-wrapper-testing'));
}}

function renderMainContent() {{
  if (activeView === 'testing') {{
    renderTestingView(document.getElementById('view-wrapper-testing'));
  }}
}}

function updateTestingQuestionCounts(host) {{
  const main = document.getElementById('testing-main-content');
  if (!main) return;
  const t = M[host] || {{}};
  const defaultSteps = t.steps || [];
  const custom = customSteps[host] || [];
  const checks = checklistState[host] || {{}};

  // Parse categories
  let categories = {{}};
  let catOrder = [];
  defaultSteps.forEach(step => {{
    if (step.includes('|')) {{
      let parts = step.split('|');
      if (!categories[parts[0]]) {{ categories[parts[0]] = {{ questions: [] }}; catOrder.push(parts[0]); }}
      categories[parts[0]].questions.push(parts[2]);
    }}
  }});
  if (custom.length) {{ categories['_custom'] = {{ questions: custom.slice() }}; catOrder.push('_custom'); }}

  // Update overall progress
  let totalQ = 0, answeredQ = 0;
  catOrder.forEach(ck => {{ categories[ck].questions.forEach(q => {{ totalQ++; if (checks[q]) answeredQ++; }}); }});
  const progress = totalQ ? Math.round(answeredQ / totalQ * 100) : 0;
  const progressColor = progress >= 75 ? 'var(--success)' : progress >= 50 ? 'var(--warning)' : 'var(--p-critical)';

  // Update progress bar
  const fillEl = main.querySelector('.pt-progress-fill');
  if (fillEl) fillEl.style.width = progress+'%';
  // Update progress percentage text
  const progressTextEl = main.querySelector('.ws-header span[style*="min-width:36px"]');
  if (progressTextEl) {{ progressTextEl.textContent = progress+'%'; progressTextEl.style.color = progressColor; }}

  // Update per-category counts
  catOrder.forEach(ck => {{
    const doneCount = categories[ck].questions.filter(q => checks[q]).length;
    const section = main.querySelector('.pt-section[data-cat="'+ck+'"]');
    if (section) {{
      const countEl = section.querySelector('.pt-cat-count');
      if (countEl) countEl.textContent = doneCount+'/'+categories[ck].questions.length;
    }}
  }});

  // Update main questions panel too (if editor is open for this host)
  updateMainQuestionCounts(host);
}}

// ========== EDITOR VIEW ==========
function openEditorTab(el) {{
  let host = typeof el === 'string' ? el : el.dataset.value;
  if (!openEditorTabs.includes(host)) openEditorTabs.push(host);
  switchView('editor-' + host);
  if (!testingHosts.includes(host)) {{
    testingHosts.push(host);
    ensureDefaultRoot(host);
    saveState();
  }}
}}

function renderEditorView(vp, host) {{
  let t = M[host] || {{}};
  let note = getCurrentNote(host);
  let title = note ? note.title : 'No note selected';
  if (!sidebarActiveTab[host]) sidebarActiveTab[host] = 'notes';

  vp.innerHTML =
  '<div class="sidebar-wrapper" id="sidebar-wrapper-'+host+'">' +
   '<div class="editor-sidebar" id="sidebar-'+host+'">' +
    '<div class="sidebar-content" id="sb-content-'+host+'"></div>' +
   '</div>' +
   '<button class="sidebar-toggle" id="collapse-btn-'+host+'" data-action="toggle-sidebar" data-value="'+host+'" onclick="toggleSidebar(this)"><i class="ph ph-caret-left"></i></button>' +
   '<div class="resize-handle" id="resize-'+host+'"></div>' +
  '</div>' +
  '<div class="editor-main" id="editor-main-'+host+'">' +
   '<div class="editor-note-panel" id="note-panel-'+host+'">' +
    '<div class="editor-toolbar">' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="bold" title="Bold"><b>B</b></button>' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="italic" title="Italic"><i>I</i></button>' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="code" title="Code">&lt;/&gt;</button>' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="heading" title="Heading">H</button>' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="list" title="List">•</button>' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="link" title="Link">🔗</button>' +
     '<button class="md-btn" onclick="insertMD(this)" data-type="quote" title="Quote">❝</button>' +
     '<span class="editor-title" id="editor-title-'+host+'">'+escHtml(title)+'</span>' +
    '</div>' +
    '<div class="editor-mode-tabs" id="mode-tabs-'+host+'">' +
     '<button class="mode-tab active" data-mode="edit" onclick="setNoteMode(this)">Edit</button>' +
     '<button class="mode-tab" data-mode="preview" onclick="setNoteMode(this)">Preview</button>' +
    '</div>' +
    '<div class="editor-content">' +
     '<textarea id="cm-'+host+'" style="display:none"></textarea>' +
     '<div class="preview-pane" id="preview-'+host+'"></div>' +
    '</div>' +
    '<div class="status-bar">' +
     '<span id="chars-'+host+'">0 chars · 1 line</span>' +
     '<span>Ctrl+Shift+P = Preview</span>' +
    '</div>' +
   '</div>' +
   '<div class="editor-questions-panel" id="questions-panel-'+host+'" style="display:none"></div>' +
  '</div>';

  setTimeout(() => {{
    renderSidebar(host);
    initEditor(host);
    renderPreview(host);
    initResize(host);
    applySidebarTab(host, sidebarActiveTab[host]);
    const sidebar = document.getElementById('sidebar-'+host);
    if (sidebarCollapsed[host]) {{
      document.getElementById('sidebar-wrapper-'+host).classList.add('collapsed');
      document.getElementById('collapse-btn-'+host).innerHTML = '<i class="ph ph-caret-right"></i>';
      sidebar.style.width = '';
    }} else if (sidebarWidths[host]) {{
      sidebar.style.width = sidebarWidths[host] + 'px';
    }}
  }}, 0);
}}

function applySidebarTab(host, tab) {{
  // Update sidebar tab buttons
  const wrapper = document.getElementById('sidebar-wrapper-'+host);
  if (!wrapper) return;
  wrapper.querySelectorAll('.sidebar-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  // Update sidebar tab content panels
  wrapper.querySelectorAll('.sidebar-tab-content').forEach(c => c.classList.remove('active'));
  const tabContent = document.getElementById('tab-' + tab + '-' + host);
  if (tabContent) tabContent.classList.add('active');

  // Switch main area
  const notePanel = document.getElementById('note-panel-'+host);
  const qPanel = document.getElementById('questions-panel-'+host);

  if (tab === 'questions') {{
    if (notePanel) notePanel.style.display = 'none';
    if (qPanel) {{ qPanel.style.display = 'flex'; renderMainQuestions(host); }}
  }} else {{
    if (notePanel) notePanel.style.display = 'flex';
    if (qPanel) qPanel.style.display = 'none';
  }}
}}

function renderSidebar(host) {{
  let el = document.getElementById('sb-content-'+host);
  if (!el) return;
  let t = M[host] || {{}};
  let ipsHtml = (t.ips||[]).map(ip => '<span class="mini-tag">'+ip+'</span>').join('');
  let techsHtml = (t.tech||[]).map(tech => '<span class="mini-tag">'+escHtml(tech)+'</span>').join('');
  let catsHtml = (t.cats||[]).map(cat => '<span class="mini-tag">'+cat+'</span>').join('');

  if (!sidebarActiveTab[host]) sidebarActiveTab[host] = 'notes';

  el.innerHTML =
  '<div class="sidebar-tabs">' +
   '<button class="sidebar-tab active" data-tab="notes" data-host="'+host+'" onclick="switchSidebarTab(this)"><i class="ph ph-notebook"></i>Notes</button>' +
   '<button class="sidebar-tab" data-tab="info" data-host="'+host+'" onclick="switchSidebarTab(this)"><i class="ph ph-info"></i>Info</button>' +
   '<button class="sidebar-tab" data-tab="questions" data-host="'+host+'" onclick="switchSidebarTab(this)"><i class="ph ph-clipboard-text"></i>Questions</button>' +
  '</div>' +
  '<div class="sidebar-tab-content active" id="tab-notes-'+host+'">' +
   '<details class="tree-section" open>' +
    '<summary><span><i class="ph ph-notebook" style="margin-right:4px;font-size:11px"></i>Notes <span class="sb-head-actions"><span class="item-act" data-action="add-note" data-host="'+host+'" title="New Note" style="display:inline-flex"><i class="ph ph-plus"></i></span> <span class="item-act" data-action="add-root-folder" data-host="'+host+'" title="New Folder" style="display:inline-flex"><i class="ph ph-folder-plus"></i></span></span></span></summary>' +
    '<div class="sb-content" id="notes-tree-'+host+'"></div>' +
   '</details>' +
  '</div>' +
  '<div class="sidebar-tab-content" id="tab-info-'+host+'">' +
   '<div class="data-row"><span class="data-lbl">URL</span><span class="data-val"><a href="'+(t.url||'')+'" target="_blank">'+escHtml(t.url||'—')+'</a></span></div>' +
   '<div class="data-row"><span class="data-lbl">Status</span><span class="data-val">'+getStatusBadge(t.status)+'</span></div>' +
   '<div class="data-row"><span class="data-lbl">Score</span><span class="data-val">'+t.score+'</span></div>' +
   '<div class="data-row"><span class="data-lbl">Primary IP</span><span class="data-val">'+(t.ip||'—')+'</span></div>' +
   ((t.ips && t.ips.length > 1) ? '<div class="data-row"><span class="data-lbl">All IPs</span><span class="data-val list">'+ipsHtml+'</span></div>' : '') +
   '<div class="data-row"><span class="data-lbl">Port</span><span class="data-val">'+(t.port||'—')+'</span></div>' +
   '<div class="data-row"><span class="data-lbl">Words</span><span class="data-val">'+((t.words||0).toLocaleString())+'</span></div>' +
   '<div class="data-row"><span class="data-lbl">Size</span><span class="data-val">'+((t.cl||0).toLocaleString())+' B</span></div>' +
   (t.location ? '<div class="data-row"><span class="data-lbl">Redirects</span><span class="data-val">'+escHtml(t.location)+'</span></div>' : '') +
   '<div class="data-row"><span class="data-lbl">Tech Stack</span><span class="data-val list">'+(techsHtml||'—')+'</span></div>' +
   '<div class="data-row"><span class="data-lbl">Categories</span><span class="data-val list">'+(catsHtml||'—')+'</span></div>' +
  '</div>';

  renderNotesTree(host);
  attachSidebarEvents(host);
}}

function switchSidebarTab(el) {{
  const host = el.dataset.host;
  const tab = el.dataset.tab;
  sidebarActiveTab[host] = tab;
  saveState();
  applySidebarTab(host, tab);
}}

function renderMainQuestions(host) {{
  const container = document.getElementById('questions-panel-'+host);
  if (!container) return;
  const t = M[host] || {{}};
  const defaultSteps = t.steps || [];
  const custom = customSteps[host] || [];
  const checks = checklistState[host] || {{}};
  const answers = pretestingAnswers[host] || {{}};

  let categories = {{}};
  let catOrder = [];
  defaultSteps.forEach(step => {{
    if (step.includes('|')) {{
      let parts = step.split('|');
      let catKey = parts[0];
      let catName = parts[1];
      let question = parts[2];
      if (!categories[catKey]) {{ categories[catKey] = {{ name: catName, questions: [] }}; catOrder.push(catKey); }}
      categories[catKey].questions.push(question);
    }}
  }});
  if (custom.length) {{ categories['_custom'] = {{ name: 'Custom', questions: custom.slice() }}; catOrder.push('_custom'); }}

  let totalQ = 0, answeredQ = 0;
  catOrder.forEach(ck => {{ categories[ck].questions.forEach(q => {{ totalQ++; if (checks[q]) answeredQ++; }}); }});
  const progress = totalQ ? Math.round(answeredQ / totalQ * 100) : 0;
  const progressColor = progress >= 75 ? 'var(--success)' : progress >= 50 ? 'var(--warning)' : 'var(--p-critical)';

  const catIconMap = {{
    'recon': 'ph-buildings', 'stack': 'ph-wrench', 'surface': 'ph-crosshair',
    'auth': 'ph-lock-key', 'security': 'ph-shield', 'logic': 'ph-puzzle-piece',
    'tech-wp': 'ph-pencil-simple', 'tech-api': 'ph-lightning',
    'tech-vpn': 'ph-lock-simple', 'tech-cicd': 'ph-hammer',
    'tech-mon': 'ph-chart-bar', 'tech-cloud': 'ph-cloud',
    'tech-mail': 'ph-envelope', 'status-401': 'ph-key',
    'status-403': 'ph-prohibit', 'status-200': 'ph-check-circle', '_custom': 'ph-tag',
  }};

  let html = '<div class="questions-top-bar">' +
    '<span class="questions-title"><i class="ph ph-clipboard-text"></i> Pre-Testing Intelligence — '+escHtml(host)+'</span>' +
    '<div class="questions-progress">' +
     '<div class="q-progress-bar"><div class="q-progress-fill" id="q-fill-'+host+'" style="width:'+progress+'%;background:'+progressColor+'"></div></div>' +
     '<span class="q-progress-label" id="q-label-'+host+'" style="color:'+progressColor+'">'+answeredQ+'/'+totalQ+' answered</span>' +
    '</div>' +
  '</div>';

  html += '<div class="questions-body" id="questions-body-'+host+'">';

  let savedOpen = ptOpenSections[host] || [];
  catOrder.forEach(ck => {{
    let cat = categories[ck];
    if (!cat.questions.length) return;
    let isExpanded = savedOpen.includes(ck);
    let doneCount = cat.questions.filter(q => checks[q]).length;
    let iconClass = catIconMap[ck] || 'ph-file-text';

    html += '<div class="q-section'+(isExpanded?' expanded':'')+'" data-cat="'+ck+'">' +
      '<div class="q-section-header" data-action="q-section-toggle" data-cat="'+ck+'" data-host="'+host+'">' +
        '<span class="q-cat-icon"><i class="ph '+iconClass+'"></i></span>' +
        '<span class="q-cat-label">'+escHtml(cat.name)+'</span>' +
        '<span class="q-cat-count" data-cat-count="'+ck+'">'+doneCount+'/'+cat.questions.length+'</span>' +
        '<i class="ph ph-caret-right q-cat-arrow"></i>' +
      '</div>' +
      '<div class="q-section-body">';

    cat.questions.forEach(q => {{
      let isAnswered = checks[q];
      let answer = answers[q] || '';
      html += '<div class="q-item'+(isAnswered?' answered':'')+'" data-q="'+escAttr(q)+'" data-host="'+host+'">' +
        '<div class="q-item-header">' +
          '<div class="q-status-dot">'+(isAnswered?'<i class="ph ph-check"></i>':'')+'</div>' +
          '<span class="q-item-text">'+escHtml(q)+'</span>' +
          '<i class="ph ph-caret-down q-item-chevron"></i>' +
        '</div>' +
        '<div class="q-answer-area">' +
          '<textarea class="q-answer-input" data-q="'+escAttr(q)+'" data-host="'+host+'" placeholder="Type your findings here. Press Enter to save.">'+escHtml(answer)+'</textarea>' +
        '</div>' +
      '</div>';
    }});

    html += '</div></div>';
  }});

  html += '</div>';

  // Custom question input at bottom
  html += '<div class="q-add-form">' +
    '<input type="text" id="q-custom-input-'+host+'" placeholder="Add a custom question...">' +
    '<button class="btn-sm primary" data-action="q-add-custom" data-host="'+host+'"><i class="ph ph-plus"></i> Add</button>' +
  '</div>';

  container.innerHTML = html;
  attachMainQuestionsEvents(host);
}}

function attachMainQuestionsEvents(host) {{
  const container = document.getElementById('questions-panel-'+host);
  if (!container || container.dataset.qEventsAttached) return;
  container.dataset.qEventsAttached = 'true';

  container.addEventListener('click', e => {{
    // Section header toggle
    const btn = e.target.closest('[data-action]');
    if (btn) {{
      if (btn.dataset.action === 'q-section-toggle') {{
        const cat = btn.dataset.cat;
        const section = btn.closest('.q-section');
        if (!section) return;
        let open = ptOpenSections[host] || [];
        const idx = open.indexOf(cat);
        if (idx >= 0) {{ open.splice(idx, 1); section.classList.remove('expanded'); }}
        else {{ open.push(cat); section.classList.add('expanded'); }}
        ptOpenSections[host] = open;
        saveState();
        return;
      }}
      if (btn.dataset.action === 'q-add-custom') {{
        const input = document.getElementById('q-custom-input-'+host);
        if (input && input.value.trim()) {{
          if (!customSteps[host]) customSteps[host] = [];
          customSteps[host].push(input.value.trim());
          input.value = '';
          saveState();
          renderMainQuestions(host);
        }}
        return;
      }}
    }}

    // Question header accordion toggle (click anywhere on header to expand/collapse answer)
    const header = e.target.closest('.q-item-header');
    if (header) {{
      const qItem = header.closest('.q-item');
      if (!qItem) return;
      // Close all other open questions in this section
      container.querySelectorAll('.q-item.open').forEach(item => {{
        if (item !== qItem) item.classList.remove('open');
      }});
      qItem.classList.toggle('open');
      // Auto-focus textarea when opening
      if (qItem.classList.contains('open')) {{
        const ta = qItem.querySelector('.q-answer-input');
        if (ta) setTimeout(() => ta.focus(), 100);
      }}
    }}
  }});

  // Enter key on textarea: save answer, mark as answered, update counts
  container.addEventListener('keydown', e => {{
    if (e.target.classList.contains('q-answer-input') && e.key === 'Enter' && !e.shiftKey) {{
      e.preventDefault();
      const q = e.target.dataset.q;
      const val = e.target.value;
      if (!pretestingAnswers[host]) pretestingAnswers[host] = {{}};
      pretestingAnswers[host][q] = val;
      if (!checklistState[host]) checklistState[host] = {{}};
      const isAnswered = val.trim().length > 0;
      checklistState[host][q] = isAnswered;

      // Update the item DOM
      const qItem = e.target.closest('.q-item');
      if (qItem) {{
        qItem.classList.toggle('answered', isAnswered);
        qItem.classList.remove('open');
        const dot = qItem.querySelector('.q-status-dot');
        if (dot) dot.innerHTML = isAnswered ? '<i class="ph ph-check"></i>' : '';
      }}
      updateMainQuestionCounts(host);
      saveState();
    }}
  }});

  // Enter on custom question input
  const customInput = document.getElementById('q-custom-input-'+host);
  if (customInput) {{
    customInput.addEventListener('keydown', e => {{
      if (e.key === 'Enter') {{
        e.preventDefault();
        if (e.target.value.trim()) {{
          if (!customSteps[host]) customSteps[host] = [];
          customSteps[host].push(e.target.value.trim());
          e.target.value = '';
          saveState();
          renderMainQuestions(host);
        }}
      }}
    }});
  }}
}}

function updateMainQuestionCounts(host) {{
  const container = document.getElementById('questions-panel-'+host);
  if (!container) return;
  const t = M[host] || {{}};
  const defaultSteps = t.steps || [];
  const custom = customSteps[host] || [];
  const checks = checklistState[host] || {{}};

  let categories = {{}};
  let catOrder = [];
  defaultSteps.forEach(step => {{
    if (step.includes('|')) {{
      let parts = step.split('|');
      if (!categories[parts[0]]) {{ categories[parts[0]] = {{ questions: [] }}; catOrder.push(parts[0]); }}
      categories[parts[0]].questions.push(parts[2]);
    }}
  }});
  if (custom.length) {{ categories['_custom'] = {{ questions: custom.slice() }}; catOrder.push('_custom'); }}

  let totalQ = 0, answeredQ = 0;
  catOrder.forEach(ck => {{ categories[ck].questions.forEach(q => {{ totalQ++; if (checks[q]) answeredQ++; }}); }});
  const progress = totalQ ? Math.round(answeredQ / totalQ * 100) : 0;
  const progressColor = progress >= 75 ? 'var(--success)' : progress >= 50 ? 'var(--warning)' : 'var(--p-critical)';

  // Update top progress bar
  const fillEl = document.getElementById('q-fill-'+host);
  if (fillEl) fillEl.style.width = progress+'%';
  const labelEl = document.getElementById('q-label-'+host);
  if (labelEl) {{ labelEl.textContent = answeredQ+'/'+totalQ+' answered'; labelEl.style.color = progressColor; }}

  // Update per-category counts
  catOrder.forEach(ck => {{
    const doneCount = categories[ck].questions.filter(q => checks[q]).length;
    const countEl = container.querySelector('[data-cat-count="'+ck+'"]');
    if (countEl) countEl.textContent = doneCount+'/'+categories[ck].questions.length;
  }});
  updateTestingSidebarProgress(host);
}}

function updateTestingSidebarProgress(host) {{
  const hostItem = document.querySelector('.testing-host-item[data-host="'+host+'"]');
  if (!hostItem) return;
  const t = M[host] || {{}};
  const defaultSteps = t.steps || [];
  const custom = customSteps[host] || [];
  const checks = checklistState[host] || {{}};
  let totalQ = 0, doneQ = 0;
  defaultSteps.forEach(s => {{ totalQ++; if (checks[s]) doneQ++; }});
  custom.forEach(s => {{ totalQ++; if (checks[s]) doneQ++; }});
  const progress = totalQ ? Math.round(doneQ / totalQ * 100) : 0;
  const span = hostItem.querySelector('span:last-child');
  if (span && totalQ > 0) span.textContent = progress+'%';
}}

function getCurrentNote(host) {{
  let arr = notes[host] || [];
  let id = activeNote[host];
  let found = id ? arr.find(n => n.id === id) : null;
  if (found && found.type === 'file') return found;
  // Auto-select first file (skip folders)
  let firstFile = arr.find(n => n.type === 'file');
  if (firstFile) {{ activeNote[host] = firstFile.id; return firstFile; }}
  return null;
}}

function updateNoteContent(host, content) {{
  if (suppressEditorSync) return;
  let note = getCurrentNote(host);
  if (note) {{ note.content = content; saveState(); }}
  // Sync general notes: if editing a "general" note, update all other hosts
  if (note && note.title === 'general' && note.type === 'file') {{
    generalNotesContent = content;
    for (let h in notes) {{
      if (h === host) continue;
      let genNote = (notes[h] || []).find(n => n.title === 'general' && n.type === 'file');
      if (genNote) genNote.content = content;
    }}
  }}
}}

function initEditor(host) {{
  const ta = document.getElementById('cm-'+host);
  if (!ta || cmInstances[host]) return;
  cmInstances[host] = CodeMirror.fromTextArea(ta, {{
    mode: {{
      name: 'markdown',
      getMode: function(editor, state) {{
        if (state.fencedChars) {{
          var lang = (state.fenced_leading_trailering_space_string || '').trim().toLowerCase();
          var modeMap = {{
            'js': 'javascript', 'javascript': 'javascript', 'jsx': 'javascript', 'ts': 'javascript', 'typescript': 'javascript',
            'py': 'python', 'python': 'python',
            'sql': 'sql', 'mysql': 'sql', 'postgresql': 'sql', 'postgres': 'sql', 'sqlite': 'sql',
            'json': 'javascript', 'jsonc': 'javascript',
            'sh': 'shell', 'bash': 'shell', 'zsh': 'shell', 'shell': 'shell',
            'css': 'css', 'scss': 'css', 'less': 'css',
            'html': 'htmlmixed', 'htm': 'htmlmixed',
            'java': 'text/x-java', 'c': 'text/x-csrc', 'cpp': 'text/x-c++src', 'c++': 'text/x-c++src',
            'go': 'text/x-go', 'rust': 'text/x-rustsrc', 'rb': 'ruby', 'ruby': 'ruby',
            'php': 'text/x-php', 'xml': 'xml', 'yaml': 'yaml', 'yml': 'yaml', 'md': 'markdown'
          }};
          var modeName = modeMap[lang] || 'text/plain';
          return CodeMirror.getMode(editor.options, modeName);
        }}
        return CodeMirror.getMode(editor.options, 'markdown');
      }}
    }},
    lineNumbers: true, lineWrapping: true,
    theme: 'material-darker',
    extraKeys: {{'Enter': 'newlineAndIndentContinueMarkdownList'}}
  }});
  const note = getCurrentNote(host);
  cmInstances[host].setValue(note ? note.content : '');
  cmInstances[host].on('change', (cm) => {{
    updateNoteContent(host, cm.getValue());
    updateStatusBar(host);
    const preview = document.getElementById('preview-'+host);
    if (preview && preview.classList.contains('active')) {{
      marked.setOptions({{ breaks: true, gfm: true }});
      let md2 = marked.parse(cm.getValue());
      md2 = md2.replace(/<a /g, '<a target="_blank" rel="noopener" ');
      preview.innerHTML = md2;
    }}
  }});
  updateStatusBar(host);
}}

function toggleSidebar(el) {{
  let host = typeof el === 'string' ? el : el.dataset.value;
  const wrapper = document.getElementById('sidebar-wrapper-'+host);
  const sidebar = document.getElementById('sidebar-'+host);
  const btn = document.getElementById('collapse-btn-'+host);
  const isCollapsed = wrapper.classList.toggle('collapsed');
  if (isCollapsed) {{
    sidebar.style.width = '';
  }} else if (sidebarWidths[host]) {{
    sidebar.style.width = sidebarWidths[host] + 'px';
  }}
  btn.innerHTML = isCollapsed ? '<i class="ph ph-caret-right"></i>' : '<i class="ph ph-caret-left"></i>';
  sidebarCollapsed[host] = isCollapsed;
  saveState();
  setTimeout(() => {{ if (cmInstances[host]) cmInstances[host].refresh(); }}, 250);
}}

function initResize(host) {{
  const handle = document.getElementById('resize-'+host);
  const sidebar = document.getElementById('sidebar-'+host);
  if (!handle || !sidebar) return;
  let isResizing = false, startX, startWidth;
  handle.addEventListener('mousedown', (e) => {{
    isResizing = true; startX = e.clientX; startWidth = sidebar.offsetWidth;
    document.body.style.cursor = 'col-resize'; document.body.style.userSelect = 'none';
    handle.classList.add('active'); e.preventDefault();
  }});
  document.addEventListener('mousemove', (e) => {{
    if (!isResizing) return;
    const newWidth = Math.max(220, Math.min(600, startWidth + (e.clientX - startX)));
    sidebar.style.width = newWidth + 'px';
    sidebarWidths[host] = newWidth;
    if (cmInstances[host]) cmInstances[host].refresh();
  }});
  document.addEventListener('mouseup', () => {{
    if (isResizing) {{
      isResizing = false; document.body.style.cursor = ''; document.body.style.userSelect = '';
      handle.classList.remove('active'); saveState();
    }}
  }});
}}

function attachSidebarEvents(host) {{
  const sidebar = document.getElementById('sidebar-'+host);
  if (!sidebar || sidebar.dataset.eventsAttached) return;
  sidebar.dataset.eventsAttached = 'true';

  // Button actions (add note, rename, delete, etc.)
  sidebar.addEventListener('click', (e) => {{
    const actionEl = e.target.closest('[data-action]');
    if (!actionEl) return;
    e.stopPropagation(); e.preventDefault();
    const action = actionEl.dataset.action;
    const h = actionEl.dataset.host || host;
    const nid = actionEl.dataset.nid;
    if (action === 'add-note') addNoteForHost(h);
    if (action === 'add-root-folder') addRootFolder(h);
    if (action === 'toggle-folder') toggleFolder(h, nid);
    if (action === 'add-file') addFileInFolder(h, nid);
    if (action === 'add-subfolder') addSubFolder(h, nid);
    if (action === 'rename-item') startRename(h, nid);
    if (action === 'delete-item') confirmDeleteItem(h, nid);
  }});

  // Tree item: single click = select/toggle, double-click on label = rename
  const treeContainer = document.getElementById('notes-tree-' + host);
  if (!treeContainer || treeContainer.dataset.treeEvents) return;
  treeContainer.dataset.treeEvents = 'true';

  treeContainer.addEventListener('click', (e) => {{
    // Don't handle if clicking action buttons
    if (e.target.closest('[data-action]')) return;
    const treeItem = e.target.closest('.tree-item');
    if (!treeItem) return;
    const h = treeItem.dataset.host;
    const nid = treeItem.dataset.id;
    const type = treeItem.dataset.type;
    const depth = parseInt(treeItem.dataset.depth || '0');
    // Root folder (depth 0) is always open, no toggle
    if (type === 'folder' && depth > 0) {{
      toggleFolder(h, nid);
    }} else if (type === 'file') {{
      selectNote(h, nid);
    }}
  }});

  treeContainer.addEventListener('dblclick', (e) => {{
    if (e.target.closest('[data-action]')) return;
    const treeItem = e.target.closest('.tree-item');
    if (!treeItem) return;
    const h = treeItem.dataset.host;
    const nid = treeItem.dataset.id;
    startRename(h, nid);
  }});

  // Right-click context menu on tree items
  treeContainer.addEventListener('contextmenu', (e) => {{
    const treeItem = e.target.closest('.tree-item');
    if (!treeItem) return;
    e.preventDefault();
    const h = treeItem.dataset.host;
    const nid = treeItem.dataset.id;
    showContextMenu(h, nid, e.clientX, e.clientY);
  }});
}}

function addNoteForHost(host) {{
  ensureDefaultRoot(host);
  const root = findRootFolder(host);
  let parentId = root ? root.id : null;
  if (root) {{
    let open = openFolders[host] || [];
    if (!open.includes(root.id)) {{ open.push(root.id); openFolders[host] = open; }}
  }}
  const noteNum = (notes[host]||[]).filter(n=>n.type==='file').length + 1;
  const title = 'untitled';
  const id = addNoteItem(host, title, '', 'file', parentId);
  saveState();
  renderNotesTree(host);
  activeNote[host] = id;
  saveState();
  loadNoteIntoEditor(host, id);
  setTimeout(() => startRename(host, id), 100);
}}

function setNoteModeByHost(host, mode) {{
  let cm = cmInstances[host];
  let preview = document.getElementById('preview-'+host);
  let modeTabs = document.getElementById('mode-tabs-'+host);
  if (!cm || !preview || !modeTabs) return;
  if (mode === 'edit') {{
    cm.getWrapperElement().style.display = '';
    preview.classList.remove('active');
    setTimeout(() => cm.refresh(), 10);
  }} else {{
    cm.getWrapperElement().style.display = 'none';
    preview.classList.add('active');
    marked.setOptions({{ breaks: true, gfm: true }});
    let md = marked.parse(cm.getValue() || '');
  md = md.replace(/<a /g, '<a target="_blank" rel="noopener" ');
  preview.innerHTML = md;
  }}
  modeTabs.querySelectorAll('.mode-tab').forEach(btn => btn.classList.toggle('active', btn.dataset.mode === mode));
}}

function setNoteMode(el) {{
  let host = el.closest('.editor-main') ? activeView.replace('editor-','') : selectedTestingHost;
  let mode = el.dataset.mode;
  let cm = cmInstances[host];
  let preview = document.getElementById('preview-'+host);
  let modeTabs = document.getElementById('mode-tabs-'+host);
  if (!cm || !preview || !modeTabs) return;
  if (mode === 'edit') {{
    cm.getWrapperElement().style.display = '';
    preview.classList.remove('active');
    setTimeout(() => cm.refresh(), 10);
  }} else {{
    cm.getWrapperElement().style.display = 'none';
    preview.classList.add('active');
    marked.setOptions({{ breaks: true, gfm: true }});
    let md = marked.parse(cm.getValue() || '');
  md = md.replace(/<a /g, '<a target="_blank" rel="noopener" ');
  preview.innerHTML = md;
  }}
  modeTabs.querySelectorAll('.mode-tab').forEach(btn => btn.classList.toggle('active', btn.dataset.mode === mode));
}}

function renderPreview(host) {{
  let cm = cmInstances[host];
  let preview = document.getElementById('preview-'+host);
  if (cm && preview && preview.classList.contains('active')) {{
    marked.setOptions({{ breaks: true, gfm: true }});
    let md = marked.parse(cm.getValue() || '');
  md = md.replace(/<a /g, '<a target="_blank" rel="noopener" ');
  preview.innerHTML = md;
  }}
}}

function updateStatusBar(host) {{
  let cm = cmInstances[host];
  let span = document.getElementById('chars-'+host);
  if (!cm || !span) return;
  let val = cm.getValue();
  let lines = val.split('\\n').length;
  let words = val.trim() ? val.trim().split(/\\s+/).length : 0;
  span.innerText = val.length + ' chars · ' + lines + ' lines · ' + words + ' words';
}}

function insertMDByHost(host, type) {{
  let cm = cmInstances[host];
  if (!cm) return;
  cm.focus();
  let sel = cm.getSelection();
  let map = {{
    bold: '**'+(sel||'text')+'**',
    italic: '*'+(sel||'text')+'*',
    code: '`'+(sel||'code')+'`',
    heading: '## '+(sel||'Heading'),
    list: '- '+(sel||'item'),
    link: '['+(sel||'text')+'](url)',
    quote: '> '+(sel||'quote')
  }};
  cm.replaceSelection(map[type] || sel);
}}

function insertMD(el) {{
  let host = el.closest('.editor-main') ? activeView.replace('editor-','') : selectedTestingHost;
  let type = el.dataset.type;
  let cm = cmInstances[host];
  if (!cm) return;
  cm.focus();
  let sel = cm.getSelection();
  let map = {{
    bold: '**'+(sel||'text')+'**',
    italic: '*'+(sel||'text')+'*',
    code: '`'+(sel||'code')+'`',
    heading: '## '+(sel||'Heading'),
    list: '- '+(sel||'item'),
    link: '['+(sel||'text')+'](url)',
    quote: '> '+(sel||'quote')
  }};
  cm.replaceSelection(map[type] || sel);
}}

// ========== TARGET MANAGEMENT ==========
function addToTesting(host) {{
  if (!testingHosts.includes(host)) {{
    testingHosts.push(host);
    ensureDefaultRoot(host);
    saveState();
  }}
  openEditorTab(host);
  showToast('Added ' + host + ' to Testing');
}}

function removeFromTesting(el) {{
  let host = typeof el === 'string' ? el : el.dataset.value;
  confirmAction('Remove from Testing', 'Remove ' + host + ' from testing workspace?', () => {{
    testingHosts = testingHosts.filter(h => h !== host);
    if (selectedTestingHost === host) selectedTestingHost = testingHosts[0] || null;
    saveState();
    closeEditorTab(host);
    if (activeView === 'testing') renderViewport();
    showToast('Removed ' + host);
  }}, 'Remove');
}}

// Hide: reversible, immediate, no confirmation needed. Removes the target
// from the main Targets list and files it under the "Hidden (N)" list next
// to the sorting/filter toolbar, where it can be unhidden or permanently
// deleted later.
function hideTarget(host) {{
  if (!hiddenHosts.includes(host)) hiddenHosts.push(host);
  saveState();
  // Hide the card directly via DOM — no re-render, preserves scroll position
  document.querySelectorAll('.t-card').forEach(card => {{
    if (card.querySelector('[data-action="hide-target"][data-value="' + host + '"]')) {{
      card.style.transition = 'opacity 0.2s, transform 0.2s';
      card.style.opacity = '0';
      card.style.transform = 'scale(0.95)';
      setTimeout(() => card.remove(), 200);
    }}
  }});
  // Update hidden count badge
  const hiddenBtn = document.getElementById('hiddenToggleBtn');
  if (hiddenBtn) hiddenBtn.innerHTML = '<i class="ph ph-eye-slash"></i> Hidden (' + hiddenHosts.length + ')';
  showToast('Hidden ' + host);
}}

function unhideTarget(host) {{
  hiddenHosts = hiddenHosts.filter(h => h !== host);
  saveState();
  renderViewport();
  showToast('Unhidden ' + host);
}}

function unhideAll() {{
  if (!hiddenHosts.length) return;
  confirmAction('Unhide All', 'Unhide all ' + hiddenHosts.length + ' hidden target(s)?', () => {{
    hiddenHosts = [];
    saveState();
    renderViewport();
    showToast('Unhidden all targets');
  }}, 'Unhide All');
}}

function getFilteredHosts() {{
  let search = (document.getElementById('searchInput')?.value || '').toLowerCase();
  let prio = document.getElementById('prioFilter')?.value || 'all';
  let statusF = document.getElementById('statusFilter')?.value || 'all';
  let cat = currentCategory || 'all';
  let filtered = showHiddenOnly
    ? T.filter(t => hiddenHosts.includes(t.host))
    : T.filter(t => !hiddenHosts.includes(t.host));
  filtered = filtered.filter(t => {{
    if (prio !== 'all' && t.priority !== prio) return false;
    if (cat !== 'all' && !(t.cats || []).includes(cat)) return false;
    if (search) {{
      let hay = (t.host + ' ' + (t.title||'') + ' ' + (t.tech||[]).join(' ') + ' ' + (t.ip||'')).toLowerCase();
      if (!hay.includes(search)) return false;
    }}
    if (statusF !== 'all') {{
      if (statusF === '2xx' && (t.status < 200 || t.status >= 300)) return false;
      else if (statusF === '3xx' && (t.status < 300 || t.status >= 400)) return false;
      else if (statusF === '4xx' && (t.status < 400 || t.status >= 500)) return false;
      else if (statusF === '5xx' && t.status < 500) return false;
      else if (['200','301','401','403','500'].includes(statusF) && t.status !== parseInt(statusF)) return false;
    }}
    return true;
  }});
  return filtered.map(t => t.host);
}}

function copyFilteredTargets() {{
  const hosts = getFilteredHosts();
  if (!hosts.length) {{ showToast('No targets to copy'); return; }}
  navigator.clipboard.writeText(hosts.join('\\n')).then(() => showToast('Copied ' + hosts.length + ' host(s)')).catch(() => showToast('Copy failed'));
}}

function hideFilteredTargets() {{
  const hosts = getFilteredHosts();
  if (!hosts.length) {{ showToast('No targets to hide'); return; }}
  hosts.forEach(h => {{ if (!hiddenHosts.includes(h)) hiddenHosts.push(h); }});
  saveState();
  renderViewport();
  showToast('Hidden ' + hosts.length + ' target(s)');
}}

// Delete: permanent. Actually removes the target and all of its associated
// data (notes, testing state, pre-testing answers, editor tabs, etc.) — it
// will not come back on reload/resume. (Bug fix: this used to just alias
// Hide, leaving the target in memory and state forever with no way to
// truly get rid of it.)
function confirmDeleteTarget(host) {{
  confirmAction('Delete Target', 'Permanently delete ' + host + '? This cannot be undone — the target and all of its notes and testing data will be removed.', () => {{
    permanentlyDeleteTarget(host);
  }}, 'Delete Forever');
}}

function permanentlyDeleteTarget(host) {{
  const wasOpenInEditor = openEditorTabs.includes(host);
  T = T.filter(t => t.host !== host);
  delete M[host];
  purgedHosts = purgedHosts.filter(h => h !== host);
  purgedHosts.push(host);
  hiddenHosts = hiddenHosts.filter(h => h !== host);
  testingHosts = testingHosts.filter(h => h !== host);
  if (selectedTestingHost === host) selectedTestingHost = testingHosts[0] || null;
  delete notes[host];
  delete activeNote[host];
  delete openFolders[host];
  delete checklistState[host];
  delete customSteps[host];
  delete hiddenSteps[host];
  delete pretestingAnswers[host];
  delete ptOpenSections[host];
  delete openQuestions[host];
  delete sidebarWidths[host];
  delete sidebarCollapsed[host];
  delete sidebarActiveTab[host];
  if (cmInstances[host]) {{ try {{ cmInstances[host].toTextArea(); }} catch(e) {{}} delete cmInstances[host]; }}
  saveState();
  if (wasOpenInEditor) {{
    closeEditorTab(host);
  }} else {{
    renderViewport();
  }}
  showToast('Permanently deleted ' + host);
}}

// ========== MODALS ==========
function openAddModal() {{
  document.getElementById('addModal').classList.add('open');
  setTimeout(() => document.getElementById('newHost').focus(), 100);
}}
function closeModal(id) {{ document.getElementById(id).classList.remove('open'); }}
function addCustomSubdomain() {{
  let host = document.getElementById('newHost').value.trim();
  if (!host) return;
  let url = document.getElementById('newUrl').value.trim() || 'https://' + host;
  if (!M[host]) {{
    let nt = {{ host, url, ip:'-', port:'-', status:0, tech:[], title:'', words:0, cl:0, score:0, priority:'info', cats:['web'], vulns:[], steps: generatePretestingSteps(host, [], 0), desc:'Custom target', ips:[], score_breakdown:{{}} }};
    T.push(nt); M[nt.host] = nt;
  }}
  addToTesting(host);
  closeModal('addModal');
  document.getElementById('newHost').value = '';
  document.getElementById('newUrl').value = '';
}}

let confirmCallback = null;
function confirmAction(title, msg, callback, btnLabel) {{
  document.getElementById('confirmTitle').innerText = title;
  document.getElementById('confirmMsg').innerText = msg;
  document.getElementById('confirmBtn').innerText = btnLabel || 'Delete';
  confirmCallback = callback;
  document.getElementById('confirmModal').classList.add('open');
}}
document.getElementById('confirmBtn').addEventListener('click', () => {{
  closeModal('confirmModal');
  if (confirmCallback) {{ confirmCallback(); confirmCallback = null; }}
}});

// ========== PERSISTENT <domain>.json (File System Access API + IndexedDB) ==========
// Goal: every change in the dashboard silently overwrites a single "<domain>.json"
// file living next to this HTML file — no repeated download dialogs, no growing
// pile of "target (1).json" copies. This uses the File System Access API, which
// is supported in Chrome/Edge/Opera. On unsupported browsers (Firefox/Safari) we
// fall back to a manual "download <domain>.json" action, since those browsers have
// no API for a page to silently overwrite a local file.
const FS_DB_NAME = 'keendash-fs';
const FS_STORE = 'handles';
const FS_KEY = 'target-json-handle';
const fsSupported = ('showSaveFilePicker' in window);
let fileHandle = null;
let pendingHandle = null;
let autosaveTimer = null;

// Compute base domain from first target
function getBaseDomain() {{
  if (T.length === 0) return 'target';
  let host = T[0].host;
  let parts = host.split('.');
  if (parts.length >= 1) {{
    return parts[0];
  }}
  return host;
}}

function openHandleDB() {{
  return new Promise((resolve, reject) => {{
    const req = indexedDB.open(FS_DB_NAME, 1);
    req.onupgradeneeded = () => {{ req.result.createObjectStore(FS_STORE); }};
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }});
}}
async function idbGet(key) {{
  try {{
    const db = await openHandleDB();
    return await new Promise((resolve, reject) => {{
      const tx = db.transaction(FS_STORE, 'readonly');
      const r = tx.objectStore(FS_STORE).get(key);
      r.onsuccess = () => resolve(r.result || null);
      r.onerror = () => reject(r.error);
    }});
  }} catch(e) {{ return null; }}
}}
async function idbSet(key, value) {{
  try {{
    const db = await openHandleDB();
    return await new Promise((resolve, reject) => {{
      const tx = db.transaction(FS_STORE, 'readwrite');
      tx.objectStore(FS_STORE).put(value, key);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    }});
  }} catch(e) {{ return false; }}
}}

function updateSaveIndicator(status, label) {{
  const dot = document.querySelector('#save-status .status-dot');
  const txt = document.getElementById('save-status-label');
  const btnLabel = document.getElementById('save-btn-label');
  if (dot) dot.className = 'status-dot ' + status;
  if (txt) txt.textContent = label;
  if (btnLabel) btnLabel.textContent = fileHandle ? 'Save now' : 'Link ' + getBaseDomain() + '.json';
}}

async function tryRestoreFileHandle() {{
  if (!fsSupported) {{ updateSaveIndicator('gray', 'Autosave needs Chrome/Edge'); return; }}
  const stored = await idbGet(FS_KEY);
  if (!stored) {{ updateSaveIndicator('gray', 'Not linked — click Save'); return; }}
  try {{
    const perm = await stored.queryPermission({{ mode: 'readwrite' }});
    if (perm === 'granted') {{
      fileHandle = stored;
      updateSaveIndicator('green', 'Autosaving to ' + getBaseDomain() + '.json');
    }} else {{
      pendingHandle = stored;
      updateSaveIndicator('yellow', 'Click Save to relink ' + getBaseDomain() + '.json');
    }}
  }} catch(e) {{
    updateSaveIndicator('gray', 'Not linked — click Save');
  }}
}}

async function connectFileHandle() {{
  if (!fsSupported) return false;
  try {{
    if (pendingHandle) {{
      const perm = await pendingHandle.requestPermission({{ mode: 'readwrite' }});
      if (perm === 'granted') {{ fileHandle = pendingHandle; pendingHandle = null; return true; }}
      return false;
    }}
    const handle = await window.showSaveFilePicker({{
      suggestedName: getBaseDomain() + '.json',
      types: [{{ description: 'JSON', accept: {{ 'application/json': ['.json'] }} }}]
    }});
    await idbSet(FS_KEY, handle);
    fileHandle = handle;
    return true;
  }} catch(e) {{
    return false; // user cancelled the picker — not an error
  }}
}}

async function writeStateToDisk(jsonString) {{
  if (!fileHandle) return false;
  try {{
    const writable = await fileHandle.createWritable();
    await writable.write(jsonString);
    await writable.close();
    return true;
  }} catch(e) {{
    console.error('KeenDash: failed writing ' + getBaseDomain() + '.json', e);
    fileHandle = null;
    return false;
  }}
}}

function buildExportData() {{
  // Collect live content from all CodeMirror instances first
  for (let h in cmInstances) {{
    try {{
      let note = getCurrentNote(h);
      if (note) note.content = cmInstances[h].getValue();
    }} catch(e) {{}}
  }}
  return {{
    KeenDash_state: true,
    version: '9.2',
    exportedAt: new Date().toISOString(),
    targets: T,
    state: {{
      hidden: hiddenHosts,
      purged: purgedHosts,
      testing: testingHosts,
      notes: notes,
      activeNote: activeNote,
      openFolders: openFolders,
      checklist: checklistState,
      customSteps: customSteps,
      hiddenSteps: hiddenSteps,
      pretestingAnswers: pretestingAnswers,
      ptOpenSections: ptOpenSections,
      openQuestions: openQuestions,
      sidebarWidths: sidebarWidths,
      sidebarCollapsed: sidebarCollapsed,
      sidebarActiveTab: sidebarActiveTab,
      testingSidebarCollapsed: testingSidebarCollapsed,
      generalNotesContent: generalNotesContent,
      custom: T.filter(t => t.desc === 'Custom target').map(t => ({{host: t.host, url: t.url}}))
    }}
  }};
}}

function downloadFallback(jsonString) {{
  const blob = new Blob([jsonString], {{type: 'application/json'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = getBaseDomain() + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}

// isAuto=true  -> silent background autosave (only writes if already linked)
// isAuto=false -> user clicked Save: link the file if needed, then write
async function saveTargetJSON(isAuto) {{
  const exportData = buildExportData();
  const json = JSON.stringify(exportData, null, 2);

  if (fileHandle) {{
    const ok = await writeStateToDisk(json);
    if (ok) {{
      updateSaveIndicator('green', 'Saved ' + new Date().toLocaleTimeString());
      if (!isAuto) showToast('Saved to ' + getBaseDomain() + '.json');
      return;
    }}
  }}

  if (isAuto) {{
    updateSaveIndicator(fsSupported ? 'yellow' : 'gray', 'Unsaved changes — click Save');
    return;
  }}

  // Manual save with no active handle: try to link one now
  if (fsSupported) {{
    const connected = await connectFileHandle();
    if (connected) {{
      const ok = await writeStateToDisk(json);
      updateSaveIndicator(ok ? 'green' : 'yellow', ok ? 'Saved ' + new Date().toLocaleTimeString() : 'Save failed');
      showToast(ok ? 'Linked & saved ' + getBaseDomain() + '.json' : 'Could not save target.json');
      return;
    }}
  }}

  // Fallback for browsers without the File System Access API (or a cancelled picker)
  downloadFallback(json);
  updateSaveIndicator('yellow', 'Downloaded ' + getBaseDomain() + '.json (manual)');
  showToast('Downloaded ' + getBaseDomain() + '.json — this browser can\\'t autosave silently');
}}

function handleSaveClick() {{ saveTargetJSON(false); }}

function queueAutosave() {{
  clearTimeout(autosaveTimer);
  if (fileHandle) updateSaveIndicator('yellow', 'Saving…');
  autosaveTimer = setTimeout(() => {{ saveTargetJSON(true); }}, 700);
}}

// ========== UTILITIES ==========
function hashCode(str) {{
  let hash = 0;
  for (let i = 0; i < str.length; i++) {{
    const ch = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + ch;
    hash |= 0;
  }}
  return 'h' + Math.abs(hash).toString(36);
}}
function openInNewTab(url) {{ window.open(url, '_blank'); }}

function copyClip(txt) {{
  navigator.clipboard.writeText(txt).then(() => showToast('Copied: ' + txt)).catch(() => showToast('Copy failed'));
}}

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.innerHTML = '<i class="ph ph-check-circle" style="color:var(--success)"></i> ' + msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}}

function escHtml(str) {{ return str ? String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : ''; }}
function escAttr(str) {{
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/'/g,'&#39;').replace(/"/g,'&quot;').replace(/</g,'&#60;').replace(/>/g,'&#62;');
}}

// ========== KEYBOARD SHORTCUTS ==========
document.addEventListener('keydown', e => {{
  if (e.ctrlKey && e.shiftKey && e.key === 'P') {{
    e.preventDefault();
    if (activeView.startsWith('editor-')) {{
      let host = activeView.replace('editor-','');
      setNoteModeByHost(host, 'preview');
    }}
  }}
  if (e.ctrlKey && e.key === 's') {{
    e.preventDefault();
    saveTargetJSON(false);
  }}
  if (e.ctrlKey && e.key === '/') {{
    e.preventDefault();
    showShortcutsModal();
  }}
  if (e.key === 'Escape') {{
    document.querySelectorAll('.mod-bg.open').forEach(m => m.classList.remove('open'));
    closeContextMenu();
  }}
}});

document.querySelectorAll('.mod-bg').forEach(modal => {{
  modal.addEventListener('click', e => {{
    if (e.target === modal) modal.classList.remove('open');
  }});
}});

// Close context menu on click outside
document.addEventListener('click', e => {{
  if (!e.target.closest('#ctx-menu')) closeContextMenu();
}});

// ===== ENHANCEMENT FUNCTIONS =====
function duplicateNote(host) {{
  const note = getCurrentNote(host);
  if (!note) return;
  const id = addNoteItem(host, note.title + ' (copy)', note.content, 'file', note.parentId);
  // Open parent folder if needed
  if (note.parentId) {{
    let open = openFolders[host] || [];
    if (!open.includes(note.parentId)) {{ open.push(note.parentId); openFolders[host] = open; }}
  }}
  saveState();
  renderNotesTree(host);
  selectNote(host, id);
  showToast('Note duplicated');
}}

function exportNote(host) {{
  const note = getCurrentNote(host);
  if (!note) return;
  const blob = new Blob([note.content], {{type:'text/markdown'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = note.title.replace(/[^a-zA-Z0-9_-]/g, '_') + '.md';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Exported ' + a.download);
}}

function showShortcutsModal() {{
  const existing = document.getElementById('shortcutsModal');
  if (existing) {{ existing.classList.remove('open'); return; }}
  const modal = document.createElement('div');
  modal.id = 'shortcutsModal';
  modal.className = 'mod-bg open';
  modal.innerHTML = '<div class="mod" style="width:500px">' +
    '<h3 style="margin-bottom:16px"><i class="ph ph-keyboard" style="margin-right:8px"></i>Keyboard Shortcuts</h3>' +
    '<div style="font-size:13px;color:var(--text-secondary);line-height:2">' +
    '<div style="display:flex;justify-content:space-between"><span><kbd style="background:var(--bg-surface);padding:2px 6px;border-radius:3px;border:1px solid var(--border)">Ctrl+S</kbd></span><span>Save / link target.json</span></div>' +
    '<div style="display:flex;justify-content:space-between"><span><kbd style="background:var(--bg-surface);padding:2px 6px;border-radius:3px;border:1px solid var(--border)">Ctrl+Shift+P</kbd></span><span>Preview mode</span></div>' +
    '<div style="display:flex;justify-content:space-between"><span><kbd style="background:var(--bg-surface);padding:2px 6px;border-radius:3px;border:1px solid var(--border)">Ctrl+/</kbd></span><span>Show shortcuts</span></div>' +
    '<div style="display:flex;justify-content:space-between"><span><kbd style="background:var(--bg-surface);padding:2px 6px;border-radius:3px;border:1px solid var(--border)">Esc</kbd></span><span>Close modals</span></div>' +
    '</div>' +
    '<div class="mod-acts" style="margin-top:16px"><button class="btn-action" id="closeShortcutsBtn">Close</button></div>' +
    '</div>';
  modal.addEventListener('click', e => {{
    if (e.target === modal || e.target.id === 'closeShortcutsBtn') modal.classList.remove('open');
  }});
  document.body.appendChild(modal);
}}

// ========== CLICK HANDLING ==========
// Host name click already opens in new tab via <a> tag.
// We removed the copy-on-click listener, so the link works normally.
// The Copy button still works via data-action="copy-clip".

// Event delegation for target card buttons
document.addEventListener('click', function(e) {{
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const value = btn.dataset.value;
  if (action === 'copy-clip') copyClip(value);
  if (action === 'add-testing') addToTesting(value);
  if (action === 'hide-target') hideTarget(value);
  if (action === 'unhide-target') unhideTarget(value);
  if (action === 'delete-target') confirmDeleteTarget(value);
  if (action === 'select-host') selectTestingHost(value);
  if (action === 'open-editor') openEditorTab(value);
  if (action === 'remove-testing') removeFromTesting(value);
  if (action === 'toggle-sidebar') toggleSidebar(value);
  if (action === 'toggle-detail') {{
    const sd = document.getElementById('sd-'+value);
    if (!sd) return;
    if (sd.classList.contains('open')) {{
      sd.style.maxHeight = sd.scrollHeight + 'px';
      requestAnimationFrame(() => {{
        sd.style.transition = 'max-height 0.35s cubic-bezier(0.4,0,0.2,1), opacity 0.3s ease, margin 0.3s ease, padding 0.3s ease, border-color 0.3s ease';
        sd.style.maxHeight = '0px';
        sd.style.opacity = '0';
        sd.classList.remove('open');
        btn.classList.remove('active');
      }});
    }} else {{
      sd.classList.add('open');
      btn.classList.add('active');
      sd.style.transition = 'none';
      sd.style.maxHeight = '0px';
      sd.style.opacity = '0';
      requestAnimationFrame(() => {{
        sd.style.transition = 'max-height 0.4s cubic-bezier(0.4,0,0.2,1), opacity 0.35s ease, margin 0.3s ease, padding 0.3s ease, border-color 0.3s ease';
        sd.style.maxHeight = sd.scrollHeight + 'px';
        sd.style.opacity = '1';
        setTimeout(() => {{ sd.style.maxHeight = 'none'; }}, 420);
      }});
    }}
  }}
}});

// ========== BOOT ==========
loadInitialState();
renderNav();
renderViewport();
updateNoteCount();
tryRestoreFileHandle();
</script>
</body>
</html>'''
    return html

def main():
    parser = argparse.ArgumentParser(
        prog="keendash.py",
        description="KeenDash — Ultimate Bug Bounty Prioritization Dashboard (v9.2 Obsidian Pro)",
    )
    parser.add_argument(
        "input",
        help="httpx JSON/JSONL file, or a previous KeenDash export (.json/.html) to resume"
    )
    parser.add_argument(
        "-k", "--katana", metavar="FILE",
        help="Optional katana crawl JSONL file (all discovered subdomain URLs) to sharpen scoring"
    )
    parser.add_argument(
        "-n", "--nuclei", metavar="FILE",
        help="Optional nuclei JSONL output (e.g. tls/ssl/tech-detect templates) to sharpen scoring"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Override the state export filename (default: <input>_state.json)"
    )
    args = parser.parse_args()

    inp = args.input
    if not os.path.exists(inp):
        print(f"[!] File not found: {inp}")
        sys.exit(1)
    print(f"[*] Loading {inp} ...")
    targets, saved_state, is_state = load_data(inp)
    if not targets:
        print("[!] No data found.")
        sys.exit(1)

    # Bug fix: permanently-deleted hosts must stay deleted across resumes too,
    # not just be hidden client-side. Drop them from the target list before
    # doing anything else with it.
    if is_state and saved_state:
        purged = set(saved_state.get("purged") or [])
        if purged:
            before = len(targets)
            targets = [t for t in targets if t.get("host") not in purged]
            removed = before - len(targets)
            if removed:
                print(f"[*] Dropped {removed} permanently-deleted host(s) from resumed data")

    katana_map = {}
    if args.katana:
        if os.path.exists(args.katana):
            print(f"[*] Parsing katana crawl data: {args.katana} ...")
            katana_map = parse_katana(args.katana)
            url_count = sum(len(v["urls"]) for v in katana_map.values())
            print(f"[+] Katana: {url_count} URLs across {len(katana_map)} hosts")
        else:
            print(f"[!] Katana file not found, skipping: {args.katana}")

    nuclei_map = {}
    if args.nuclei:
        if os.path.exists(args.nuclei):
            print(f"[*] Parsing nuclei findings: {args.nuclei} ...")
            nuclei_map = parse_nuclei(args.nuclei)
            finding_count = sum(len(v) for v in nuclei_map.values())
            print(f"[+] Nuclei: {finding_count} findings across {len(nuclei_map)} hosts")
        else:
            print(f"[!] Nuclei file not found, skipping: {args.nuclei}")

    if katana_map or nuclei_map:
        targets = enrich_with_recon(targets, katana_map, nuclei_map)
        targets.sort(key=lambda t: t["score"], reverse=True)
        print("[*] Recon data merged — scores and vulnerabilities updated")

    ip_map = build_ip_map(targets)
    print(f"[*] Built {len(targets)} unique targets, {len(ip_map)} IPs")

    # Derive output name: calendly.json -> calendly_state.json
    base = os.path.basename(inp)
    out_base = re.sub(r'(_state)?\.(json|html)$', '', base, flags=re.IGNORECASE)
    out = args.output or (out_base + '_state.json')

    # Export as JSON with KeenDash_state wrapper
    export_data = {
        "KeenDash_state": True,
        "version": "9.2",
        "targets": targets,
        "state": saved_state or {}
    }
    # Ensure essential state keys exist with correct types (bug fix: these used to
    # default to {} even for list/bool fields, which broke resumed dashboards)
    state = export_data["state"]
    # Migrate the legacy 'deleted' (soft-hide) key forward to 'hidden' so older
    # exports keep working with the new Hide/Delete split going forward.
    if "deleted" in state and "hidden" not in state:
        state["hidden"] = state.pop("deleted")
    else:
        state.pop("deleted", None)
    list_keys = ("hidden", "purged", "testing")
    bool_keys = ("testingSidebarCollapsed",)
    for key in ("hidden", "purged", "testing", "notes", "activeNote", "openFolders",
                "checklist", "customSteps", "hiddenSteps", "pretestingAnswers",
                "ptOpenSections", "openQuestions", "sidebarWidths",
                "sidebarCollapsed", "sidebarActiveTab", "testingSidebarCollapsed"):
        if key not in state:
            if key in list_keys:
                state[key] = []
            elif key in bool_keys:
                state[key] = False
            else:
                state[key] = {}

    with open(out, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    size = os.path.getsize(out)
    unit = "KB" if size < 1_000_000 else "MB"
    size_display = f"{size // 1024} {unit}" if unit == "KB" else f"{size / 1_000_000:.1f} {unit}"
    print(f"[+] State saved to {out} ({size_display})")

    # Generate HTML dashboard
    html_out = out_base + '.html'
    html = generate_html(targets, ip_map, saved_state or {}, inp)
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(html)
    html_size = os.path.getsize(html_out)
    html_unit = "KB" if html_size < 1_000_000 else "MB"
    html_size_display = f"{html_size // 1024} {html_unit}" if html_unit == "KB" else f"{html_size / 1_000_000:.1f} {html_unit}"
    print(f"[+] Dashboard generated → {html_out} ({html_size_display})")
    print("\n[*] v9.2 Obsidian Pro — Pre-Testing Intelligence Panel")
    print("    - Categorized pre-testing questions (Ars0n Framework v2 + R-s0n + HackTricks)")
    print("    - Answer fields per question, auto-save on Enter")
    print("    - Collapsible sections, expand/collapse all")
    print("    - Progress tracking with visual bar")
    print("    - Obsidian premium dark theme, Phosphor Icons (CDN)")
    print("    - Notes tree: folders, subfolders, files, inline rename")
    print(f"    - Open {out} in KeenDash to restore your full workspace")
    print("    - In the dashboard, click 'Link <domain>.json' once — every change")
    print("      after that silently autosaves to <domain>.json next to the HTML file")
    print("      (Chrome/Edge only; other browsers fall back to manual downloads)")
    if not args.katana:
        print("    - Tip: add -k katana-file.json to sharpen scoring with crawled URLs")
    if not args.nuclei:
        print("    - Tip: add -n nuclei-file.json to fold in nuclei/TLS findings")

if __name__ == "__main__":
    main()
