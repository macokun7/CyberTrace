# cybertrace.py — CyberTrace with URLhaus/OTX feeds, per-IOC OTX enrichment, CSV export
# Usage:  python .\cybertrace.py
# Deps:   pip install rich dnspython python-whois PyYAML requests

from __future__ import annotations
import os, sys, re, html, json, sqlite3, glob, time, urllib.request, webbrowser
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterable, List, Tuple, Dict, Optional

import yaml, requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.traceback import install as rich_install
rich_install(show_locals=False)

# ──────────────────────────── Constants ────────────────────────────
APP_NAME = "CyberTrace"
DB_DEFAULT = "cybertrace.sqlite3"
REPORT_DEFAULT = "report.html"
SETTINGS_PATH = Path("settings.yaml")
ALLOWED_SUFFIXES = {".log", ".txt", ".json", ".csv"}

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"   # recent URLs (~1–2 days)
OTX_INDICATORS_RECENT = "https://otx.alienvault.com/api/v1/indicators/recent"

console = Console()

# ──────────────────────────── Settings ─────────────────────────────
def load_settings() -> dict:
    if SETTINGS_PATH.exists():
        try:
            data = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}

def save_settings(d: dict) -> None:
    try:
        cur = load_settings()
        cur.update(d)
        SETTINGS_PATH.write_text(yaml.safe_dump(cur, sort_keys=True), encoding="utf-8")
    except Exception as e:
        console.print(f"[yellow]Could not save settings: {e}[/yellow]")

def get_otx_key() -> Optional[str]:
    s = load_settings()
    key = s.get("otx_api_key")
    return key.strip() if isinstance(key, str) and key.strip() else None

# ──────────────────────────── Regexes ──────────────────────────────
IP_RE     = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,24}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

Match = Tuple[str, str, int, str, str]  # (type, value, line_no, file, context)

# ──────────────────────────── File helpers ─────────────────────────
def iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        try:
            if p.is_file() and p.suffix.lower() in ALLOWED_SUFFIXES:
                yield p
        except Exception:
            continue

def _tokenize_inputs(s: str) -> List[str]:
    return [t.strip() for t in re.split(r"[;,]", s or "") if t.strip()]

def gather_files(logs_input: str) -> List[Path]:
    """Accept file, folder, glob, or multiple (separated by ; or ,)."""
    out, seen = [], set()
    for token in _tokenize_inputs(logs_input):
        # glob?
        if any(ch in token for ch in "*?[]"):
            for m in glob.glob(token, recursive=True):
                p = Path(m)
                if p.is_file() and p.suffix.lower() in ALLOWED_SUFFIXES:
                    rp = p.resolve()
                    if rp not in seen: seen.add(rp); out.append(p)
                elif p.is_dir():
                    for f in iter_files(p):
                        rf = f.resolve()
                        if rf not in seen: seen.add(rf); out.append(f)
            continue
        # path
        p = Path(token)
        if p.exists():
            if p.is_file() and p.suffix.lower() in ALLOWED_SUFFIXES:
                rp = p.resolve()
                if rp not in seen: seen.add(rp); out.append(p)
            elif p.is_dir():
                for f in iter_files(p):
                    rf = f.resolve()
                    if rf not in seen: seen.add(rf); out.append(f)
    return out

# ──────────────────────────── Scanning ────────────────────────────
def scan_files(files: List[Path]) -> List[Match]:
    results: List[Match] = []
    for fp in files:
        try:
            with fp.open("r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    s = line.rstrip("\r\n")
                    for m in IP_RE.findall(line):     results.append(("ip",     m.lower(), i, str(fp), s))
                    for m in DOMAIN_RE.findall(line): results.append(("domain", m.lower(), i, str(fp), s))
                    for m in SHA256_RE.findall(line): results.append(("hash",   m.lower(), i, str(fp), s))
        except Exception as e:
            console.print(f"[yellow]Skipped unreadable file {fp}: {e}[/yellow]")
    return results

# ──────────────────────────── Enrichment ──────────────────────────
def days_between(a: datetime, b: datetime) -> int:
    return abs((a - b).days)

def whois_domain(domain: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        import whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list): created = created[0]
        if isinstance(created, datetime):
            created = created.replace(tzinfo=timezone.utc)
            return created.isoformat(), days_between(datetime.now(timezone.utc), created)
    except Exception:
        pass
    return None, None

def dns_lookup(domain: str) -> Tuple[List[str], List[str], List[str]]:
    A = MX = NS = []
    try:
        import dns.resolver
        r = dns.resolver.Resolver(); r.lifetime = 2.0
        try: A  = [x.to_text() for x in r.resolve(domain, "A",  lifetime=2.0)]
        except Exception: A = []
        try: MX = [x.to_text() for x in r.resolve(domain, "MX", lifetime=2.0)]
        except Exception: MX = []
        try: NS = [x.to_text() for x in r.resolve(domain, "NS", lifetime=2.0)]
        except Exception: NS = []
    except Exception:
        pass
    return A, MX, NS

def geo_ip(ip: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,as"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("country"), data.get("as")
    except Exception:
        return None, None

def risk_flags_for_domain(age_days: Optional[int], tld: str, a_count: int) -> List[str]:
    flags: List[str] = []
    if age_days is not None and age_days < 30: flags.append(f"young-domain({age_days}d)")
    if tld.lower() in {"tk","gq","ml","cf","top","xyz","click","work","country","zip","review"}:
        flags.append(f"suspicious-tld(.{tld})")
    if a_count == 0: flags.append("no-a-record")
    return flags

def check_otx_indicator(ioc_type: str, ioc_value: str, api_key: Optional[str]) -> dict:
    """
    Query OTX 'general' endpoint for a single indicator (domain or ip).
    Returns {'pulse_count': int, 'malware_families': [...]} or {}.
    """
    if not api_key:
        return {}
    ptype = "domain" if ioc_type == "domain" else "ip"
    url = f"https://otx.alienvault.com/api/v1/indicators/{ptype}/{ioc_value}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code in (401, 403):
            console.print("[red]OTX unauthorized. Check otx_api_key in settings.yaml[/red]")
            return {}
        if r.status_code == 404:
            return {}
        if r.status_code == 429:
            time.sleep(2)
            r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        pulses = data.get("pulse_info", {}).get("pulses", []) or []
        families = [p.get("name", "") for p in pulses if isinstance(p, dict)]
        return {"pulse_count": len(pulses), "malware_families": [f for f in families if f]}
    except requests.Timeout:
        console.print(f"[yellow]OTX timeout for {ioc_type}:{ioc_value}[/yellow]")
    except Exception as e:
        console.print(f"[yellow]OTX lookup failed for {ioc_type}:{ioc_value}: {e}[/yellow]")
    return {}

# ──────────────────────────── SQLite ──────────────────────────────
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS ioc (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen TEXT,
  sources TEXT,
  tags TEXT,
  UNIQUE(type,value)
);
CREATE TABLE IF NOT EXISTS enrichment (
  ioc_id INTEGER PRIMARY KEY,
  whois_created TEXT,
  domain_age_days INTEGER,
  dns_a TEXT, dns_mx TEXT, dns_ns TEXT,
  country TEXT, asn TEXT,
  risk_flags TEXT,
  FOREIGN KEY(ioc_id) REFERENCES ioc(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sightings (
  id INTEGER PRIMARY KEY,
  ioc_id INTEGER NOT NULL,
  file TEXT NOT NULL,
  line_no INTEGER NOT NULL,
  context TEXT,
  FOREIGN KEY(ioc_id) REFERENCES ioc(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ioc_type  ON ioc(type);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc(value);
"""

def db_init(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(SCHEMA)
    return conn

def db_upsert_ioc(conn: sqlite3.Connection, t: str, v: str,
                  first_seen: Optional[str]=None, src: Optional[str]="logs", tags: Optional[str]=None) -> int:
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO ioc (type,value,first_seen,sources,tags)
      VALUES (?,?,?,?,?)
      ON CONFLICT(type,value) DO UPDATE SET
        first_seen = COALESCE(excluded.first_seen, ioc.first_seen),
        sources = CASE
          WHEN IFNULL(ioc.sources,'')='' THEN excluded.sources
          WHEN IFNULL(excluded.sources,'')='' THEN ioc.sources
          WHEN instr(ioc.sources,excluded.sources)=0 THEN ioc.sources||','||excluded.sources
          ELSE ioc.sources END,
        tags = CASE
          WHEN IFNULL(ioc.tags,'')='' THEN excluded.tags
          WHEN IFNULL(excluded.tags,'')='' THEN ioc.tags
          WHEN instr(ioc.tags,excluded.tags)=0 THEN ioc.tags||','||excluded.tags
          ELSE ioc.tags END
    """, (t, v, first_seen, src, tags))
    conn.commit()
    cur.execute("SELECT id FROM ioc WHERE type=? AND value=?", (t, v))
    return cur.fetchone()[0]

def db_upsert_enrichment(conn: sqlite3.Connection, ioc_id: int, fields: Dict[str, str|int]) -> None:
    if not fields: return
    cols    = ",".join(fields.keys())
    qs      = ",".join(["?"]*len(fields))
    updates = ",".join([f"{k}=excluded.{k}" for k in fields.keys()])
    sql = f"INSERT INTO enrichment (ioc_id,{cols}) VALUES (?,{qs}) ON CONFLICT(ioc_id) DO UPDATE SET {updates}"
    conn.execute(sql, (ioc_id, *fields.values())); conn.commit()

def db_insert_sighting(conn: sqlite3.Connection, ioc_id: int, file: str, line_no: int, ctx: str) -> None:
    conn.execute("INSERT INTO sightings (ioc_id,file,line_no,context) VALUES (?,?,?,?)", (ioc_id, file, line_no, ctx))
    conn.commit()

def db_export(conn: sqlite3.Connection):
    cur = conn.cursor()
    totals = dict(cur.execute("""
      SELECT 'total',COUNT(*) FROM ioc
      UNION ALL SELECT 'ip',COUNT(*) FROM ioc WHERE type='ip'
      UNION ALL SELECT 'domain',COUNT(*) FROM ioc WHERE type='domain'
      UNION ALL SELECT 'hash',COUNT(*) FROM ioc WHERE type='hash'
    """).fetchall())
    high_risk = cur.execute("""
      SELECT i.type,i.value,i.first_seen,IFNULL(e.risk_flags,''),IFNULL(i.sources,'')
      FROM ioc i LEFT JOIN enrichment e ON e.ioc_id=i.id
      WHERE e.risk_flags IS NOT NULL AND e.risk_flags <> ''
      ORDER BY LENGTH(e.risk_flags) DESC LIMIT 200
    """).fetchall()
    sightings = cur.execute("""
      SELECT i.value,i.type,IFNULL(i.sources,''),s.file,s.line_no,s.context
      FROM sightings s JOIN ioc i ON s.ioc_id=i.id
      ORDER BY s.id DESC LIMIT 1000
    """).fetchall()
    feed_corr = cur.execute("""
      SELECT i.type,i.value,IFNULL(i.sources,''),IFNULL(e.risk_flags,'')
      FROM ioc i LEFT JOIN enrichment e ON e.ioc_id=i.id
      WHERE i.sources LIKE '%logs%' AND (i.sources LIKE '%urlhaus%' OR i.sources LIKE '%otx%')
      ORDER BY i.type, i.value LIMIT 300
    """).fetchall()
    return totals, high_risk, sightings, feed_corr

# ──────────────────────────── CSV Export ───────────────────────────
def export_csv(conn: sqlite3.Connection, out_path: str):
    try:
        import csv
        cur = conn.cursor()
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["table","type","value","first_seen","sources","tags","file","line_no","context"])
            for t,v,fs,src,tags in cur.execute("SELECT type,value,first_seen,IFNULL(sources,''),IFNULL(tags,'') FROM ioc"):
                w.writerow(["ioc", t, v, fs or "", src, tags or "", "", "", ""])
            for v,t,src,fp,ln,ctx in cur.execute("""
                SELECT i.value,i.type,IFNULL(i.sources,''),s.file,s.line_no,s.context
                FROM sightings s JOIN ioc i ON s.ioc_id=i.id ORDER BY s.id
            """):
                w.writerow(["sighting", t, v, "", src, "", fp, ln, ctx])
        console.print(f"[green]CSV exported to {Path(out_path).resolve()}[/green]")
    except Exception as e:
        console.print(f"[red]CSV export failed: {e}[/red]")

# ──────────────────────────── Report ───────────────────────────────
def write_report(html_path: str, db_path: str, totals, high_risk, sightings, feed_corr) -> None:
    def esc(x: str) -> str: return html.escape(x or "")

    def table(rows: List[str], header: str) -> str:
        if not rows:
            return "<p>No data.</p>"
        return f"<table class='tbl'><thead>{header}</thead><tbody>{''.join(rows)}</tbody></table>"

    rows_hr = [
        f"<tr><td>{esc(t)}</td><td><code>{esc(v)}</code></td><td>{esc(fs)}</td>"
        f"<td class='flags'>{esc(rf)}</td><td>{esc(src)}</td></tr>"
        for (t,v,fs,rf,src) in high_risk
    ]
    rows_s = [
        f"<tr><td><code>{esc(v)}</code></td><td>{esc(t)}</td><td>{esc(src)}</td>"
        f"<td>{esc(f)}</td><td>{ln}</td><td><pre style='margin:0;white-space:pre-wrap'>{esc(ctx)}</pre></td></tr>"
        for (v,t,src,f,ln,ctx) in sightings
    ]
    rows_fc = [
        f"<tr><td>{esc(t)}</td><td><code>{esc(v)}</code></td><td>{esc(src)}</td><td class='flags'>{esc(rf)}</td></tr>"
        for (t,v,src,rf) in feed_corr
    ]

    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{APP_NAME} Report</title>
<meta http-equiv="refresh" content="10">
<style>
body{{font-family:Segoe UI, Roboto, sans-serif;margin:1.5rem}}
.tbl{{border-collapse:collapse;width:100%;margin:.6rem 0}}
.tbl th,.tbl td{{border:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
.tbl th{{background:#f0f0f0}}
code{{background:#f7f7f7;padding:2px 4px;border-radius:3px}}
.flags{{color:#a40000}}
.summary span{{display:inline-block;margin-right:1rem}}
small{{opacity:.7}}
</style></head><body>
<h1>{APP_NAME} — Threat Intel Report</h1>
<div class="summary">
  <span><b>Total IOCs:</b> {totals.get('total',0)}</span>
  <span><b>IPs:</b> {totals.get('ip',0)}</span>
  <span><b>Domains:</b> {totals.get('domain',0)}</span>
  <span><b>Hashes:</b> {totals.get('hash',0)}</span>
  <span><b>DB:</b> {html.escape(str(Path(db_path).resolve()))}</span>
</div>

<h2>High-Risk IOCs</h2>
{table(rows_hr, "<tr><th>Type</th><th>Value</th><th>First Seen</th><th>Risk Flags</th><th>Sources</th></tr>")}

<h2>Feed Correlations (in logs & in feeds)</h2>
{table(rows_fc, "<tr><th>Type</th><th>Value</th><th>Sources</th><th>Risk Flags</th></tr>")}

<h2>Latest Sightings</h2>
{table(rows_s, "<tr><th>IOC</th><th>Type</th><th>Sources</th><th>File</th><th>Line</th><th>Context</th></tr>")}

<small>Tip: report auto-refreshes every 10s. ‘Sources’ shows where an IOC came from (e.g., logs,urlhaus,otx).</small>
</body></html>"""
    Path(html_path).write_text(doc, encoding="utf-8")

def open_report(report_path: str):
    url = f"file://{Path(report_path).resolve()}"
    ok = webbrowser.open(url)
    if ok: return
    try:
        if sys.platform.startswith("win"):
            os.startfile(report_path)  # type: ignore[attr-defined]
        else:
            import subprocess
            subprocess.Popen(["xdg-open", url])
    except Exception as e:
        console.print(f"[yellow]Could not auto-open browser: {e}[/yellow]")
        console.print(f"Open manually: {url}")

# ──────────────────────────── Feeds ────────────────────────────────
def ingest_iocs(conn: sqlite3.Connection, items: List[Tuple[str,str,str]]) -> int:
    """items: list of (type, value, source_label)"""
    if not items: return 0
    count = 0
    for t, v, src in items:
        try:
            db_upsert_ioc(conn, t, v, src=src)
            count += 1
        except Exception:
            continue
    conn.commit()
    return count

def fetch_urlhaus() -> List[Tuple[str,str,str]]:
    """Return (type,value,'urlhaus') from recent URLhaus CSV (domains extracted from URLs)."""
    try:
        r = requests.get(URLHAUS_CSV, timeout=15)
        r.raise_for_status()
        lines = r.text.splitlines()
        out: List[Tuple[str,str,str]] = []
        from urllib.parse import urlparse
        for line in lines:
            if not line or line.startswith("#"):  # comments/header
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                url = parts[1].strip().strip('"')
                netloc = urlparse(url).netloc
                if netloc:
                    domain = netloc.split("@")[-1].split(":")[0].lower()
                    if DOMAIN_RE.search(domain):
                        out.append(("domain", domain, "urlhaus"))
        return out
    except Exception as e:
        console.print(f"[yellow]URLhaus fetch failed: {e}[/yellow]")
        return []

def fetch_otx_recent(api_key: Optional[str]) -> List[Tuple[str,str,str]]:
    """Return recent indicators from OTX (needs API key) mapped to (type,value,'otx')."""
    if not api_key:
        console.print("[yellow]OTX API key not set (settings.yaml → otx_api_key). Skipping.[/yellow]")
        return []
    try:
        r = requests.get(OTX_INDICATORS_RECENT, headers={"X-OTX-API-KEY": api_key}, timeout=15)
        if r.status_code == 401:
            console.print("[red]OTX: unauthorized (check API key).[/red]")
            return []
        r.raise_for_status()
        data = r.json()
        out: List[Tuple[str,str,str]] = []
        for ind in data.get("results", []):
            ind_type = (ind.get("type") or "").lower()
            val = (ind.get("indicator") or "").strip()
            if not val: continue
            if ind_type in {"domain", "hostname"} and DOMAIN_RE.search(val):
                out.append(("domain", val.lower(), "otx"))
            elif ind_type in {"ipv4", "ip"} and IP_RE.search(val):
                out.append(("ip", val.lower(), "otx"))
            elif ind_type in {"filehash-sha256", "sha256"} and SHA256_RE.search(val):
                out.append(("hash", val.lower(), "otx"))
        return out
    except Exception as e:
        console.print(f"[yellow]OTX fetch failed: {e}[/yellow]")
        return []

# ──────────────────────────── Pipeline ─────────────────────────────
def run_pipeline(logs_input: str, db_path: str, report_path: str, auto_open: bool):
    console.print(Panel.fit(f"[bold]{APP_NAME}[/bold]\nScan → Enrich → Store → Report",
                            title="Pipeline", border_style="cyan"))

    if not get_otx_key():
        console.print("[yellow]Tip: add 'otx_api_key' to settings.yaml to enable OTX per-IOC enrichment.[/yellow]")

    files = gather_files(logs_input)
    if not files:
        console.print(f"[red]No matching files.[/red] "
                      f"Try a glob like [cyan]{Path(logs_input)}\\*.txt[/cyan] or [cyan]...\\*.log[/cyan], "
                      "or provide multiple paths separated by ';'.")
        return

    console.print(f"[blue]Scanning {len(files)} file(s).[/blue]")

    # Scan
    matches = scan_files(files)
    ips    = sorted({v for (k,v,_,_,_) in matches if k == "ip"})
    doms   = sorted({v for (k,v,_,_,_) in matches if k == "domain"})
    hashes = sorted({v for (k,v,_,_,_) in matches if k == "hash"})
    console.print(f"[green]✓[/green] Scanned {len(matches)} hits | unique: IPs={len(ips)} domains={len(doms)} hashes={len(hashes)}")

    # Enrich (WHOIS/DNS/Geo)
    enrich: Dict[Tuple[str,str], Dict[str,str|int|None]] = {}
    for d in doms:
        created, age = whois_domain(d)
        A, MX, NS = dns_lookup(d)
        flags = risk_flags_for_domain(age, d.split(".")[-1] if "." in d else "", len(A))
        enrich[("domain", d)] = {
            "whois_created": created, "domain_age_days": age,
            "dns_a": ",".join(A) if A else None,
            "dns_mx": ",".join(MX) if MX else None,
            "dns_ns": ",".join(NS) if NS else None,
            "risk_flags": ",".join(flags) if flags else None
        }
    for ip in ips:
        country, asn = geo_ip(ip)
        enrich[("ip", ip)] = {"country": country, "asn": asn}

    # Per-IOC OTX lookups (cap to keep it fast)
    otx_key = get_otx_key()
    MAX_OTX = 60
    if otx_key:
        console.print(f"[blue]OTX: checking up to {min(len(doms),MAX_OTX)+min(len(ips),MAX_OTX)} indicator(s)...[/blue]")
        for d in doms[:MAX_OTX]:
            info = check_otx_indicator("domain", d, otx_key)
            if info.get("pulse_count", 0) > 0:
                row = enrich.get(("domain", d), {})
                flags_now = set((row.get("risk_flags") or "").split(",")) if row.get("risk_flags") else set()
                flags_now.add(f"otx-pulses:{info['pulse_count']}")
                row["risk_flags"] = ",".join(sorted(f for f in flags_now if f))
                fams = info.get("malware_families", [])
                if fams: row["tags"] = ",".join(sorted(set(fams)))[:200]
                enrich[("domain", d)] = row
        for ip in ips[:MAX_OTX]:
            info = check_otx_indicator("ip", ip, otx_key)
            if info.get("pulse_count", 0) > 0:
                row = enrich.get(("ip", ip), {})
                flags_now = set((row.get("risk_flags") or "").split(",")) if row.get("risk_flags") else set()
                flags_now.add(f"otx-pulses:{info['pulse_count']}")
                row["risk_flags"] = ",".join(sorted(f for f in flags_now if f))
                enrich[("ip", ip)] = row

    # DB
    try:
        conn = db_init(db_path)

        # label this run’s logs source
        src_label = f"logs:{Path(str(logs_input)).name if Path(str(logs_input)).exists() else 'glob'}"
        idmap: Dict[Tuple[str,str], int] = {}
        for v in ips:    idmap[("ip", v)]     = db_upsert_ioc(conn, "ip",     v, src=src_label)
        for v in doms:   idmap[("domain", v)] = db_upsert_ioc(conn, "domain", v, src=src_label)
        for v in hashes: idmap[("hash", v)]   = db_upsert_ioc(conn, "hash",   v, src="logs")

        for (t,v), fields in enrich.items():
            fields_clean = {k:val for k,val in fields.items() if val not in (None, "") and k != "tags"}
            db_upsert_enrichment(conn, idmap[(t,v)], fields_clean)
            # tag OTX hits in sources
            if "otx-pulses:" in (fields.get("risk_flags") or ""):
                db_upsert_ioc(conn, t, v, src="otx")
            # optional: store tags from OTX families
            if fields.get("tags"):
                db_upsert_ioc(conn, t, v, tags=str(fields["tags"]))

        for (t,v,ln,fp,ctx) in matches:
            db_insert_sighting(conn, idmap[(t,v)], fp, ln, ctx)

        console.print(f"[green]✓[/green] Saved to DB: {Path(db_path).resolve()}")
    except Exception as e:
        console.print(f"[red]Database error:[/red] {e}")
        return

    # Report
    try:
        totals, high_risk, sightings, feed_corr = db_export(conn)
        write_report(report_path, db_path, totals, high_risk, sightings, feed_corr)
        console.print(f"[green]✓[/green] Report: {Path(report_path).resolve()}")
    except Exception as e:
        console.print(f"[red]Failed to write report:[/red] {e}")
        return

    if auto_open and Confirm.ask("Open report in your browser now?", default=True):
        open_report(report_path)

# ──────────────────────────── Watch mode ───────────────────────────
def _snapshot(files: List[Path]) -> tuple:
    try:
        return tuple(sorted((str(p), p.stat().st_mtime, p.stat().st_size) for p in files if p.exists()))
    except Exception:
        return tuple()

def watch_and_run(logs_input: str, db_path: str, report_path: str, auto_open: bool, interval: int = 5):
    console.print(Panel.fit("Watching for changes… (Ctrl+C to stop)", border_style="magenta"))
    files = gather_files(logs_input)
    if not files:
        console.print("[red]Nothing to watch — no matching files.[/red]")
        return
    last = _snapshot(files)
    try:
        while True:
            time.sleep(interval)
            files = gather_files(logs_input)
            snap = _snapshot(files)
            if snap != last:
                console.print("[yellow]Change detected — re-running pipeline…[/yellow]")
                run_pipeline(logs_input, db_path, report_path, auto_open)
                last = snap
    except KeyboardInterrupt:
        console.print("\n[green]Stopped watching.[/green]")

# ──────────────────────────── Menu ─────────────────────────────────
def main_menu():
    s = load_settings()
    logs_path   = s.get("logs_path", "sample_logs" if Path("sample_logs").exists() else ".")
    db_path     = s.get("db_path", DB_DEFAULT)
    report_path = s.get("report_path", REPORT_DEFAULT)
    auto_open   = bool(s.get("auto_open", True))
    otx_key     = s.get("otx_api_key")

    console.print(Panel.fit(f"{APP_NAME}", border_style="cyan"))
    while True:
        console.print("\n[bold]Choose an action:[/bold]")
        console.print(f"  [1] Run full pipeline (logs: [cyan]{logs_path}[/cyan])")
        console.print(f"  [2] Change logs location (file/folder/glob or multiple with ;)")
        console.print(f"  [3] Change DB path      (now: [cyan]{db_path}[/cyan])")
        console.print(f"  [4] Change report path  (now: [cyan]{report_path}[/cyan])")
        console.print(f"  [5] Toggle auto-open report (now: [cyan]{'ON' if auto_open else 'OFF'}[/cyan])")
        console.print(f"  [6] Open last report (if exists)")
        console.print(f"  [7] Reset DB (delete file) — careful")
        console.print(f"  [8] One-off analyze different path(s)")
        console.print(f"  [9] Watch current logs for changes")
        console.print(f" [10] Pull URLhaus recent IOCs and merge")
        console.print(f" [11] Pull OTX recent IOCs and merge (API key {'set' if otx_key else 'missing'})")
        console.print(f" [12] Export CSV (IOCs & Sightings)")
        console.print(f"  [0] Exit")

        choice = Prompt.ask("> ", choices=[str(i) for i in range(13)], default="1")

        if choice == "1":
            console.print("[blue]Starting pipeline...[/blue]")
            try:
                run_pipeline(logs_path, db_path, report_path, auto_open)
                console.print("[green]Pipeline finished.[/green]")
            except Exception as e:
                console.print(f"[red]Pipeline crashed: {e}[/red]")

        elif choice == "2":
            newp = Prompt.ask("Enter file/folder/glob or multiple separated by ';'", default=logs_path).strip()
            if not newp:
                console.print("[yellow]No input provided.[/yellow]")
            else:
                files = gather_files(newp)
                if not files:
                    console.print("[red]No matching files. Try a glob like *.txt or *.log[/red]")
                else:
                    logs_path = newp
                    save_settings({"logs_path": logs_path})
                    console.print(f"[green]Saved new logs path.[/green] Found {len(files)} file(s).")

        elif choice == "3":
            db_path = Prompt.ask("Enter SQLite DB path", default=db_path).strip()
            save_settings({"db_path": db_path})

        elif choice == "4":
            report_path = Prompt.ask("Enter report HTML path", default=report_path).strip()
            save_settings({"report_path": report_path})

        elif choice == "5":
            auto_open = not auto_open
            console.print(f"[green]Auto-open is now {'ON' if auto_open else 'OFF'}[/green]")
            save_settings({"auto_open": auto_open})

        elif choice == "6":
            if Path(report_path).exists():
                open_report(report_path)
            else:
                console.print("[yellow]No report found yet.[/yellow]")

        elif choice == "7":
            if Confirm.ask(f"Delete {db_path}?", default=False):
                try:
                    Path(db_path).unlink(missing_ok=True)
                    console.print("[green]DB removed.[/green]")
                except Exception as e:
                    console.print(f"[red]Failed: {e}[/red]")

        elif choice == "8":
            temp = Prompt.ask("Enter file/folder/glob or multiple separated by ';'").strip()
            if not temp:
                console.print("[yellow]No input given.[/yellow]")
            else:
                files = gather_files(temp)
                if not files:
                    console.print("[red]No matching files for that input.[/red]")
                else:
                    run_pipeline(temp, db_path, report_path, auto_open)
                    if Confirm.ask("Use this as your new default logs path?", default=False):
                        logs_path = temp
                        save_settings({"logs_path": logs_path})
                        console.print("[green]Default logs path updated.[/green]")

        elif choice == "9":
            if not gather_files(logs_path):
                console.print("[red]No matching files in current logs setting. Use option 2 first.[/red]")
            else:
                watch_and_run(logs_path, db_path, report_path, auto_open, interval=5)

        elif choice == "10":
            conn = db_init(db_path)
            console.print("[blue]Fetching URLhaus recent…[/blue]")
            items = fetch_urlhaus()
            if not items:
                console.print("[yellow]No URLhaus items ingested.[/yellow]")
            else:
                n = ingest_iocs(conn, items)
                console.print(f"[green]Ingested {n} URLhaus domain(s).[/green]")
                totals, high_risk, sightings, feed_corr = db_export(conn)
                write_report(report_path, db_path, totals, high_risk, sightings, feed_corr)
                if Confirm.ask("Open report to view correlations?", default=True):
                    open_report(report_path)

        elif choice == "11":
            if not otx_key:
                if Confirm.ask("Set OTX API key now?", default=True):
                    otx_key = Prompt.ask("Enter OTX API key").strip()
                    save_settings({"otx_api_key": otx_key})
            conn = db_init(db_path)
            console.print("[blue]Fetching OTX recent…[/blue]")
            items = fetch_otx_recent(otx_key)
            if not items:
                console.print("[yellow]No OTX items ingested.[/yellow]")
            else:
                n = ingest_iocs(conn, items)
                console.print(f"[green]Ingested {n} OTX indicator(s).[/green]")
                totals, high_risk, sightings, feed_corr = db_export(conn)
                write_report(report_path, db_path, totals, high_risk, sightings, feed_corr)
                if Confirm.ask("Open report to view correlations?", default=True):
                    open_report(report_path)

        elif choice == "12":
            conn = db_init(db_path)
            dest = Prompt.ask("CSV output path", default="cybertrace_export.csv").strip()
            export_csv(conn, dest)

        elif choice == "0":
            console.print("Bye!")
            break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\nExiting…")
