from __future__ import annotations
import ipaddress, json, re, socket, time
from datetime import datetime, timezone
from email.utils import parseaddr
from urllib.parse import quote, urlparse
import requests

TIMEOUT = 8
UA = {"User-Agent": "OpenOSINT-AI-Research/1.0 (public-data research; contact: project-maintainer)"}

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def result(module, status, **data): return {"module": module, "status": status, "timestamp_utc": now(), **data}
def safe_get(url, headers=None, timeout=TIMEOUT):
    try:
        r = requests.get(url, headers={**UA, **(headers or {})}, timeout=timeout, allow_redirects=True)
        return {"http_status": r.status_code, "final_url": r.url, "content_type": r.headers.get("content-type"), "text": r.text[:30000], "headers": dict(list(r.headers.items())[:30])}
    except requests.RequestException as e:
        return {"error": f"{type(e).__name__}: {e}"}

def check_email(email, check_breach=False):
    email = (email or "").strip()
    _, parsed = parseaddr(email)
    valid = bool(parsed == email and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))
    out = result("email", "completed", input=email, syntax_valid=valid,
                 interpretation="Syntax only; does not verify mailbox existence or ownership.", sources=[])
    if not valid: return out
    domain = email.rsplit("@", 1)[1].lower()
    try:
        out["domain_mx_or_dns"] = {"domain": domain, "addresses": sorted(set(x[4][0] for x in socket.getaddrinfo(domain, None)))[:10]}
    except Exception as e: out["domain_mx_or_dns"] = {"domain": domain, "error": str(e)}
    if check_breach:
        try:
            import streamlit as st
            key = st.secrets.get("HIBP_API_KEY", "")
        except Exception: key = ""
        if not key:
            out["hibp"] = {"status": "not_run", "reason": "HIBP_API_KEY not configured; service may require eligible API access."}
        else:
            try:
                resp = requests.get("https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(email, safe=""),
                    headers={"hibp-api-key": key, "user-agent": "OpenOSINT-AI"}, params={"truncateResponse":"false"}, timeout=TIMEOUT)
                if resp.status_code == 200: out["hibp"] = {"status":"matches_returned", "breaches":resp.json()}
                elif resp.status_code == 404: out["hibp"] = {"status":"no_breaches_returned", "note":"Only means this endpoint returned no breach records; not proof of account safety."}
                else: out["hibp"] = {"status":"inconclusive", "http_status":resp.status_code, "message":resp.text[:500]}
            except Exception as e: out["hibp"] = {"status":"error", "message":str(e)}
    return out

SERVICES = {
    "GitHub": "https://github.com/{u}", "GitLab":"https://gitlab.com/{u}",
    "Reddit":"https://www.reddit.com/user/{u}/", "Dev.to":"https://dev.to/{u}",
    "Medium":"https://medium.com/@{u}", "Hacker News":"https://news.ycombinator.com/user?id={u}"
}
def check_username(username, services):
    u = (username or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,39}", u):
        return result("username", "invalid_input", input=username, error="Use 1–39 letters, digits, dots, underscores or hyphens.")
    findings=[]
    for name in services:
        template=SERVICES.get(name)
        if not template: continue
        url=template.format(u=quote(u, safe=""))
        data=safe_get(url, timeout=6)
        code=data.get("http_status")
        if code == 200: signal="page_reachable"
        elif code == 404: signal="not_found_signal"
        elif code in (403, 429): signal="blocked_or_rate_limited_inconclusive"
        elif data.get("error"): signal="request_error_inconclusive"
        else: signal="unknown_inconclusive"
        findings.append({"service":name,"url":url,"signal":signal,"http_status":code,"error":data.get("error"),"final_url":data.get("final_url")})
        time.sleep(0.15)
    return result("username", "completed", input=u, checks=findings,
        interpretation="Signals are based on HTTP responses only; no identity or account ownership is established.")

def normalize_domain(value):
    v=(value or "").strip().lower()
    if "://" in v: v=urlparse(v).hostname or ""
    v=v.split("/")[0].split(":")[0].rstrip(".")
    if not v or len(v)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$", v): return None
    return v

def domain_intel(value):
    domain=normalize_domain(value)
    if not domain: return result("domain", "invalid_input", input=value, error="Enter a valid public domain such as example.com.")
    out=result("domain","completed",input=domain,sources=[f"https://rdap.org/domain/{domain}"])
    try:
        infos=socket.getaddrinfo(domain, None)
        out["dns"]={"addresses":sorted(set(x[4][0] for x in infos))}
    except Exception as e: out["dns"]={"error":str(e)}
    rdap=safe_get(f"https://rdap.org/domain/{quote(domain)}")
    if rdap.get("http_status")==200:
        try:
            j=json.loads(rdap["text"])
            out["rdap"]={k:j.get(k) for k in ("ldhName","handle","status","events","nameservers","secureDNS") if k in j}
        except Exception: out["rdap"]={"http_status":200,"parse_error":"Invalid JSON"}
    else: out["rdap"]={k:v for k,v in rdap.items() if k in ("http_status","error","final_url")}
    for scheme in ("https","http"):
        url=f"{scheme}://{domain}"
        h=safe_get(url, timeout=6)
        out.setdefault("http_checks",[]).append({"url":url,"http_status":h.get("http_status"),"final_url":h.get("final_url"),"headers":h.get("headers",{}),"error":h.get("error")})
        if h.get("http_status"): break
    return out

def ip_intel(value):
    raw=(value or "").strip()
    try: addr=ipaddress.ip_address(raw)
    except ValueError: return result("ip", "invalid_input", input=raw, error="Invalid IPv4/IPv6 address.")
    if not addr.is_global:
        return result("ip", "completed", input=raw, is_global=False, interpretation="Private, loopback, reserved or otherwise non-global IP; public geolocation was not queried.")
    data=safe_get(f"https://ipwho.is/{quote(raw)}")
    if data.get("http_status")==200:
        try:
            j=json.loads(data["text"])
            fields=("success","type","continent","country","region","city","latitude","longitude","connection","timezone")
            return result("ip","completed",input=raw,is_global=True,provider="ipwho.is",metadata={k:j.get(k) for k in fields if k in j},interpretation="Approximate IP/network geolocation, not a person's precise physical location.")
        except Exception: pass
    return result("ip","inconclusive",input=raw,is_global=True,provider_response={k:v for k,v in data.items() if k in ("http_status","error","final_url")})

def web_search(query):
    q=(query or "").strip()
    if not q or len(q)>300: return result("web_search","invalid_input",input=q,error="Enter a query of 1–300 characters.")
    out=result("web_search","completed",input=q,results=[],notes=[])
    # Prefer a configured Google Custom Search integration; never scrape Google result pages.
    try:
        import streamlit as st
        cse_key=st.secrets.get("GOOGLE_CSE_API_KEY", "")
        cse_id=st.secrets.get("GOOGLE_CSE_ID", "")
    except Exception: cse_key=cse_id=""
    if cse_key and cse_id:
        try:
            r=requests.get("https://www.googleapis.com/customsearch/v1",params={"key":cse_key,"cx":cse_id,"q":q,"num":10},timeout=TIMEOUT)
            if r.status_code==200:
                data=r.json(); out["provider"]="Google Programmable Search"; out["results"]=[{"title":x.get("title"),"url":x.get("link"),"snippet":x.get("snippet")} for x in data.get("items",[])]; return out
            out["notes"].append({"provider":"Google Programmable Search","http_status":r.status_code,"message":r.text[:300],"meaning":"Google API failure; trying fallback."})
        except Exception as e: out["notes"].append({"provider":"Google Programmable Search","error":str(e)})
    try:
        from ddgs import DDGS
        with DDGS() as ddgs: items=list(ddgs.text(q, max_results=8))
        out["provider"]="DuckDuckGo search library fallback"
        out["results"]=[{"title":x.get("title"),"url":x.get("href"),"snippet":x.get("body")} for x in items]
        if not items: out["notes"].append("No results returned; this is not proof that no public information exists.")
    except Exception as e:
        out["status"]="provider_error"; out["error"]=f"Search fallback unavailable: {type(e).__name__}: {e}"
        out["notes"].append("Search can fail due to provider blocking, network limits, or API quotas. Retry later or configure Google CSE.")
    return out

def image_metadata(raw, filename):
    out=result("image","completed",filename=filename,bytes=len(raw),exif={})
    try:
        from PIL import Image, ExifTags
        import io
        img=Image.open(io.BytesIO(raw)); out["format"]=img.format; out["dimensions"]={"width":img.width,"height":img.height}
        exif=img.getexif(); decoded={ExifTags.TAGS.get(k,str(k)):str(v)[:500] for k,v in exif.items()}
        out["exif"]={k:v for k,v in decoded.items() if k in ("Make","Model","DateTime","DateTimeOriginal","Software","GPSInfo","Orientation")}
        gps=exif.get(34853)
        if gps:
            out["gps_metadata_present"]=True
            out["gps_note"]="GPS tag exists; use a dedicated EXIF/GPS parser to decode rational coordinates. Metadata can be edited and does not prove where a photo was taken."
        else: out["gps_metadata_present"]=False
    except Exception as e: out["metadata_error"]=str(e)
    return out

def image_caption_hf(raw, content_type):
    try:
        import streamlit as st
        token=st.secrets.get("HF_TOKEN", "")
    except Exception: token=""
    if not token: return {"status":"not_run","reason":"HF_TOKEN is not configured."}
    # Hugging Face router API: model availability and access can vary.
    url="https://router.huggingface.co/hf-inference/models/Salesforce/blip-image-captioning-base"
    try:
        r=requests.post(url,headers={"Authorization":f"Bearer {token}","Content-Type":content_type},data=raw,timeout=30)
        if r.status_code==200: return {"status":"completed","provider":"Hugging Face Inference","caption_response":r.json()}
        return {"status":"inconclusive","http_status":r.status_code,"message":r.text[:500]}
    except Exception as e: return {"status":"error","message":str(e)}

def build_report(results):
    lines=["# OpenOSINT AI — Evidence Report", "", f"Generated (UTC): {now()}", "", "> Scope: public-data research. AI interpretation is not primary evidence.", ""]
    if not results: lines.append("No module results collected.")
    for name,data in results.items():
        lines += [f"## {name.replace('_',' ').title()}", "", "```json", json.dumps(data, indent=2, ensure_ascii=False), "```", ""]
    lines += ["## Limitations", "", "HTTP signals do not prove identity or ownership. Third-party results can be stale, blocked, incomplete, or rate-limited. IP location is approximate. Image captions and EXIF are not proof of exact location. Verify claims directly at sources."]
    return "\n".join(lines)
