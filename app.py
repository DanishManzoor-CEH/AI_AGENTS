from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import streamlit as st
from osint_tools import (check_email, check_username, domain_intel, ip_intel, web_search,
                         image_metadata, image_caption_hf, build_report)
from crew_agents import run_crew_analysis

st.set_page_config(page_title="OpenOSINT AI | Multi-Agent OSINT", page_icon="🛰️", layout="wide")
st.title("🛰️ OpenOSINT AI — Evidence-First OSINT Workspace")
st.caption("Public-source research • Real tool outputs • Optional CrewAI analysis • Exportable evidence")

with st.sidebar:
    st.header("Configuration")
    st.write("**AI analysis:** optional (Groq API)")
    st.write("**Public lookups:** do not require an LLM key")
    st.info("Use only for lawful, authorized research. Public profile responses are signals, not proof of identity.")
    use_ai = st.toggle("Run CrewAI analysis when GROQ_API_KEY is configured", value=True)
    st.divider()
    st.caption("A 403/429 response is shown as a blocked/rate-limited result, never treated as proof that a profile is absent.")

pages = st.tabs(["Dashboard", "Email", "Username / Identity", "Domain", "IP", "Web Search", "Image Metadata", "AI Investigation", "Report & Limits"])
results = st.session_state.setdefault("osint_results", {})

with pages[0]:
    st.subheader("Investigation dashboard")
    a,b,c,d = st.columns(4)
    a.metric("Modules", "7")
    b.metric("API keys required for basic lookups", "0")
    c.metric("AI layer", "Optional")
    d.metric("Evidence policy", "Source-first")
    st.markdown("""**What this application does**
- Runs bounded public-data checks using Python and third-party public endpoints.
- Records module outputs with timestamps and source URLs where available.
- Uses CrewAI agents only to interpret collected evidence; agents are instructed not to invent findings.
- Keeps AI unavailable without breaking deterministic OSINT modules.

**What it cannot prove:** account ownership, a real person's identity, precise location from an IP address, whether an email inbox exists, or that a username is absent from every platform.""")
    if results:
        st.write(f"Current session has **{len(results)}** module result(s).")
        st.json({k: v.get("status", "completed") for k,v in results.items()})
    else:
        st.info("Start with any module tab. Results are retained in this browser session until it resets.")

with pages[1]:
    st.subheader("Email OSINT")
    email = st.text_input("Email address", placeholder="analyst@example.com", key="email_input")
    check_breach = st.checkbox("Check Have I Been Pwned (requires your HIBP API key)")
    if st.button("Analyze email", key="email_btn"):
        with st.spinner("Validating and checking configured public sources..."):
            r = check_email(email, check_breach=check_breach)
            results["email"] = r
        st.json(r)
        st.caption("Syntax validation is not mailbox verification. Breach results are only queried when a valid HIBP key is configured.")

with pages[2]:
    st.subheader("Username / Identity Tracker")
    username = st.text_input("Username / handle", placeholder="example_handle", key="username_input")
    services = st.multiselect("Public profile services", ["GitHub", "GitLab", "Reddit", "Dev.to", "Medium", "Hacker News"], default=["GitHub", "GitLab", "Reddit", "Dev.to", "Medium"])
    if st.button("Check public profile URLs", key="username_btn"):
        with st.spinner("Checking selected public profile URLs politely..."):
            r = check_username(username, services)
            results["username"] = r
        st.json(r)
        st.warning("A profile URL response is not identity verification. HTTP 403, 429, and timeouts are inconclusive.")

with pages[3]:
    st.subheader("Domain intelligence")
    domain = st.text_input("Domain (not a full URL)", placeholder="example.com", key="domain_input")
    if st.button("Analyze domain", key="domain_btn"):
        with st.spinner("Querying DNS, RDAP and public HTTP metadata..."):
            r = domain_intel(domain)
            results["domain"] = r
        st.json(r)

with pages[4]:
    st.subheader("Public IP intelligence")
    ip = st.text_input("IPv4 or IPv6 address", placeholder="8.8.8.8", key="ip_input")
    if st.button("Analyze IP", key="ip_btn"):
        with st.spinner("Validating IP and querying public metadata..."):
            r = ip_intel(ip)
            results["ip"] = r
        st.json(r)
        st.caption("IP geolocation is approximate and identifies network-level information, not a person's exact location.")

with pages[5]:
    st.subheader("Public Web Search")
    query = st.text_input("Search query", placeholder='site:example.com "security contact"', key="search_input")
    if st.button("Search public web", key="search_btn"):
        with st.spinner("Trying a configured search provider and safe fallback..."):
            r = web_search(query)
            results["web_search"] = r
        st.json(r)
        st.caption("This is public-web search, not dark-web access. Search results may be incomplete or stale.")

with pages[6]:
    st.subheader("Image metadata & optional caption")
    uploaded = st.file_uploader("Upload an image you are authorized to analyze", type=["jpg", "jpeg", "png", "webp"])
    use_hf = st.checkbox("Also request an image caption from Hugging Face (requires HF_TOKEN)")
    if st.button("Inspect image", key="image_btn", disabled=uploaded is None):
        raw = uploaded.getvalue()
        meta = image_metadata(raw, uploaded.name)
        if use_hf:
            meta["captioning"] = image_caption_hf(raw, uploaded.type or "image/jpeg")
        results["image"] = meta
        st.json(meta)
        st.caption("EXIF GPS may be absent or stripped. A caption describes visible content; it does not reliably identify an exact location.")

with pages[7]:
    st.subheader("Multi-agent investigation")
    st.write("The Python modules collect the evidence first. CrewAI specialists then analyze only the collected JSON; they cannot claim a lookup occurred unless it appears in the evidence.")
    target = st.text_input("Investigation question / scope", placeholder="Summarize the evidence collected for example.com", key="ai_scope")
    available = {k:v for k,v in results.items()}
    if st.button("Run CrewAI evidence analysis", key="crew_btn", disabled=not available):
        with st.spinner("Running specialist agents over collected evidence..."):
            ai = run_crew_analysis(target or "Summarize the collected evidence and limitations.", available)
            results["crew_analysis"] = ai
        st.markdown(ai.get("analysis", "No analysis returned."))
        if ai.get("warning"):
            st.warning(ai["warning"])
        with st.expander("Agent execution details"):
            st.json({k:v for k,v in ai.items() if k != "analysis"})
    if not available:
        st.info("Collect one or more module results before running the agents.")

with pages[8]:
    st.subheader("Report, history and limitations")
    report = build_report(results)
    st.download_button("Download current evidence report (.md)", report, file_name="openosint_evidence_report.md", mime="text/markdown")
    st.download_button("Download current session evidence (.json)", json.dumps(results, indent=2, ensure_ascii=False), file_name="openosint_evidence.json", mime="application/json")
    st.markdown("""**Reality and reliability notes**
- Public endpoints can change, rate-limit, block automated clients, or return incomplete information.
- `200 OK` is not proof of account ownership; `404` may not always mean no account; `403`/`429` are inconclusive.
- Email syntax does not establish that a mailbox exists or that it belongs to a person.
- Domain and IP data is supplied by third parties and can be stale or approximate.
- Image captioning can be wrong; metadata is stronger only when present and internally consistent.
- Streamlit Community Cloud local files are not durable storage. This starter keeps findings in session state and offers exports; add a persistent database for long-term history.
- AI text is analysis, not primary evidence. Verify important claims against source links and timestamps.""")

st.divider()
st.caption(f"Session view generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} • OpenOSINT AI prototype — not a production attribution system")
