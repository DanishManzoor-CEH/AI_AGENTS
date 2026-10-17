import streamlit as st
import asyncio
import aiohttp
import requests
import hashlib
from bs4 import BeautifulSoup
from crewai import Agent, Task, Crew, Process
from langchain_groq import ChatGroq

# ==========================================
# 1. INITIALIZATION & STYLED DASHBOARD CONFIG
# ==========================================
st.set_page_config(page_title="Advanced Agentic OSINT Platform", page_icon="🕵️‍♂️", layout="wide")
st.title("🕵️‍♂️ Advanced Agentic AI OSINT Platform")

# Securely pull API keys from Streamlit Cloud Secrets
try:
    groq_api_key = st.secrets.get("GROQ_API_KEY", None)
    hf_api_key = st.secrets.get("HF_API_KEY", None)
    google_api_key = st.secrets.get("GOOGLE_API_KEY", None)
    google_cx = st.secrets.get("GOOGLE_CX", None)
except Exception:
    st.error("⚠️ Secrets configuration failed. Please update your Streamlit Advanced Settings -> Secrets.")
    groq_api_key = hf_api_key = google_api_key = google_cx = None

# Core Target Registry for Async Username Enumeration
USERNAME_TARGETS = {
    "GitHub": "https://github.com{}",
    "Reddit": "https://reddit.com{}",
    "Pinterest": "https://pinterest.com{}/",
    "Tumblr": "https://{}.tumblr.com",
    "SoundCloud": "https://soundcloud.com{}",
    "Linktree": "https://linktr.ee{}"
}

# ==========================================
# 2. CORE UTILITY ENGINES & APIS
# ==========================================

def lookup_email_via_gravatar(email_address):
    """Queries Gravatar developer profile indicators via an email MD5 hash."""
    clean_email = email_address.strip().lower()
    email_hash = hashlib.md5(clean_email.encode('utf-8')).hexdigest()
    api_url = f"https://gravatar.com{email_hash}.json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json().get("entry", [{}])[0]
            return {
                "found": True,
                "display_name": data.get("displayName", "Not Provided"),
                "profile_url": data.get("profileUrl", ""),
                "about_me": data.get("aboutMe", "No biography details added."),
                "thumbnail": data.get("thumbnailUrl", "")
            }
    except Exception:
        pass
    return {"found": False}


def lookup_via_google_cse(query, api_key, cx):
    """Executes a programmable search across indexed web structures for leaks or text footprints."""
    if not api_key or not cx:
        return [{"title": "Google CSE Not Configured", "link": "#", "snippet": "Add GOOGLE_API_KEY and GOOGLE_CX to your secrets to activate."}]
    
    api_url = "https://googleapis.com"
    params = {"key": api_key, "cx": cx, "q": query}
    
    try:
        response = requests.get(api_url, params=params, timeout=6)
        if response.status_code == 200:
            items = response.json().get("items", [])
            return [{"title": i.get("title"), "link": i.get("link"), "snippet": i.get("snippet")} for i in items]
    except Exception:
        pass
    return []


def generate_image_caption(image_bytes, token):
    """Converts image uploads into structured text labels using HuggingFace Serverless inference pipelines."""
    API_URL = "https://huggingface.co"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.post(API_URL, headers=headers, data=image_bytes, timeout=15)
        if response.status_code == 200:
            return response.json().get('generated_text', 'Could not extract pixel descriptors.')
    except Exception:
        pass
    return "Error generating caption via Hugging Face Vision Model."


# ==========================================
# 3. ASYNCHRONOUS TARGET SCRAPER MODULE
# ==========================================
async def scrape_target(session, platform, url_template, username):
    """Asynchronously hits web registries to check user presence tags without blocking interface routines."""
    target_url = url_template.format(username.strip())
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        async with session.get(target_url, headers=headers, timeout=5) as response:
            if response.status == 200:
                html_body = await response.text()
                soup = BeautifulSoup(html_body, 'html.parser')
                meta_desc = soup.find("meta", attrs={"name": "description"})
                snippet = meta_desc["content"] if meta_desc else soup.title.string if soup.title else "Profile endpoint active."
                return {"platform": platform, "url": target_url, "data": snippet.strip()}
    except Exception:
        pass
    return None

async def run_parallel_scan(username):
    """Fires all scraping checks concurrently in the background."""
    async with aiohttp.ClientSession() as session:
        tasks = [scrape_target(session, name, template, username) for name, template in USERNAME_TARGETS.items()]
        results = await asyncio.gather(*tasks)
        return [res for res in results if res is not None]


# ==========================================
# 4. STREAMLIT GRAPHIC INTERFACE LAYOUT
# ==========================================
if not groq_api_key or not hf_api_key:
    st.warning("⚠️ Application functionality is partial until 'GROQ_API_KEY' and 'HF_API_KEY' are properly added in the Streamlit Cloud Settings configuration panel.")
else:
    # Initialize Llama 3.3 Versatile via LangChain wrapper
    llm = ChatGroq(groq_api_key=groq_api_key, model_name="llama-3.3-70b-versatile")
    
    tab1, tab2, tab3 = st.tabs(["📱 Identity Tracker", "🌍 Geolocation Analyst", "🔍 Google Deep Web Search"])

    # --- TAB 1: IDENTITY SURVEILLANCE & DIGITAL LINK MAPPING ---
    with tab1:
        st.subheader("Cross-Platform Footprint Identification")
        search_mode = st.radio("Select Target Data Type:", ["Username Handle", "Email Address Address"], horizontal=True)
        target_input = st.text_input("Enter Target Identifier Value", placeholder="e.g., testuser or target@domain.com")
        
        if st.button("Trigger Core Footprint Analysis") and target_input:
            progress_status = st.empty()
            intelligence_payload = ""
            
            # --- Scenario A: Handling Username Ingestion ---
            if search_mode == "Username Handle":
                progress_status.info(f"📡 Dispatching spiders across username structures for: `{target_input}`...")
                found_profiles = asyncio.run(run_parallel_scan(target_input))
                
                if found_profiles:
                    progress_status.success(f"💥 Discovered {len(found_profiles)} verified target registry mappings!")
                    st.markdown("### 🕸️ Discovered Digital Links")
                    for p in found_profiles:
                        st.markdown(f"- **[{p['platform']}]({p['url']})**: `{p['data'][:120]}...`")
                    intelligence_payload = "\n".join([f"Site: {p['platform']} | Link: {p['url']} | Bio: {p['data']}" for p in found_profiles])
                else:
                    progress_status.warning("❌ No plain records found via target username scan repositories.")
            
            # --- Scenario B: Handling Email Ingestion (Gravatar Engine) ---
            else:
                progress_status.info(f"🔑 Generating MD5 checksum matrix and polling Gravatar registries for: `{target_input}`...")
                gravatar_data = lookup_email_via_gravatar(target_input)
                
                if gravatar_data["found"]:
                    progress_status.success("✅ Public profile registry match extracted successfully!")
                    col1, col2 = st.columns([1, 4])
                    with col1:
                        if gravatar_data["thumbnail"]:
                            st.image(gravatar_data["thumbnail"], width=130)
                    with col2:
                        st.markdown(f"**Associated Name:** `{gravatar_data['display_name']}`")
                        st.markdown(f"**Profile URL:** [View Gravatar Record]({gravatar_data['profile_url']})")
                        st.markdown(f"**Biography Statement:** *\"{gravatar_data['about_me']}\"*")
                    intelligence_payload = f"Identity Source: Gravatar | Target: {target_input} | Extracted Name: {gravatar_data['display_name']} | Bio Statement: {gravatar_data['about_me']}"
                else:
                    progress_status.warning("❌ No active public Gravatar signature matched this email address hash.")

            # --- Trigger CrewAI Execution Synthesis Output ---
            if intelligence_payload:
                st.markdown("---")
                st.markdown("### 🧠 Running Agentic Data Synthesis...")
                with st.spinner("Social Tracker Agent analyzing bio indicators..."):
                    social_agent = Agent(
                        role='Senior Digital Footprint Profiler',
                        goal='Synthesize raw text fragments, links, and identity schemas to structure clean dossiers.',
                        backstory='You are an elite open-source intelligence engineer skilled at linking disconnected social networks and mapping target patterns-of-life.',
                        llm=llm,
                        verbose=False
                    )
                    social_task = Task(
                        description=f"Review this collected footprint data payload:\n{intelligence_payload}\nGenerate a professional Intelligence Dossier outlining all derived facts, location hints, and interests.",
                        expected_output="A clean, structured Markdown Intelligence Assessment Report.",
                        agent=social_agent
                    )
