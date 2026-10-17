import streamlit as st
import requests
from crewai import Agent, Task, Crew
from langchain_groq import ChatGroq

# =====================================================================
# 1. STREAMLIT PAGE CONFIGURATION & STYLING
# =====================================================================
st.set_page_config(
    page_title="Advanced Agentic AI OSINT Platform",
    page_icon="🕵️‍♂️",
    layout="wide"
)

# Custom Title Block
st.markdown(
    """
    <div style="background-color:#0A2540; padding:15px; border-radius:8px; margin-bottom:25px;">
        <h1 style="color:white; margin:0;">🕵️‍♂️ Advanced Agentic AI OSINT Platform</h1>
    </div>
    """, 
    unsafe_allow_index=True
)

# =====================================================================
# 2. CREDENTIAL VERIFICATION & LLM INITIALIZATION
# =====================================================================
# Verify that all mandatory API keys exist inside Streamlit Secrets
required_secrets = ["GROQ_API_KEY", "HF_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CX"]
missing_secrets = [key for key in required_secrets if key not in st.secrets]

if missing_secrets:
    st.error(
        f"⚠️ Application functionality is partial or halted. Missing keys: {', '.join(missing_secrets)} "
        "in your Streamlit Cloud configuration panel."
    )
    st.stop()

# Properly initialize the LLM to fix the Pydantic ValidationError
try:
    llm = ChatGroq(
        api_key=st.secrets["GROQ_API_KEY"],
        model_name="llama3-8b-8192",
        temperature=0.2
    )
except Exception as e:
    st.error(f"❌ Failed to instantiate Groq LLM: {str(e)}")
    st.stop()


# =====================================================================
# 3. HELPER FUNCTIONS FOR CLEANER OSINT SEARCHES
# =====================================================================
def search_digital_footprint(target_value, data_type):
    """
    Queries Google Custom Search Engine with advanced queries optimized
    to skip generic root indexing placeholders (like general login pages).
    """
    api_key = st.secrets["GOOGLE_API_KEY"]
    cx = st.secrets["GOOGLE_CX"]
    
    # Structure queries using target platforms to pull explicit account mappings
    platforms = "site:github.com OR site:reddit.com OR site:pinterest.com OR site:soundcloud.com OR site:linktr.ee"
    
    if data_type == "Email Address":
        # Quote encapsulation enforces an absolute string match for the email account
        query = f'"{target_value}" ({platforms})'
    else:
        # Username query construction
        query = f'{target_value} ({platforms})'
        
    url = f"https://googleapis.com{api_key}&cx={cx}&q={query}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            results = response.json().get("items", [])
            return results
        else:
            st.error(f"Google API Error: Received Status Code {response.status_code}")
            return []
    except Exception as e:
        st.error(f"Failed to query search matrix: {str(e)}")
        return []


# =====================================================================
# 4. USER INTERACTION INTERFACE (SIDEBAR & MAIN PANELS)
# =====================================================================
# Sidebar Application Navigation Tabs
st.sidebar.title("Navigation")
app_mode = st.sidebar.radio(
    "Go To Panel:", 
    ["📱 Identity Tracker", "🌍 Geolocation Analyst", "🔍 Google Deep Web Search"]
)

if app_mode == "📱 Identity Tracker":
    st.subheader("Cross-Platform Footprint Identification")
    
    # Input Selection Blocks
    data_type = st.radio("Select Target Data Type:", ["Username Handle", "Email Address"])
    target_value = st.text_input("Enter Target Identifier Value", placeholder="e.g., username or example@gmail.com")
    
    if st.button("💥 Execute Footprint Map Lookup"):
        if not target_value.strip():
            st.warning("Please enter a valid target identifier before running execution sequences.")
        else:
            with st.spinner("Scanning digital registries..."):
                search_hits = search_digital_footprint(target_value, data_type)
                
            if not search_hits:
                st.info("No explicit data maps found matching this target footprint configuration.")
            else:
                st.success(f"Discovered {len(search_hits)} target registry mappings!")
                st.markdown("### 🕸️ Discovered Digital Links")
                
                # Format raw records for display and pass them over to the multi-agent crew
                raw_intel_payload = ""
                for index, item in enumerate(search_hits):
                    title = item.get("title", "Unknown Source")
                    link = item.get("link", "#")
                    snippet = item.get("snippet", "")
                    
                    st.markdown(f"- **[{title}]({link})**: {snippet}")
                    raw_intel_payload += f"Source Title: {title}\nURL: {link}\nSnippet text: {snippet}\n\n"
                
                # =====================================================
                # 5. MULTI-AGENT SYNTHESIS PIPELINE (CREWAI)
                # =====================================================
                st.markdown("### 🧠 Running Agentic Data Synthesis...")
                
                with st.spinner("AI Analysis ongoing..."):
                    # Initializing the Agent using the validated LLM object
                    social_agent = Agent(
                        role='Senior Digital Footprint Profiler',
                        goal='Analyze cross-platform links and filter structural payload intelligence out of target footprints.',
                        backstory='You are an elite cyber forensics analyst specialized in organizing disjointed OSINT profile snippets into actionable situational records.',
                        verbose=True,  # Set to True during debugging to capture errors locally if they occur
                        llm=llm
                    )
                    
                    profile_synthesis_task = Task(
                        description=(
                            f"Review this collection of internet lookup raw payload items:\n\n{raw_intel_payload}\n"
                            "Isolate genuine public account links from generic landing page matches. Organize structural "
                            "insights including inferred alias names, related activities, or locations if present."
                        ),
                        expected_output="A structured markdown target profile report grouping verified links and associated metadata.",
                        agent=social_agent
                    )
                    
                    osint_crew = Crew(
                        agents=[social_agent],
                        tasks=[profile_synthesis_task],
                        verbose=True
                    )
                    
                    try:
                        final_intelligence_report = osint_crew.kickoff()
                        st.markdown("### 📋 Final Intelligence Summary")
                        st.markdown(str(final_intelligence_report))
                    except Exception as agent_err:
                        st.error(f"The multi-agent execution pipeline halted unexpectedly: {str(agent_err)}")

elif app_mode == "🌍 Geolocation Analyst":
    st.subheader("🌍 Geolocation Analyst")
    st.info("Module loading blueprint sequence pending configuration updates.")

elif app_mode == "🔍 Google Deep Web Search":
    st.subheader("🔍 Google Deep Web Search")
    st.info("Direct Custom Search Sandbox interface loading configuration sequences.")
