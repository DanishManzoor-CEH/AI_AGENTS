import re
from typing import Any

import requests
import streamlit as st
from crewai import Agent, Crew, Process, Task
from langchain_groq import ChatGroq

APP_TITLE = "Advanced Agentic AI OSINT Platform"
GOOGLE_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"
SOCIAL_DOMAINS = (
    "site:github.com OR site:reddit.com OR site:pinterest.com "
    "OR site:soundcloud.com OR site:linktr.ee"
)
REQUEST_TIMEOUT_SECONDS = 15
MAX_SEARCH_RESULTS = 10

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🕵️‍♂️",
    layout="wide",
)

# Validate required deployment secrets before running application features.
REQUIRED_SECRETS = ("GROQ_API_KEY", "HF_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CX")
try:
    available_secrets = st.secrets
    missing_secrets = [
        name
        for name in REQUIRED_SECRETS
        if not str(available_secrets.get(name, "")).strip()
    ]
except Exception:
    available_secrets = {}
    missing_secrets = list(REQUIRED_SECRETS)

if missing_secrets:
    st.error(
        "Configuration incomplete. Add the following required secrets in your "
        "Streamlit deployment dashboard under Settings → Secrets: "
        + ", ".join(missing_secrets)
    )
    st.stop()

# Explicitly construct a LangChain Chat model; never pass a raw token to CrewAI.
try:
    llm = ChatGroq(
        api_key=st.secrets["GROQ_API_KEY"],
        model_name="openai/gpt-oss-20b",
        temperature=0.2,
    )
except Exception as exc:
    st.error(
        "The Groq chat model could not be initialized. Check GROQ_API_KEY and "
        "the installed package versions. Details: "
        + str(exc)
    )
    st.stop()


def build_search_query(target_value: str, identifier_type: str) -> str:
    """Build an exact-match query limited to selected public social/code sites."""
    escaped_target = target_value.replace("\\", "\\\\").replace('"', '\\"')
    if identifier_type == "Email Address":
        return f'"{escaped_target}" ({SOCIAL_DOMAINS})'
    return f'"{escaped_target}" ({SOCIAL_DOMAINS})'


def validate_identifier(value: str, identifier_type: str) -> str:
    """Validate and normalize the user's search input."""
    target = value.strip()
    if not target:
        raise ValueError("Enter a username handle or email address.")

    if len(target) > 254:
        raise ValueError("The identifier is too long. Use 254 characters or fewer.")

    if any(ord(char) < 32 for char in target):
        raise ValueError("The identifier contains unsupported control characters.")

    if identifier_type == "Email Address":
        email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        if not re.fullmatch(email_pattern, target):
            raise ValueError("Enter a valid email address, such as name@example.com.")
    else:
        if len(target) < 2:
            raise ValueError("A username handle must contain at least 2 characters.")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", target):
            raise ValueError(
                "Use only letters, numbers, periods, underscores, or hyphens "
                "for a username handle."
            )

    return target


def google_custom_search(target_value: str, identifier_type: str) -> list[dict[str, str]]:
    """Call Google Custom Search JSON API and safely normalize result records."""
    query = build_search_query(target_value, identifier_type)
    params = {
        "key": st.secrets["GOOGLE_API_KEY"],
        "cx": st.secrets["GOOGLE_CX"],
        "q": query,
        "num": MAX_SEARCH_RESULTS,
    }

    try:
        response = requests.get(
            GOOGLE_SEARCH_URL,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload: Any = response.json()
    except requests.Timeout as exc:
        raise RuntimeError("Google Search timed out. Please try again.") from exc
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else "unknown"
        if status_code in (401, 403):
            raise RuntimeError(
                "Google Search rejected the API credentials or quota. Check "
                "GOOGLE_API_KEY, Custom Search API access, and billing/quota settings."
            ) from exc
        raise RuntimeError(
            f"Google Search returned HTTP {status_code}. Please try again later."
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError("Could not connect to Google Search. Check the deployment network.") from exc
    except ValueError as exc:
        raise RuntimeError("Google Search returned an unreadable JSON response.") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("Google Search returned an unexpected response format.")

    api_error = payload.get("error")
    if isinstance(api_error, dict):
        message = str(api_error.get("message", "Google Search API error"))
        raise RuntimeError(message[:500])

    raw_items = payload.get("items", [])
    if not isinstance(raw_items, list):
        return []

    records: list[dict[str, str]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue

        title = str(item.get("title", "")).strip()
        url = str(item.get("link", "")).strip()
        snippet = str(item.get("snippet", "")).strip()

        # Only accept ordinary web URLs and ignore malformed/non-HTTP records.
        if not title or not url.startswith(("https://", "http://")):
            continue

        records.append(
            {
                "title": title[:300],
                "url": url[:2000],
                "snippet": snippet[:1500],
            }
        )

    return records


def build_research_context(records: list[dict[str, str]]) -> str:
    """Create a clearly labeled evidence payload for the analysis agent."""
    sections = []
    for index, record in enumerate(records, start=1):
        sections.append(
            f"Result {index}\n"
            f"Title: {record['title']}\n"
            f"URL: {record['url']}\n"
            f"Search snippet: {record['snippet']}\n"
        )
    return "\n".join(sections)


def analyze_public_footprint(records: list[dict[str, str]], target: str) -> str:
    """Run a single CrewAI analyst over the returned search snippets."""
    context = build_research_context(records)

    analyst = Agent(
        role="Senior Digital Footprint Profiler",
        goal=(
            "Summarize relevant public professional, technical, and social profile "
            "evidence while clearly separating verified source facts from uncertainty."
        ),
        backstory=(
            "You are a cautious OSINT analyst. You evaluate public search-result "
            "fragments, distinguish genuine profile pages from generic service pages, "
            "and do not assume that two pages belong to the same person merely because "
            "they share a name or handle."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    task = Task(
        description=(
            "Analyze the Google Custom Search result fragments below for the supplied "
            "identifier: {target}. Identify relevant public profile pages and summarize "
            "only metadata visible in the provided titles, URLs, and snippets. Exclude "
            "generic login pages, marketing templates, and unrelated results. Do not "
            "invent facts, claim you visited pages, infer sensitive personal attributes, "
            "derive private contact details, or infer physical location. If evidence is "
            "weak or ambiguous, say so. Include source URLs next to each finding. "
            "Use Markdown sections: Executive Summary, Relevant Public Profiles, "
            "Evidence and Confidence, Irrelevant or Ambiguous Results, and Limitations. "
            "Treat search snippets as unverified and do not present a match as confirmed "
            "identity unless the supplied evidence directly supports that conclusion.\n\n"
            "SEARCH RESULT CONTEXT:\n{context}"
        ),
        expected_output=(
            "A concise, structured Markdown report with source URLs, evidence-based "
            "findings, uncertainty notes, and explicit limitations."
        ),
        agent=analyst,
    )

    crew = Crew(
        agents=[analyst],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )

    result = crew.kickoff(inputs={"target": target, "context": context})
    return str(result)


# UI
st.markdown(
    """
    <div style="
        background-color:#0A2540;
        padding:1.25rem 1.5rem;
        border-radius:12px;
        margin-bottom:1rem;
        color:white;">
        <h1 style="color:white; margin:0;">🕵️‍♂️ Advanced Agentic AI OSINT Platform</h1>
        <p style="color:#D9E7F5; margin:0.5rem 0 0 0;">
            Evidence-led analysis of publicly indexed profiles and technical footprints
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.title("Navigation")
    selected_tab = st.radio(
        "Choose a workspace",
        (
            "📱 Identity Tracker",
            "🌍 Geolocation Analyst",
            "🔍 Google Deep Web Search",
        ),
        index=0,
    )
    st.divider()
    st.caption("Use only identifiers you are authorized to research.")
    st.caption("Search results may be incomplete or incorrectly associated.")

if selected_tab == "📱 Identity Tracker":
    st.subheader("Identity Tracker")
    st.write(
        "Search selected public websites for an exact username or email match, "
        "then use an AI analyst to summarize the returned search evidence."
    )

    with st.form("identity_search_form"):
        identifier_type = st.radio(
            "Identifier type",
            ("Username Handle", "Email Address"),
            horizontal=True,
        )
        identifier_value = st.text_input(
            "Username handle or email address",
            placeholder="e.g. danishmanzoor or name@example.com",
            max_chars=254,
        )
        submitted = st.form_submit_button(
            "Search public sources and analyze",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        try:
            target = validate_identifier(identifier_value, identifier_type)
            with st.spinner("Searching selected public sources..."):
                records = google_custom_search(target, identifier_type)

            if not records:
                st.info(
                    "No matching records were returned for this exact query. "
                    "This does not prove that no public profiles exist."
                )
            else:
                st.markdown("### Search Results")
                for index, record in enumerate(records, start=1):
                    st.markdown(f"**{index}. [{record['title']}]({record['url']})**")
                    st.write(record["snippet"] or "No snippet was provided.")
                    st.caption(record["url"])

                st.markdown("### AI Analysis")
                st.caption(
                    "The report is based on the search-result fragments shown above. "
                    "It may contain uncertainty and should be independently verified."
                )
                with st.spinner("CrewAI analyst is preparing the report..."):
                    try:
                        report = analyze_public_footprint(records, target)
                    except Exception as exc:
                        st.error(
                            "Search succeeded, but AI analysis failed. Check the Groq "
                            "key, model availability, and CrewAI/LangChain versions. "
                            f"Details: {exc}"
                        )
                    else:
                        with st.container(border=True):
                            st.markdown(report)
        except ValueError as exc:
            st.warning(str(exc))
        except RuntimeError as exc:
            st.error(str(exc))

elif selected_tab == "🌍 Geolocation Analyst":
    st.subheader("Geolocation Analyst")
    st.info(
        "This workspace is a placeholder. No geolocation lookup or physical-location "
        "inference is performed in this version."
    )
    st.write(
        "A future version can focus on non-personal, consent-based analysis of public "
        "IP geolocation data, with clear accuracy limitations."
    )

elif selected_tab == "🔍 Google Deep Web Search":
    st.subheader("Google Deep Web Search")
    st.info(
        "This workspace is a placeholder. The current Identity Tracker uses Google "
        "Custom Search results from a limited set of public websites; it does not access "
        "private accounts, bypass authentication, or search the entire deep web."
    )
    st.write(
        "To keep this deployment predictable, broader search configuration should be "
        "added only with explicit source allowlists, quotas, and rate limits."
    )

st.divider()
st.caption(
    "Responsible-use note: use public data lawfully, verify findings at their sources, "
    "and do not use this tool to harass, expose, or make consequential decisions about people."
)
