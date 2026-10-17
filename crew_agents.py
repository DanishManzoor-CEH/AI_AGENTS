from __future__ import annotations
import json, os

def run_crew_analysis(scope: str, evidence: dict) -> dict:
    """Use specialist CrewAI agents only to interpret collected evidence. No API key = safe graceful fallback."""
    api_key = os.getenv("GROQ_API_KEY", "")
    try:
        import streamlit as st
        api_key = api_key or st.secrets.get("GROQ_API_KEY", "")
    except Exception:
        pass
    if not api_key:
        return {"status":"skipped", "analysis":"CrewAI analysis was not run because GROQ_API_KEY is not configured. The deterministic module outputs are still valid and available above.", "warning":"Add GROQ_API_KEY in Streamlit Secrets to enable AI analysis."}
    try:
        from crewai import Agent, Task, Crew, Process, LLM
        llm = LLM(model="groq/openai/gpt-oss-20b", api_key=api_key, temperature=0.1)
        compact = json.dumps(evidence, ensure_ascii=False, default=str)[:24000]
        instructions = ("Use only the supplied evidence JSON. Never claim an unperformed lookup, infer account ownership, "
                        "invent source URLs, or present a hypothesis as fact. Explicitly label unknowns and limitations. "
                        "When evidence is empty or an API returned 403/429, say inconclusive.")
        agents = [
            Agent(role="Evidence Quality Analyst", goal="Separate observed facts from uncertain signals", backstory="You are a cautious OSINT analyst who prioritizes source provenance and uncertainty.", llm=llm, verbose=False, allow_delegation=False),
            Agent(role="Technical OSINT Analyst", goal="Interpret technical evidence accurately", backstory="You analyze DNS, RDAP, public IP metadata, profile URL checks, and search results without overclaiming.", llm=llm, verbose=False, allow_delegation=False),
            Agent(role="Report Reviewer", goal="Produce a concise, evidence-grounded investigation summary", backstory="You write clear reports that distinguish facts, limitations, and next verification steps.", llm=llm, verbose=False, allow_delegation=False),
        ]
        t1=Task(description=f"Review the evidence JSON for direct observations, provider status, and gaps. Scope: {scope}. Evidence: {compact}. {instructions}", expected_output="Bullet list of observed facts, evidence sources, and uncertainty.", agent=agents[0])
        t2=Task(description=f"Interpret only technical observations in this evidence. Scope: {scope}. Evidence: {compact}. {instructions}", expected_output="Technical interpretation with explicit confidence limitations.", agent=agents[1], context=[t1])
        t3=Task(description="Combine the prior outputs into a final report with sections: Summary, Observed Evidence, Interpretation, Unknowns, and Safe Next Steps. Do not add facts absent from the JSON.", expected_output="Markdown report grounded exclusively in supplied evidence.", agent=agents[2], context=[t1,t2])
        crew=Crew(agents=agents, tasks=[t1,t2,t3], process=Process.sequential, verbose=False)
        output=crew.kickoff()
        return {"status":"completed", "agents":[a.role for a in agents], "process":"sequential", "analysis":str(output), "evidence_keys":list(evidence.keys()), "note":"LLM-generated interpretation; verify against original sources."}
    except Exception as e:
        return {"status":"error", "analysis":"CrewAI could not complete the analysis. The evidence collectors remain available; inspect the error and retry after fixing configuration.", "error":f"{type(e).__name__}: {e}", "warning":"Check GROQ_API_KEY, active Groq model availability, CrewAI dependencies, and API rate limits."}
