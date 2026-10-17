# OpenOSINT AI — CrewAI + Streamlit

A modular, evidence-first OSINT demonstration. Python collectors perform public-data lookups; optional CrewAI agents summarize only the evidence that was actually collected. This project is a prototype, not a production attribution or identity-verification system.

## Modules
- Email syntax and DNS resolution; optional Have I Been Pwned lookup if you supply eligible API access.
- Public profile URL response checks for GitHub, GitLab, Reddit, Dev.to, Medium, and Hacker News.
- Domain DNS, RDAP, and HTTP metadata.
- Public IP metadata via ipwho.is, only for globally routable IP addresses.
- Public web search via Google Programmable Search if configured, with a DuckDuckGo library fallback. Google HTML is not scraped.
- Image dimensions and EXIF inspection; optional Hugging Face image captioning.
- Three sequential CrewAI agents for evidence quality, technical interpretation, and report review.
- Markdown and JSON evidence export.

## Python version
Use **Python 3.12** for both local development and Streamlit Community Cloud. Community Cloud's current documented default is Python 3.12, and CrewAI requires Python >=3.10 and <3.14. Recheck official compatibility notes when upgrading dependencies.

## Local setup (Windows PowerShell)
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml
# Edit .streamlit/secrets.toml and add keys you actually have
streamlit run app.py
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

## API keys
Basic DNS/RDAP/IP/profile checks need no LLM key. Optional integrations:
- `GROQ_API_KEY`: enables CrewAI analysis. Create it in the Groq console; verify model access and current rate limits.
- `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_ID`: Google Programmable Search; if missing or Google returns 403/429, the app tries DuckDuckGo fallback.
- `HIBP_API_KEY`: optional Have I Been Pwned breach endpoint; access and endpoint use may require an eligible plan.
- `HF_TOKEN`: optional Hugging Face inference for image captioning; model/provider access can change.

Keys belong in `.streamlit/secrets.toml` locally and Streamlit Cloud's Secrets UI after deployment. Never commit secrets or paste keys into source files.

## GitHub upload
1. Create a new **private** GitHub repository initially (you can make it public later after checking for secrets).
2. Extract this ZIP, open a terminal in the `OpenOSINT_AI_CrewAI` folder.
3. Run:
   ```bash
   git init
   git add .
   git status
   git commit -m "Initial evidence-first OSINT app"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
   git push -u origin main
   ```
4. Confirm `.streamlit/secrets.toml` is not in the commit. `.gitignore` excludes it.

## Streamlit Community Cloud deployment
1. Push the repository to GitHub.
2. Open https://share.streamlit.io and sign in with GitHub.
3. Choose **Create app** → select repository, branch `main`, and main file path `app.py`.
4. Open **Advanced settings** and choose **Python 3.12**.
5. In **Secrets**, paste TOML such as:
   ```toml
   GROQ_API_KEY = "your_real_key"
   GOOGLE_CSE_API_KEY = "your_real_key"
   GOOGLE_CSE_ID = "your_search_engine_id"
   HIBP_API_KEY = "your_real_key"
   HF_TOKEN = "your_real_key"
   ```
   Only include keys you have. Do not include comments or example placeholders as if they were real credentials.
6. Click **Deploy**. Review the app logs if the build fails.
7. Test modules individually before testing CrewAI. Public providers can block cloud IP ranges or rate-limit requests.

## Important deployment facts
- Streamlit Community Cloud local filesystem and session state are not durable databases. Use report downloads for this prototype; add a persistent database/object store if you need permanent investigation history.
- `403` means blocked/forbidden; `429` means rate limited. Neither means a profile is absent.
- `404` is only a platform response signal, not proof of nonexistence or identity.
- An email syntax check does not verify mailbox ownership. IP geolocation is approximate. EXIF and model captions can be missing, edited, or wrong.
- Search results are public-web search, not dark-web access.
- Use only for lawful, authorized purposes and respect privacy, provider terms, and rate limits.

## Troubleshooting
- **Google HTTP 403**: verify the API key, enabled Programmable Search API, search engine ID, quota and billing/access requirements. The app records the failure and tries the fallback provider.
- **CrewAI fails**: verify Python 3.12, `GROQ_API_KEY`, and that `groq/openai/gpt-oss-20b` remains available to your account. Core lookups work without CrewAI.
- **Build fails**: read Streamlit logs; confirm the selected Python version and that `requirements.txt` is at repository root. Dependency versions may need adjustment over time.
- **No profile result**: blocked/rate-limited/timeout responses remain inconclusive. Avoid repeated aggressive requests.
