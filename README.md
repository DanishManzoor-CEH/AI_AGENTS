# Advanced Agentic AI OSINT Platform

## Files
- `app.py`: Streamlit app
- `requirements.txt`: pinned Python dependencies

## Streamlit secrets
Add the following in Streamlit Cloud → App settings → Secrets:

```toml
GROQ_API_KEY = "your-groq-api-key"
HF_API_KEY = "your-huggingface-api-key"
GOOGLE_API_KEY = "your-google-custom-search-api-key"
GOOGLE_CX = "your-google-custom-search-engine-id"
```

`HF_API_KEY` is required by the requested configuration contract but is not used by this version.

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The app uses `openai/gpt-oss-20b` because Groq retired `llama3-8b-8192` on August 30, 2025. The app searches only selected public domains and analyzes returned snippets; it does not crawl pages or access private/deep-web sources. Confirm dependency compatibility in a clean deployment environment before production use.
