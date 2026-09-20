# PhishGuard

AI-powered phishing email analyzer. Paste a suspicious email and get a risk assessment with an explanation.

**Live Demo:** https://phishguard-rrxp4e24e6dumdhyxf9gnj.streamlit.app/

## What It Does

- Extracts phishing indicators locally: URLs, urgency language, sender/reply-to mismatches
- Sends indicators plus email text to an LLM for risk assessment
- Returns Low/Medium/High risk with a plain-language explanation

## Why It Matters

Phishing is one of the most common initial access vectors in breaches. This tool demonstrates how LLMs can assist with basic security triage — combining rule-based detection with AI reasoning.

## Tech Stack

- Python
- Streamlit (UI + free hosting)
- Groq API with `openai/gpt-oss-120b`
- python-dotenv for local config

## Run Locally

1. Clone: `git clone https://github.com/AbdulAK608/phishguard.git`
2. Install: `pip install -r requirements.txt`
3. Get a free Groq API key at console.groq.com
4. Create `.env` with `GROQ_API_KEY=your_key_here`
5. Run: `streamlit run app.py`

## Limitations

- Not production-ready
- Rule-based indicators only catch known patterns
- LLM may produce false positives on legitimate urgent emails

## License

MIT