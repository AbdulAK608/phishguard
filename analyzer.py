import re
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

try:
    import streamlit as st
    API_KEY = os.environ.get("GROQ_API_KEY") or st.secrets.get("GROQ_API_KEY")
except Exception:
    API_KEY = os.environ.get("GROQ_API_KEY")





def extract_urls(text):
    """Extract all http/https URLs from the text"""
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text)

def check_urgency_words(text):
    """Check for urgency keywords"""
    urgency_terms = [
        "verify immediately", "account suspended", "urgent action",
        "act now", "within 24 hours", "click here to confirm",
        "your account will be", "immediate attention",
        "password expires", "unusual sign-in", "confirm your identity"
    ]
    found = []
    text_lower = text.lower()
    for term in urgency_terms:
        if term in text_lower:
            found.append(term)
    return found

def check_sender_mismatch(text):
    """Check if From and Reply-To are inconsistent"""
    from_match = re.search(r'From:\s*.*?@([\w.-]+)', text, re.IGNORECASE)
    reply_match = re.search(r'Reply-To:\s*.*?@([\w.-]+)', text, re.IGNORECASE)
    if from_match and reply_match:
        from_domain = from_match.group(1).lower()
        reply_domain = reply_match.group(1).lower()
        if from_domain != reply_domain:
            return f"From domain ({from_domain}) != Reply-To domain ({reply_domain})"
    return None

def analyze_text(text):
    """Combine and extract all indicators"""
    urls = extract_urls(text)
    urgency = check_urgency_words(text)
    mismatch = check_sender_mismatch(text)
    
    indicators = []
    if urls:
        indicators.append(f"Found {len(urls)} URL(s): {', '.join(urls[:3])}")
    if urgency:
        indicators.append(f"Urgency language: {', '.join(urgency)}")
    if mismatch:
        indicators.append(mismatch)
    if not indicators:
        indicators.append("No obvious indicators detected")
    
    return {
        "urls": urls,
        "urgency_words": urgency,
        "sender_mismatch": mismatch,
        "indicators": indicators
    }

def analyze_with_ai(email_text, indicators):
    """Send the email and extracted indicators to Groq for risk assessment"""
    client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=API_KEY
    )
    
    prompt = f"""You are a phishing detection assistant. Analyze this email and the detected indicators.

EMAIL:
{email_text[:2000]}

DETECTED INDICATORS:
{chr(10).join('- ' + i for i in indicators)}

Respond in this exact format:
RISK: [Low/Medium/High]
EXPLANATION: [2-3 sentences explaining why]"""
    
    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )
    
    return response.choices[0].message.content

def parse_ai_response(response_text):
    """Extract the risk level and explanation from the AI response"""
    risk = "Unknown"
    explanation = response_text
    
    lines = response_text.strip().split('\n')
    for line in lines:
        if line.startswith("RISK:"):
            risk = line.replace("RISK:", "").strip()
        elif line.startswith("EXPLANATION:"):
            explanation = line.replace("EXPLANATION:", "").strip()
    
    return {"risk": risk, "explanation": explanation}
