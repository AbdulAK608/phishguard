# ---------------------------------------------------------------
# analyzer.py — the "brain" of PhishGuard.
# It does three jobs:
#   1. Look for suspicious stuff in the email (URLs, urgent words, etc.)
#   2. Ask an AI to decide how risky the email is.
#   3. Read the AI's answer and split it into a risk level + explanation.
# No buttons or screens in this file — just the logic.
# ---------------------------------------------------------------

import re                              # "re" = regex. A tool for finding patterns in text.
import os                              # Lets us read "environment variables" (secret settings).
from dotenv import load_dotenv         # Reads a file called .env so we don't hardcode the API key.
from openai import OpenAI              # A library for talking to AI services.

# Read the .env file and turn each line into a setting Python can access.
# On the cloud there's no .env file, so this line quietly does nothing.
load_dotenv()


def extract_urls(text):
    """Find every link in the text."""
    # This pattern tells regex what a URL looks like:
    #   https?://   -> starts with http:// or https://
    #   [^\s<>"']+  -> then any characters EXCEPT spaces, <, >, quotes
    # findall() returns ALL matches, not just the first one.
    # We want all of them because phishing emails often have several links.
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text)


def check_urgency_words(text):
    """Look for words/phrases that pressure the reader to act fast."""
    # These are phrases phishing emails love to use. We hardcode them
    # because the list is short and easy to read — no need for anything fancy.
    urgency_terms = [
        "verify immediately", "account suspended", "urgent action",
        "act now", "within 24 hours", "click here to confirm",
        "your account will be", "immediate attention",
        "password expires", "unusual sign-in", "confirm your identity"
    ]

    found = []                             # We'll add each matching phrase here.
    text_lower = text.lower()              # Lowercase everything once so "Verify" and "verify" both match.

    # Go through each phrase and check if it's hiding somewhere in the email.
    for term in urgency_terms:
        if term in text_lower:             # "in" checks if the phrase appears anywhere.
            found.append(term)             # If yes, remember it.

    return found                           # Empty list if nothing matched.


def check_sender_mismatch(text):
    """Check if the 'From' and 'Reply-To' email addresses use different domains."""
    # Phishing trick: the From address looks real, but the Reply-To
    # points somewhere else (so the attacker gets your reply).
    #
    # The regex below finds the part after the @ in each header.
    # group(1) means "the part in parentheses" — here, the domain.
    from_match = re.search(r'From:\s*.*?@([\w.-]+)', text, re.IGNORECASE)
    reply_match = re.search(r'Reply-To:\s*.*?@([\w.-]+)', text, re.IGNORECASE)

    # We can only compare if BOTH headers exist in the text.
    if from_match and reply_match:
        from_domain = from_match.group(1).lower()      # e.g. "gmail.com"
        reply_domain = reply_match.group(1).lower()

        # If the two domains are different, that's a red flag.
        if from_domain != reply_domain:
            return f"From domain ({from_domain}) != Reply-To domain ({reply_domain})"

    # Return None when there's nothing to report. None = "no signal found."
    return None


def analyze_text(text):
    """Run all three checks and package the results into one dictionary."""
    # Call each detector. Each one returns a list or a string/None.
    urls = extract_urls(text)
    urgency = check_urgency_words(text)
    mismatch = check_sender_mismatch(text)

    # Build a list of short, human-readable sentences to show the user.
    # These same sentences get sent to the AI later.
    indicators = []

    # Only add a bullet if we found something. No empty bullets.
    if urls:
        # Show only the first 3 URLs so the UI doesn't get cluttered.
        indicators.append(f"Found {len(urls)} URL(s): {', '.join(urls[:3])}")
    if urgency:
        indicators.append(f"Urgency language: {', '.join(urgency)}")
    if mismatch:
        indicators.append(mismatch)

    # If nothing was found, say so explicitly instead of leaving a blank list.
    if not indicators:
        indicators.append("No obvious indicators detected")

    # Return a dictionary so other code can grab specific pieces by name
    # (e.g. result["urls"]) without counting positions.
    return {
        "urls": urls,
        "urgency_words": urgency,
        "sender_mismatch": mismatch,
        "indicators": indicators
    }


def analyze_with_ai(email_text, indicators):
    """Send the email + indicators to the AI and get a risk assessment back."""
    # Import streamlit HERE (not at the top of the file) on purpose.
    # At the top, it sometimes causes problems on the cloud before the app
    # is fully ready. Inside the function, it only runs when we click Analyze.
    import streamlit as st

    # Get the API key. Try two places:
    #   - Locally:  the .env file loaded it into os.environ
    #   - Cloud:    os.environ is empty, so we use st.secrets
    # The "or" means: use the left one if it exists, otherwise use the right one.
    api_key = os.environ.get("GROQ_API_KEY") or st.secrets.get("GROQ_API_KEY")

    # Create the AI client. We're using the OpenAI library, but we point it
    # at Groq's server, which speaks the same language.
    client = OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=api_key
    )

    # This is the message we send to the AI. Three things matter:
    #   1. We send the email text (cut off at 2000 characters to save tokens).
    #   2. We send our detected indicators as "evidence."
    #   3. We tell it EXACTLY how to format the reply, so we can parse it easily.
    prompt = f"""You are a phishing detection assistant. Analyze this email and the detected indicators.

EMAIL:
{email_text[:2000]}

DETECTED INDICATORS:
{chr(10).join('- ' + i for i in indicators)}

Respond in this exact format:
RISK: [Low/Medium/High]
EXPLANATION: [2-3 sentences explaining why]"""

    # Actually send the request.
    #   model:       which AI model to use (Groq supports this one).
    #   messages:    our prompt, wrapped in the expected format.
    #   temperature: 0.1 = almost no randomness. We want the same answer every time.
    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )

    # Pull out just the text of the AI's reply.
    # choices[0] = first (and only) answer, .message.content = the text inside it.
    return response.choices[0].message.content


def parse_ai_response(response_text):
    """Split the AI's reply into two parts: risk level and explanation."""
    # Default values in case the AI didn't follow the format.
    risk = "Unknown"
    explanation = response_text

    # Break the reply into individual lines.
    lines = response_text.strip().split('\n')

    # Look at each line. If it starts with "RISK:" or "EXPLANATION:",
    # grab the text after that label.
    for line in lines:
        if line.startswith("RISK:"):
            risk = line.replace("RISK:", "").strip()      # Remove the label, keep "High" etc.
        elif line.startswith("EXPLANATION:"):
            explanation = line.replace("EXPLANATION:", "").strip()

    # Return a small dictionary so the UI can use each piece by name.
    return {"risk": risk, "explanation": explanation}
