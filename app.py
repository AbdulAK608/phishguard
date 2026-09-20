# ---------------------------------------------------------------
# app.py — the "face" of PhishGuard.
# This is the file Streamlit runs. It shows a text box and a button,
# and calls functions from analyzer.py to do the real work.
# No detection logic lives here — that's all in analyzer.py.
# ---------------------------------------------------------------

import streamlit as st                              # The UI framework.
from analyzer import (                              # Grab our own functions from the other file.
    analyze_text,
    analyze_with_ai,
    parse_ai_response
)

# This must be the FIRST Streamlit command in the script.
# If you call any st.something before this, Streamlit throws an error.
# It sets the browser tab title and the little icon.
st.set_page_config(page_title="PhishGuard", page_icon="🛡️")

# Big heading at the top of the page.
st.title("🛡️ PhishGuard")

# A normal-sized line of text below the heading.
st.markdown("Paste a suspicious email below to analyze it for phishing indicators.")

# A big multi-line text box.
#   "Email content" = the label above the box.
#   height=250      = how tall the box is, in pixels.
#   placeholder     = the grey hint text inside an empty box.
# The user's typed text ends up in the variable email_text.
email_text = st.text_area(
    "Email content",
    height=250,
    placeholder="Paste the full email including headers if available..."
)

# A button. Streamlit's st.button returns True only during the moment the
# user clicks it. The whole if-block below runs only when that happens.
if st.button("Analyze", type="primary"):

    # If the box is empty (or only spaces), show a yellow warning and stop.
    # .strip() removes leading/trailing spaces so "   " counts as empty.
    if not email_text.strip():
        st.warning("Please paste some email content first.")

    else:
        # Show a small "Analyzing..." spinner while the work runs.
        # It's inside "with" so it disappears automatically when we're done.
        with st.spinner("Analyzing..."):

            # Step 1: run the local (fast) detectors.
            text_result = analyze_text(email_text)

            # Show a medium heading.
            st.subheader("Detected Indicators")

            # Loop through each indicator and print it as a bullet.
            for indicator in text_result["indicators"]:
                st.write(f"- {indicator}")

            # Step 2: send everything to the AI (slow — takes a second or two).
            ai_response = analyze_with_ai(email_text, text_result["indicators"])

            # Step 3: split the AI's reply into risk + explanation.
            parsed = parse_ai_response(ai_response)

            st.subheader("Risk Assessment")
            risk = parsed["risk"]

            # Pick a color based on the risk level:
            #   High   -> red box    (st.error)
            #   Medium -> yellow box (st.warning)
            #   else   -> green box  (st.success)
            # We use "in" instead of "==" so "High risk" or "High." still match.
            if "High" in risk:
                st.error(f"**Risk Level: {risk}**")
            elif "Medium" in risk:
                st.warning(f"**Risk Level: {risk}**")
            else:
                st.success(f"**Risk Level: {risk}**")

            st.subheader("AI Explanation")
            # Print the AI's explanation as plain text.
            st.write(parsed["explanation"])

# Small grey footnote at the very bottom of the page.
st.caption("PhishGuard is a learning project. Do not rely on it for production security decisions.")
