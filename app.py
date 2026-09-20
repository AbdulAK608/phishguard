import streamlit as st
from analyzer import analyze_text, analyze_with_ai, parse_ai_response

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")

st.title("🛡️ PhishGuard")
st.markdown("Paste a suspicious email below to analyze it for phishing indicators.")

email_text = st.text_area(
    "Email content",
    height=250,
    placeholder="Paste the full email including headers if available..."
)

if st.button("Analyze", type="primary"):
    if not email_text.strip():
        st.warning("Please paste some email content first.")
    else:
        with st.spinner("Analyzing..."):
            text_result = analyze_text(email_text)

            st.subheader("Detected Indicators")
            for indicator in text_result["indicators"]:
                st.write(f"- {indicator}")

            ai_response = analyze_with_ai(email_text, text_result["indicators"])
            parsed = parse_ai_response(ai_response)

            st.subheader("Risk Assessment")
            risk = parsed["risk"]
            if "High" in risk:
                st.error(f"**Risk Level: {risk}**")
            elif "Medium" in risk:
                st.warning(f"**Risk Level: {risk}**")
            else:
                st.success(f"**Risk Level: {risk}**")

            st.subheader("AI Explanation")
            st.write(parsed["explanation"])

st.caption("PhishGuard is a learning project. Do not rely on it for production security decisions.")

