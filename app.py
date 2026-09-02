import streamlit as st
import urllib.parse
import re
from io import BytesIO
from fpdf import FPDF
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# Set Page Layout
st.set_page_config(page_title="Regional Threat Classifier", page_icon="🛡️", layout="wide")

# =======================================================
# 1. MACHINE LEARNING MODEL FOR TEXT SCAM DETECTION
# =======================================================
@st.cache_resource
def load_and_train_model():
    training_messages = [
        "Dear customer, your bank account is suspended. Click link to update KYC immediately.",
        "Your electricity bill is overdue. Power will be disconnected tonight. Call officer now.",
        "Congratulations! You won 1,000,000 cash prize in lucky draw. Claim free reward now.",
        "Urgent: Your SBI debit card blocked. Click here to verify your details immediately.",
        "Part time job offer: Earn 5000 per day working from home. No experience needed.",
        "Special festival offer: Get iPhone for 999 rupees only. Limited stock buy now.",
        "Your package delivery failed. Pay 25 rupees re-delivery fee at this link.",
        "Your OTP for net banking login is 482910. Do not share it with anyone.",
        "Your order #40291 has been dispatched via BlueDart. Track delivery status here.",
        "Dear customer, your monthly internet bill statement is now available.",
        "Meeting reminder: Project review presentation tomorrow at 10 AM.",
        "Your appointment with Dr. Sharma is confirmed for 4 PM today.",
        "Thanks for shopping with Flipkart. Your invoice is attached.",
        "Hi mom, I will reach home by 7 PM today after class."
    ]
    
    labels = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]

    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(training_messages)
    
    model = MultinomialNB()
    model.fit(X, labels)

    return vectorizer, model

vectorizer, scam_model = load_and_train_model()

# =======================================================
# 2. HEURISTIC URL RISK CHECKER
# =======================================================
def check_url_risk(user_url):
    if not user_url:
        return None

    clean_url = user_url.strip().lower()
    full_url = clean_url if clean_url.startswith(("http://", "https://")) else "https://" + clean_url

    try:
        parsed_url = urllib.parse.urlparse(full_url)
        domain = parsed_url.netloc
        if domain.startswith("www."):
            domain = domain[4:]

        score = 0
        warnings = []
        safety_checks = []

        if parsed_url.scheme == "http":
            score += 25
            warnings.append("Unencrypted HTTP protocol used (missing SSL certificate).")
        else:
            safety_checks.append("Secure HTTPS protocol detected.")

        phishing_words = ["login", "verify", "secure", "bank", "update", "account", "free", "offer", "discount", "win", "kyc"]
        found_words = [w for w in phishing_words if w in clean_url]
        if found_words:
            score += 30
            warnings.append(f"Contains high-risk keywords: {', '.join(found_words)}")

        cheap_tlds = [".xyz", ".top", ".club", ".online", ".site", ".live", ".info", ".tk", ".ml"]
        if any(domain.endswith(tld) for tld in cheap_tlds):
            score += 25
            warnings.append("Uses a low-cost top-level domain frequently associated with spam.")

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            score += 40
            warnings.append("Direct IP address used instead of official domain name.")

        if domain.count("-") >= 2:
            score += 15
            warnings.append("Multiple hyphens found in domain name (possible spoofing attempt).")

        return {
            "domain": domain,
            "risk_score": min(score, 100),
            "warnings": warnings,
            "safety_checks": safety_checks
        }
    except Exception:
        return {"error": "Invalid URL provided."}

# =======================================================
# 3. PDF REPORT GENERATOR (DYNAMIC OFFICIAL COMPLAINT)
# =======================================================
def create_pdf_report(url_text, msg_text, risk_score, confidence_prob, prediction_label, comp_name, comp_phone, comp_email):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Header Banner
    pdf.set_fill_color(24, 43, 73)
    pdf.rect(0, 0, 210, 22, 'F')
    
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 6, "FORMAL CYBER CRIME COMPLAINT REPORT", ln=True, align='C')
    
    pdf.set_font("Arial", 'I', 8)
    pdf.set_text_color(200, 210, 225)
    pdf.cell(0, 4, "Generated via AI Regional Scam Detector | National Cyber Crime Incident Format", ln=True, align='C')
    pdf.ln(8)
    
    pdf.set_text_color(40, 40, 40)

    # Section 1: Addressee Details
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(230, 235, 245)
    pdf.cell(0, 6, " 1. ADDRESSEE & INCIDENT CLASSIFICATION", ln=True, fill=True)
    pdf.ln(2)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(35, 5, "TO:")
    pdf.set_font("Arial", '', 9)
    pdf.cell(0, 5, "The Officer-in-Charge / Nodal Officer, Cyber Crime Cell", ln=True)
    
    pdf.set_font("Arial", 'B', 9)
    pdf.cell(35, 5, "SUBJECT:")
    pdf.set_font("Arial", '', 9)
    pdf.cell(0, 5, "Complaint regarding Online Phishing / E-Commerce Impersonation Fraud", ln=True)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(35, 5, "INCIDENT TYPE:")
    pdf.set_font("Arial", '', 9)
    pdf.cell(0, 5, "Financial Fraud / Impersonation SMS Scam", ln=True)
    pdf.ln(3)

    # Section 2: Dynamic Complainant Details
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(230, 235, 245)
    pdf.cell(0, 6, " 2. COMPLAINANT DETAILS", ln=True, fill=True)
    pdf.ln(2)

    pdf.set_font("Arial", '', 9)
    name_str = comp_name if comp_name else "Not Specified"
    phone_str = comp_phone if comp_phone else "Not Specified"
    email_str = comp_email if comp_email else "Not Specified"

    pdf.cell(95, 5, f"Victim Name: {name_str}", border=1)
    pdf.cell(95, 5, f"Mobile No: {phone_str}", border=1, ln=True)
    pdf.cell(95, 5, f"Email ID: {email_str}", border=1)
    pdf.cell(95, 5, "State / UT: India", border=1, ln=True)
    pdf.ln(4)

    # Section 3: Evidence Details
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(230, 235, 245)
    pdf.cell(0, 6, " 3. INCIDENT EVIDENCE & EXPORTED SNIPPET", ln=True, fill=True)
    pdf.ln(2)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(0, 5, "A. Received Phishing Text / SMS Content:", ln=True)
    
    pdf.set_font("Arial", '', 9)
    display_text = msg_text if msg_text else "No textual evidence provided."
    pdf.set_fill_color(250, 250, 250)
    pdf.multi_cell(190, 5, f'"{display_text}"', border=1, fill=True)
    pdf.ln(2)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(0, 5, "B. Perpetrator Web Link / URL:", ln=True)
    pdf.set_font("Arial", '', 9)
    display_url = url_text if url_text else "No web URL submitted."
    pdf.cell(190, 5, f" {display_url}", border=1, ln=True)
    pdf.ln(4)

    # Section 4: Technical Metrics
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(230, 235, 245)
    pdf.cell(0, 6, " 4. TECHNICAL ANALYSIS & THREAT EVALUATION", ln=True, fill=True)
    pdf.ln(2)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(63, 6, " Heuristic Risk Score", border=1)
    pdf.cell(63, 6, " NLP Detection Confidence", border=1)
    pdf.cell(64, 6, " Threat Status", border=1, ln=True)

    pdf.set_font("Arial", '', 9)
    pdf.cell(63, 6, f" {risk_score} / 100", border=1)
    pdf.cell(63, 6, f" {confidence_prob:.1f}% Confidence", border=1)
    
    if prediction_label == 1 or risk_score >= 50:
        pdf.set_text_color(180, 0, 0)
        pdf.set_font("Arial", 'B', 9)
        pdf.cell(64, 6, " MALICIOUS / SCAM", border=1, ln=True)
    else:
        pdf.set_text_color(0, 120, 0)
        pdf.set_font("Arial", 'B', 9)
        pdf.cell(64, 6, " LOW THREAT / SAFE", border=1, ln=True)

    pdf.set_text_color(40, 40, 40)
    pdf.ln(4)

    # Section 5: Legal Declaration
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(230, 235, 245)
    pdf.cell(0, 6, " 5. COMPLAINANT DECLARATION & REQUEST", ln=True, fill=True)
    pdf.ln(2)

    pdf.set_font("Arial", '', 8)
    declaration_text = (
        "I hereby declare that the evidence provided above is authentic and was received on my personal device. "
        "I request the Cyber Crime Cell to register this complaint, investigate the origin of the message/URL, "
        "and block the scammer credentials to prevent further financial loss."
    )
    pdf.multi_cell(190, 4, declaration_text)
    pdf.ln(6)

    pdf.set_font("Arial", 'B', 9)
    pdf.cell(130, 5, "")
    pdf.cell(60, 5, "Signature of Complainant", ln=True, align='R')
    pdf.cell(130, 5, "")
    pdf.cell(60, 5, "_______________________", ln=True, align='R')
    pdf.ln(4)

    pdf.set_font("Arial", 'I', 7)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 3, "Report generated using Python (FPDF) & Naive Bayes NLP Model.", ln=True, align='C')
    pdf.cell(0, 3, "BCA 2nd Year Security Mini Project | Educational Evaluation Purposes", ln=True, align='C')

    return bytes(pdf.output())

# =======================================================
# 4. STREAMLIT USER INTERFACE
# =======================================================

# Sidebar Setup
st.sidebar.title("Control Panel")
st.sidebar.markdown("### Project Info")
st.sidebar.text("Degree: BCA (2nd Year)")
st.sidebar.text("Subject: Mini Project")
st.sidebar.text("Topic: AI Driven Regional Scam & Fake E-Commerce Threat Classifier")

st.sidebar.markdown("### Team Members")
st.sidebar.text("1. Anjo")
st.sidebar.text("2. Anulakshmi")
st.sidebar.text("3. Janova")
st.sidebar.text("4. Yadhu")

st.sidebar.markdown("### Status")
st.sidebar.success("All Modules Active")

# Main Dashboard Header
st.title("🛡️ Regional Scam & Fake E-Commerce Threat Classifier")
st.write("An AI-powered dashboard designed to detect fraudulent text messages and suspicious web links.")
st.markdown("---")

# User Input Layout
col1, col2 = st.columns(2)

with col1:
    st.subheader("Step 1: Message Check")
    user_message = st.text_area(
        "Paste suspicious SMS or WhatsApp text:",
        value="Dear customer, your electricity bill is overdue. Pay immediately or connection will be cut tonight."
    )

with col2:
    st.subheader("Step 2: Web Link Check")
    user_link = st.text_input(
        "Paste e-commerce or suspicious URL:",
        value="http://free-shopping-deal-offer.xyz"
    )

st.markdown("---")

# Dynamic Processing Logic
url_score = 0
scam_prob = 0.0
is_scam = 0

if user_link:
    link_data = check_url_risk(user_link)
    if link_data and "error" not in link_data:
        url_score = link_data['risk_score']

if user_message:
    vectorized_input = vectorizer.transform([user_message])
    is_scam = int(scam_model.predict(vectorized_input)[0])
    probabilities = scam_model.predict_proba(vectorized_input)[0]
    scam_prob = float(probabilities[1] * 100)

# Dashboard Analysis Output
if st.button("Run Threat Analysis"):
    if not user_message and not user_link:
        st.warning("Please enter either a message or a URL link to analyze.")
    else:
        st.subheader("📊 Analysis Results")
        res_col1, res_col2 = st.columns(2)

        if user_link and link_data and "error" not in link_data:
            with res_col1:
                st.markdown("### 🌐 URL Risk Assessment")
                st.metric(label="Calculated Risk Score", value=f"{url_score} / 100")
                
                if url_score >= 50:
                    st.error("🚨 HIGH RISK LINK DETECTED")
                else:
                    st.success("✅ LOW RISK LINK")

                for warning in link_data['warnings']:
                    st.warning(f"⚠️ {warning}")
                for check in link_data['safety_checks']:
                    st.success(f"✅ {check}")

        if user_message:
            with res_col2:
                st.markdown("### 🤖 NLP Text Analysis")
                st.metric(label="Scam Confidence Probability", value=f"{scam_prob:.1f}%")
                
                if is_scam == 1:
                    st.error("🚨 SCAM DETECTED")
                else:
                    st.success("✅ GENUINE MESSAGE")

                st.progress(int(scam_prob))

st.markdown("---")

# Step 3: PDF Complaint Generation (Interactive Form)
st.subheader("Step 3: Generate Formal Cyber Crime Report")
st.write("Fill in victim details to populate the official Cyber Crime Complaint document.")

c_col1, c_col2, c_col3 = st.columns(3)
with c_col1:
    comp_name = st.text_input("Complainant Name", value="Anjo Student")
with c_col2:
    comp_phone = st.text_input("Contact Number", value="+91 9876543210")
with c_col3:
    comp_email = st.text_input("Email Address", value="anjo@example.com")

if st.button("Generate & Download Complaint PDF"):
    pdf_bytes = create_pdf_report(
        user_link, user_message, url_score, scam_prob, is_scam,
        comp_name, comp_phone, comp_email
    )

    st.download_button(
        label="📥 Download Official Cyber Crime Report (PDF)",
        data=pdf_bytes,
        file_name="Cyber_Crime_Incident_Report.pdf",
        mime="application/pdf"
    )