import streamlit as st
import urllib.parse
import re
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import pandas as pd
from sklearn.model_selection import train_test_split
st.set_page_config(page_title="Scam & Threat Classifier", page_icon="🛡️", layout="wide")
@st.cache_resource
def load_and_train_model():

    # Load the Kaggle dataset
    dataset_path = Path("dataset/spam.csv")
    if not dataset_path.exists():
        dataset_path = Path("spam.csv")
    data = pd.read_csv(dataset_path, encoding="latin-1")

    # Keep only the required columns
    data = data[['v1', 'v2']]

    # Rename columns
    data.columns = ['label', 'message']

    # Remove empty values
    data = data.dropna()

    # Convert labels into numbers
    data['label'] = data['label'].map({
        'ham': 0,
        'spam': 1
    })

    # Separate messages and labels
    X = data['message']
    y = data['label']

    # Split dataset into training and testing
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # Convert text into numerical features
    vectorizer = TfidfVectorizer()

    X_train_vectorized = vectorizer.fit_transform(X_train)

    # Train the Naive Bayes model
    model = MultinomialNB()
    model.fit(X_train_vectorized, y_train)

    return vectorizer, model


vectorizer, scam_model = load_and_train_model()


# FEATURE 3: CHECKOUT & PAYMENT TRUST AUDIT (AUTOMATIC)
TRUSTED_GATEWAYS = [
    "razorpay.com", "paytm.com", "payu.in", "payu.com", "ccavenue.com",
    "billdesk.com", "cashfree.com", "stripe.com", "paypal.com",
    "phonepe.com", "instamojo.com", "juspay.in", "pinelabs.com"
]

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

def get_root_domain(url):
    if not url:
        return ""
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urllib.parse.urlparse(url).netloc.split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def audit_checkout(store_url, payment_url, checkout_text, text_scam_prob):
    risk = 0
    red_flags = []
    good_signs = []
    text = (checkout_text or "").lower()

    def has(pattern):
        return re.search(pattern, text) is not None

    # ---- 1. Payment URL analysis ----
    if payment_url:
        full = payment_url.strip().lower()
        if not full.startswith(("http://", "https://")):
            full = "https://" + full

        if full.startswith("http://"):
            risk += 30
            red_flags.append("Payment page does not use HTTPS, so card/UPI details can be intercepted.")
        else:
            good_signs.append("Payment page uses HTTPS.")

        pay_root = get_root_domain(payment_url)
        store_root = get_root_domain(store_url)
        if pay_root in TRUSTED_GATEWAYS:
            good_signs.append(f"Payment is handled by a recognised gateway ({pay_root}).")
        elif store_root and pay_root and pay_root != store_root:
            risk += 20
            red_flags.append(
                f"Payment domain ({pay_root}) differs from the store domain ({store_root}) "
                "and is not a known gateway."
            )

        url_result = check_url_risk(payment_url)
        if url_result and "error" not in url_result and url_result["risk_score"] >= 50:
            risk += 15
            red_flags.append("The payment link itself looks suspicious based on URL analysis.")

        if has(r"bit\.ly|tinyurl|goo\.gl|t\.co/|cutt\.ly|rb\.gy") or \
           re.search(r"bit\.ly|tinyurl|goo\.gl|cutt\.ly|rb\.gy", full):
            risk += 15
            red_flags.append("Payment goes through a shortened link that hides the real destination.")

    # ---- 2. Automatic detection from checkout text ----
    if text:
        # personal UPI ID (user@bank) - not an email
        if re.search(r"\b[\w.\-]{2,}@[a-z]{2,15}\b(?!\.)", text) or has(r"scan (the )?qr|qr code|pay to (this )?upi|upi id|gpay number|phonepe number"):
            risk += 25
            red_flags.append("Asks you to pay a personal UPI ID / QR code instead of using a payment gateway.")

        # bank account / IFSC
        if re.search(r"\b[a-z]{4}0[a-z0-9]{6}\b", text) or (has(r"a/c|account (no|number)|ifsc|neft|imps|rtgs") and re.search(r"\b\d{9,18}\b", text)):
            risk += 25
            red_flags.append("Requests a direct bank transfer, which is hard to reverse or dispute.")

        if has(r"gift ?card|itunes|google play card|bitcoin|crypto|usdt|binance"):
            risk += 35
            red_flags.append("Asks for payment via gift cards or cryptocurrency, a classic scam method.")

        if has(r"whatsapp|telegram|dm us|inbox us|message us to pay|chat to pay"):
            risk += 30
            red_flags.append("Payment or order is being handled through WhatsApp/Telegram chat.")

        if has(r"(enter|share|send|provide).{0,25}(upi pin|pin|otp|cvv|card number|password)") or \
           has(r"(upi pin|otp|cvv).{0,25}(to receive|for refund|to get|to claim)"):
            risk += 40
            red_flags.append("Asks for UPI PIN / OTP / CVV. A PIN is only needed to SEND money, never to receive it.")

        if has(r"advance.{0,20}(cod|cash on delivery)|(cod|cash on delivery).{0,30}advance|booking amount|token amount|delivery charge.{0,15}(upfront|in advance)"):
            risk += 15
            red_flags.append("Demands an advance payment even for Cash on Delivery.")

        if has(r"hurry|only \d+ (left|items|pieces)|last chance|limited time|expires (in|today)|offer ends|act now|today only|countdown"):
            risk += 10
            red_flags.append("Uses urgency / pressure tactics to rush your payment.")

        if has(r"\b(9\d|8\d|7\d)% ?off|90% ?(off|discount)|lowest price ever|free gift|100% ?free|win (a|an)"):
            risk += 15
            red_flags.append("Offers unrealistically high discounts or freebies.")

        if has(r"no refund|non[- ]refundable|no return|no exchange|no cancellation"):
            risk += 15
            red_flags.append("States no refund / return / cancellation policy.")

        # ---- positive signs ----
        if has(r"razorpay|paytm|payu|ccavenue|billdesk|cashfree|stripe|paypal|phonepe|instamojo|juspay"):
            good_signs.append("Mentions a recognised payment gateway.")
        if has(r"cash on delivery|\bcod\b|pay on delivery"):
            risk -= 10
            good_signs.append("Cash on Delivery is available, so you pay after receiving the product.")
        if has(r"return policy|refund policy|7[- ]day return|10[- ]day return|30[- ]day return|easy return|replacement policy"):
            good_signs.append("Mentions a return/refund policy.")
        if has(r"gstin|gst no|gst number|customer care|support@|contact us|registered address"):
            good_signs.append("Shows verifiable seller details (GST / contact / address).")
        if has(r"3d secure|secure checkout|pci[- ]dss|ssl"):
            good_signs.append("Mentions secure checkout standards.")

    # ---- 3. NLP model on the pasted text (reuses your Naive Bayes model) ----
    if text_scam_prob >= 70:
        risk += 15
        red_flags.append(f"Our NLP model finds the checkout text highly scam-like ({text_scam_prob:.0f}% confidence).")

    risk = max(0, min(risk, 100))
    trust_score = 100 - risk

    if trust_score >= 75:
        verdict = "TRUSTED"
    elif trust_score >= 45:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH RISK"

    return {
        "trust_score": trust_score,
        "verdict": verdict,
        "red_flags": red_flags,
        "good_signs": good_signs,
    }
st.sidebar.title("Control Panel")
st.sidebar.markdown("### Project Info")
st.sidebar.text("Degree: BCA (2nd Year)")
st.sidebar.text("Subject: Mini Project")
st.sidebar.text("Topic: AI Driven Scam & Fake E-Commerce Threat Classifier")
st.sidebar.markdown("### Team Members")
st.sidebar.text("1. Anjo")
st.sidebar.text("2. Anulakshmi")
st.sidebar.text("3. Janova")
st.sidebar.text("4. Yadhu")
st.sidebar.markdown("### Status")
st.sidebar.success("All Modules Active")
st.title("AI Driven Scam & Fake E-Commerce Threat Classifier")
st.write("An AI-powered dashboard designed to detect fraudulent text messages and suspicious web links.")
st.markdown("---")
col1, col2 = st.columns(2)
with col1:
    st.subheader("Step 1: Message Check")
    user_message = st.text_area(
        "Paste suspicious SMS or WhatsApp text:",
        value="Congratulations! You have been selected for an exclusive shopping reward! Claim your ₹5,000 Amazon gift voucher today. Limited time offer! Click the link to redeem your reward before it expires."
    )
with col2:
    st.subheader("Step 2: Web Link Check")
    user_link = st.text_input(
        "Paste e-commerce or suspicious URL:",
        value="http://free-shopping-deal-offer.xyz"
    )
st.markdown("---")
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
                
        # ==========================================
        # FEATURE 2: AUTOMATIC SAFETY RECOMMENDATIONS
        # ==========================================

        st.markdown("---")
        st.subheader("🛡️ Automatic Safety Recommendations")

        recommendations = []

        # Message-based recommendations
        if user_message and is_scam == 1:

            recommendations.append(
                "Do not reply to this suspicious message."
            )

            recommendations.append(
                "Do not click links or download attachments from this message."
            )

            recommendations.append(
                "Never share OTPs, passwords, PINs or banking details."
            )

        elif user_message:

            recommendations.append(
                "The message was classified as genuine, but this does not guarantee safety."
            )

            recommendations.append(
                "Verify unexpected offers through the official company website."
            )

        # URL-based recommendations
        if user_link and link_data and "error" not in link_data:

            warnings = link_data["warnings"]

            if warnings:

                recommendations.append(
                    "Avoid opening this URL until its authenticity is verified."
                )

            if any("HTTP" in w for w in warnings):

                recommendations.append(
                    "Avoid entering personal information on unencrypted HTTP websites."
                )

            if any("keywords" in w for w in warnings):

                recommendations.append(
                    "Be careful with links containing urgent words like login, verify or claim."
                )

            if any("top-level domain" in w for w in warnings):

                recommendations.append(
                    "Verify the website's domain through the company's official website."
                )

            if any("IP address" in w for w in warnings):

                recommendations.append(
                    "Avoid entering sensitive information on websites accessed through unfamiliar IP addresses."
                )

            if any("hyphens" in w for w in warnings):

                recommendations.append(
                    "Check the domain spelling carefully for possible brand impersonation."
                )

            if not warnings:

                recommendations.append(
                    "No configured URL red flags were detected. Still verify the website before making payments."
                )

        # Remove duplicate recommendations
        recommendations = list(dict.fromkeys(recommendations))

        # Display recommendations
        for recommendation in recommendations:

            st.info("💡 " + recommendation)

        st.caption(
            "These recommendations are automatically generated "
            "from the detected message and URL characteristics."
        )
        # ==========================================
# FEATURE 3: CHECKOUT & PAYMENT TRUST AUDIT UI
# ==========================================

st.markdown("---")
st.header("💳 Checkout & Payment Trust Audit")
st.write("Paste the checkout or payment details from a shopping site. The AI will automatically detect payment red flags.")

a1, a2 = st.columns(2)
with a1:
    audit_store_url = st.text_input("Store website URL:", value=user_link, key="audit_store_url")
    audit_payment_url = st.text_input(
        "Payment page URL (optional):",
        value="http://pay-secure-offer.xyz/checkout",
        key="audit_payment_url"
    )
with a2:
    audit_text = st.text_area(
        "Paste checkout page text / seller's payment instructions:",
        value="Hurry! Only 2 items left, 90% off today only! Advance payment required even for COD. "
              "Pay to UPI ID shopdeal123@ybl or scan QR code. Send screenshot on WhatsApp. "
              "Enter your UPI PIN to receive cashback. No refund, no return.",
        height=170,
        key="audit_text"
    )

if st.button("Run Payment Trust Audit", key="run_audit_btn"):
    if not audit_text and not audit_payment_url:
        st.warning("Please paste the checkout text or enter a payment page URL.")
    else:
        text_prob = 0.0
        if audit_text:
            text_prob = float(scam_model.predict_proba(vectorizer.transform([audit_text]))[0][1] * 100)

        audit = audit_checkout(audit_store_url, audit_payment_url, audit_text, text_prob)

        st.subheader("🧾 Payment Trust Report")
        m1, m2 = st.columns(2)
        with m1:
            st.metric("Payment Trust Score", f"{audit['trust_score']} / 100")
            st.progress(audit["trust_score"])
        with m2:
            if audit["verdict"] == "TRUSTED":
                st.success("✅ CHECKOUT LOOKS TRUSTWORTHY")
            elif audit["verdict"] == "SUSPICIOUS":
                st.warning("⚠️ SUSPICIOUS CHECKOUT, PROCEED WITH CAUTION")
            else:
                st.error("🚨 HIGH RISK CHECKOUT, DO NOT PAY")

        if audit["red_flags"]:
            st.markdown("#### 🚩 Red Flags Detected Automatically")
            for item in audit["red_flags"]:
                st.error(item)

        if audit["good_signs"]:
            st.markdown("#### ✅ Positive Signs Detected")
            for item in audit["good_signs"]:
                st.success(item)

        if not audit["red_flags"] and not audit["good_signs"]:
            st.info("No payment red flags or trust signals were found in the details provided.")

        st.markdown("#### 💡 What You Should Do")
        advice = []
        if audit["verdict"] == "HIGH RISK":
            advice.append("Do not make any payment on this website.")
            advice.append("If you already paid, contact your bank immediately and report at cybercrime.gov.in or call 1930.")
        elif audit["verdict"] == "SUSPICIOUS":
            advice.append("Prefer Cash on Delivery or a known payment gateway.")
            advice.append("Verify the seller through independent reviews before paying.")
        else:
            advice.append("Still double-check the URL spelling before entering payment details.")
        if any("PIN" in r for r in audit["red_flags"]):
            advice.append("Never enter your UPI PIN to receive money. A PIN is only for sending money.")
        if any("UPI ID" in r or "bank transfer" in r for r in audit["red_flags"]):
            advice.append("Avoid paying personal accounts. Use platforms that offer buyer protection.")
        for tip in dict.fromkeys(advice):
            st.info("💡 " + tip)

        st.caption("This audit is automatic and rule-based, so it cannot guarantee a site is safe.")
# ==========================================
# FEATURE 1: PHISHING AWARENESS QUIZ
# ==========================================

st.markdown("---")
st.header("🎓 Phishing Awareness Quiz")
st.write("Test your knowledge and learn how to identify online scams.")

quiz_questions = [
    {
        "question": "1. You receive an SMS saying you won a ₹10,000 shopping voucher. It asks you to click a link immediately. What is it?",
        "answer": "Scam",
        "explanation": "Unexpected prize messages and urgent links are common phishing tactics. Verify the offer through the official shopping website."
    },
    {
        "question": "2. Your bank asks you to share your OTP through a WhatsApp message to prevent account closure. Is this genuine?",
        "answer": "Scam",
        "explanation": "Never share your OTP. Fraudsters often pretend to be bank employees to steal account access."
    },
    {
        "question": "3. You open your shopping app using its official app icon and check your order history. Is this generally safe?",
        "answer": "Genuine",
        "explanation": "Using the official app directly is safer than following unexpected links in messages. Always ensure the app is authentic."
    },
    {
        "question": "4. A message says your parcel is delayed and asks you to pay a small fee through an unfamiliar link. What should you do?",
        "answer": "Scam",
        "explanation": "Unexpected delivery fee messages can be parcel phishing attempts. Check delivery status through the courier's official website."
    },
    {
        "question": "5. A customer support agent asks you to install a screen-sharing application and reveal your banking PIN. Is this safe?",
        "answer": "Scam",
        "explanation": "Sharing your banking PIN or granting remote access to an unknown person can expose your financial information."
    }
]

with st.form("phishing_quiz_form"):

    st.subheader("Answer the following questions")

    for i, question in enumerate(quiz_questions):

        st.markdown(f"**{question['question']}**")

        st.radio(
            "Select your answer:",
            ["Scam", "Genuine"],
            index=None,
            key=f"quiz_answer_{i}"
        )

        st.markdown("---")

    submit_quiz = st.form_submit_button("Submit Quiz")

if submit_quiz:

    score = 0

    for i, question in enumerate(quiz_questions):

        selected_answer = st.session_state.get(
            f"quiz_answer_{i}"
        )

        if selected_answer == question["answer"]:
            score += 1

    st.subheader("🏆 Your Quiz Results")

    st.metric(
        "Your Score",
        f"{score} / {len(quiz_questions)}"
    )

    percentage = (score / len(quiz_questions)) * 100

    st.progress(int(percentage))

    if score == 5:
        st.success("Excellent! You are a phishing awareness expert!")
    elif score >= 3:
        st.info("Good job! Keep learning to stay safe online.")
    else:
        st.warning("You need more practice identifying online scams.")

    st.subheader("📖 Answer Explanations")

    for i, question in enumerate(quiz_questions):

        selected_answer = st.session_state.get(
            f"quiz_answer_{i}"
        )

        with st.expander(f"Question {i + 1} - Explanation"):

            if selected_answer == question["answer"]:
                st.success("Correct answer!")
            elif selected_answer is None:
                st.warning("You did not answer this question.")
            else:
                st.error(
                    f"Incorrect! Correct answer: {question['answer']}"
                )

            st.write(question["explanation"])
