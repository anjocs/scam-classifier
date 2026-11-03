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
