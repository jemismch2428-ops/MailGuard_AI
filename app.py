import base64
import html
import os
import re
from email.utils import parseaddr
from pathlib import Path

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).parent
MODEL_PATH = APP_DIR / "mailguard_model.joblib"
DATA_PATH = APP_DIR / "sample_emails.csv"
CREDENTIALS_PATH = APP_DIR / "credentials.json"
TOKEN_PATH = APP_DIR / "token.json"

st.set_page_config(page_title="MailGuard AI", page_icon="🛡️", layout="wide")

# Prototype signals. These are warning indicators, not proof that an email is malicious.
PHISHING_PHRASES = [
    "verify your password", "enter your password", "account will be suspended",
    "account is suspended", "confirm your password", "verify your account",
    "unusual activity", "immediately verify", "reset your password",
    "bank account blocked", "payment failed", "confirm your identity",
    "click here to avoid", "security alert"
]
SPAM_PHRASES = [
    "you have won", "claim your prize", "free gift", "limited time offer",
    "make money fast", "congratulations winner", "work from home and earn",
    "exclusive deal", "buy now", "cash prize"
]
URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.I)
EMAIL_RE = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')

def decode_b64url(value):
    if not value:
        return ""
    try:
        value += "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value.encode()).decode("utf-8", errors="replace")
    except Exception:
        return ""

def get_header(headers, name):
    for h in headers or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""

def extract_message_text(payload):
    """Extract readable text from Gmail payload without opening the message in the UI."""
    chunks = []
    def walk(part):
        mime = part.get("mimeType", "")
        body = part.get("body", {}).get("data")
        if mime == "text/plain" and body:
            chunks.append(decode_b64url(body))
        elif mime == "text/html" and body and not chunks:
            raw = decode_b64url(body)
            raw = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw)
            raw = re.sub(r"(?s)<[^>]+>", " ", raw)
            chunks.append(html.unescape(re.sub(r"\s+", " ", raw)))
        for child in part.get("parts", []) or []:
            walk(child)
    walk(payload or {})
    return "\n".join(chunks).strip()

def classify_email(subject, body, sender=""):
    text = f"{subject}\n{body}".lower()
    phishing_hits = [p for p in PHISHING_PHRASES if p in text]
    spam_hits = [p for p in SPAM_PHRASES if p in text]
    urls = URL_RE.findall(f"{subject}\n{body}")
    sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""

    # A small, transparent heuristic baseline. Never treats a single signal as certainty.
    score = 0
    reasons = []
    if phishing_hits:
        score += min(3, len(phishing_hits))
        reasons.append("Contains language commonly used in credential or account scams.")
    if len(urls) >= 2:
        score += 1
        reasons.append("Contains multiple links.")
    if re.search(r'\b(password|banking password|credit card|one-time password|otp)\b', text):
        score += 1
        reasons.append("Mentions sensitive account or payment information.")
    if re.search(r'\b(urgent|immediately|within 24 hours|suspended|blocked)\b', text):
        score += 1
        reasons.append("Uses urgency or a threat to prompt quick action.")
    if spam_hits:
        reasons.append("Contains common unsolicited promotion/prize wording.")
    if score >= 3:
        label, risk = "PHISHING", "High"
    elif score >= 1:
        label, risk = ("SPAM", "Medium") if spam_hits and not phishing_hits else ("SUSPICIOUS", "Medium")
    elif spam_hits:
        label, risk = "SPAM", "Medium"
    else:
        label, risk = "LIKELY SAFE", "Low"

    if not reasons:
        reasons = ["No major warning phrase was detected by this prototype."]
    reasons.append("This is an automated estimate; inspect sender and destination domains carefully.")
    return {"label": label, "risk": risk, "reasons": reasons, "url_count": len(urls)}

def gmail_service():
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
        from googleapiclient.discovery import build
    except ImportError as e:
        raise RuntimeError("Gmail packages are missing. Install requirements.txt first.") from e

    scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
    creds = None
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), scopes)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    if not creds or not creds.valid:
        if not CREDENTIALS_PATH.exists():
            raise RuntimeError(
                "Missing credentials.json. Follow the Gmail setup steps in README.md, "
                "download an OAuth Desktop App JSON file, and save it as credentials.json."
            )
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_PATH), scopes)
        creds = flow.run_local_server(port=0)
        TOKEN_PATH.write_text(creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def scan_unread_gmail(limit=20):
    service = gmail_service()
    response = service.users().messages().list(
        userId="me", labelIds=["UNREAD", "INBOX"], maxResults=limit
    ).execute()
    results = []
    for item in response.get("messages", []):
        msg = service.users().messages().get(
            userId="me", id=item["id"], format="full"
        ).execute()
        payload = msg.get("payload", {})
        headers = payload.get("headers", [])
        from_header = get_header(headers, "From")
        sender_name, sender_email = parseaddr(from_header)
        subject = get_header(headers, "Subject") or "(No subject)"
        body = extract_message_text(payload)
        result = classify_email(subject, body, sender_email)
        results.append({
            "Subject": subject,
            "From": from_header or "(Unknown sender)",
            "Category": result["label"],
            "Risk": result["risk"],
            "Reasons": " ".join(result["reasons"]),
            "Preview": (body[:180] + "…") if len(body) > 180 else body,
            "Message ID": item["id"],
        })
    return results

def demo_emails():
    return [
        {"Subject": "Computer Science assignment", "From": "lecturer@college.example", "Body": "Please submit your assignment by Friday. The lab is open from 10 AM to 2 PM."},
        {"Subject": "You have won a cash prize!", "From": "promo@example.test", "Body": "Congratulations! You have won a cash prize. Claim your prize now."},
        {"Subject": "Urgent bank account verification", "From": "security@example.test", "Body": "Your bank account is blocked. Verify your password immediately using this link: https://example.test/verify"},
        {"Subject": "Meeting notes", "From": "teammate@college.example", "Body": "Attached are the notes from our project meeting. Let me know if anything needs correction."},
        {"Subject": "Limited time offer", "From": "offers@example.test", "Body": "Exclusive deal, buy now and claim your free gift."},
    ]

st.title("🛡️ MailGuard AI")
st.caption("Email spam and phishing screening — student prototype")
st.warning(
    "Prototype notice: classifications can be wrong. This version uses transparent warning rules, "
    "not a production-grade security engine. Do not rely on it as the only protection."
)

with st.sidebar:
    st.header("Scan options")
    mode = st.radio("Choose source", ["Demo emails", "Gmail unread inbox"])
    limit = st.slider("Maximum unread emails to check", 5, 50, 20) if mode == "Gmail unread inbox" else 5
    st.markdown("---")
    st.caption("Gmail mode requests read-only access and does not mark messages as read or modify your inbox.")

if mode == "Demo emails":
    st.subheader("Try sample emails")
    st.write("These fictional examples let you demonstrate the scanner without connecting a real account.")
    if st.button("Scan sample emails", type="primary"):
        rows = []
        for e in demo_emails():
            r = classify_email(e["Subject"], e["Body"], e["From"])
            rows.append({
                "Subject": e["Subject"], "From": e["From"], "Category": r["label"],
                "Risk": r["risk"], "Reasons": " ".join(r["reasons"]), "Preview": e["Body"]
            })
        st.session_state["results"] = rows
else:
    st.subheader("Scan unopened Gmail messages")
    st.write("Checks messages labelled UNREAD in INBOX using Gmail API read-only access.")
    if st.button("Connect and scan unread emails", type="primary"):
        try:
            with st.spinner("Connecting to Gmail and scanning unread messages…"):
                st.session_state["results"] = scan_unread_gmail(limit)
                st.session_state["scan_error"] = None
        except Exception as e:
            st.session_state["scan_error"] = str(e)
    if st.session_state.get("scan_error"):
        st.error(st.session_state["scan_error"])

results = st.session_state.get("results", [])
if results:
    df = pd.DataFrame(results)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Emails scanned", len(df))
    c2.metric("Likely safe", int((df["Category"] == "LIKELY SAFE").sum()))
    c3.metric("Spam", int((df["Category"] == "SPAM").sum()))
    c4.metric("Phishing / suspicious", int(df["Category"].isin(["PHISHING", "SUSPICIOUS"]).sum()))
    st.subheader("Scan results")
    st.dataframe(df.drop(columns=["Message ID"], errors="ignore"), use_container_width=True, hide_index=True)
    st.subheader("Details")
    for i, row in df.iterrows():
        with st.expander(f"{row['Category']} · {row['Subject']}"):
            st.write("**Sender:**", row["From"])
            st.write("**Risk:**", row["Risk"])
            st.write("**Why flagged:**", row["Reasons"])
            st.write("**Text preview:**", row.get("Preview", ""))
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download scan report (CSV)", csv, "mailguard_scan_report.csv", "text/csv")
else:
    st.info("Choose a source and click the scan button to see results.")

st.markdown("---")
st.caption("For evaluation: demonstrate with fictional samples first. Gmail access requires the account owner's permission.")
