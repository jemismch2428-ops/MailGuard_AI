# MailGuard AI — Student Prototype

A small Streamlit app that screens sample emails and can optionally scan unread Gmail inbox messages using the Gmail API's **read-only** scope.

## What this prototype does
- Demonstrates a dashboard for likely-safe, spam, phishing, and suspicious emails.
- Uses transparent, editable warning rules so the behavior is easy to explain.
- Demo mode works without a Gmail account.
- Optional Gmail mode lists unread inbox messages, retrieves message content through the Gmail API, and shows results in this app. It does not mark messages as read, delete, move, or send messages.
- Exports a CSV scan report.

## Important limitations
This is a college-project prototype, not production security software. The current classifier is rule-based, not a trained machine-learning model, and it can miss attacks or flag legitimate mail. Do not claim it is a fully trained AI model or that it guarantees safety. A message marked “LIKELY SAFE” is not guaranteed safe. Use a separate, properly labelled dataset and evaluation before claiming ML performance.

## Run on Windows
1. Install Python 3.10 or newer from https://www.python.org/downloads/
2. Open Command Prompt in this folder.
3. Create a virtual environment:
   ```bat
   python -m venv .venv
   .venv\Scripts\activate
   ```
4. Install packages:
   ```bat
   pip install -r requirements.txt
   ```
5. Start the app:
   ```bat
   streamlit run app.py
   ```
6. A browser window should open. Choose **Demo emails** and click **Scan sample emails**.

## Run on macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Optional Gmail setup (allow extra time)
Gmail integration requires an OAuth Desktop App credential file and explicit authorization by the account owner.

1. Open Google Cloud Console: https://console.cloud.google.com/
2. Create/select a project and enable **Gmail API**.
3. Configure the OAuth consent screen for testing and add your own Google account as a test user if required.
4. Create an OAuth client ID of type **Desktop app** and download its JSON file.
5. Rename the downloaded file to `credentials.json` and place it beside `app.py`.
6. Run the app, choose **Gmail unread inbox**, and click **Connect and scan unread emails**.
7. Complete Google's consent flow in the browser. The app saves a local `token.json` for subsequent runs.

The app requests only `https://www.googleapis.com/auth/gmail.readonly`. Do not share `credentials.json` or `token.json`; they are sensitive. If you use a shared or college computer, remove them when finished and revoke access in your Google Account settings.

Google may require additional consent-screen setup or verification depending on how the app is configured. If Gmail setup takes too long, use Demo emails for the evaluation.

## Suggested evaluation demo
1. Start the app and scan fictional sample emails.
2. Point out the subject, category, risk level, reasons, dashboard counters, and CSV report.
3. Explain that “without opening” means the app reads message data through authorized API access while the user does not open the message in Gmail.
4. Explain the limitation honestly: rule-based prototype, not guaranteed detection; Gmail mode checks unread inbox messages when you press the button, it is not yet a continuously running background service.

## Future improvements
- Train and evaluate a text-classification model on a properly licensed labelled dataset.
- Add sender-domain and URL reputation checks.
- Add scheduled polling/notifications with secure deployment.
- Add an allow-list, false-positive review, and privacy-preserving logging.
