# SentinelX — Job Scam Guard

SentinelX is a multilingual, accessible job-scam awareness and screening prototype.

## Features
- Job-offer and recruiter-message risk analyzer
- Job-scam warning signs and safe next steps
- Cybersecurity awareness lessons
- Quiz with answers and explanations
- Language selector: English, Arabic, Hindi, French, Spanish
- Right-to-left layout for Arabic
- Browser text-to-speech
- Adjustable text size
- High-contrast mode
- Keyboard-friendly controls
- Screen-reader labels and skip navigation
- Local rule-based analysis with no API key

## Run in VS Code
1. Open this folder in VS Code.
2. Open a terminal in the workspace.
3. Run `python app.py` or `py app.py`.
4. Open the browser to `http://127.0.0.1:5000`.

You can also run the app with `flask run` after setting `FLASK_APP=app.py`.

## Best demo flow
1. Open **Job Scam Analyzer**.
2. Choose **Agentic Audit** mode to show the multi-step analysis pipeline.
3. Select **Load scam example**.
4. Click **Analyze Job Offer**.
5. Show the risk score, confidence summary, verification snapshot, and safety checklist.
6. Open **Learn**.
7. Open **Quiz** and answer one question.
8. Change the language to Arabic or Hindi.
9. Open **Accessibility** and demonstrate text size, high contrast, or text-to-speech.

## Important
This is an educational prototype. It does not prove that a job offer is genuine or fraudulent.

## Production improvements
- Add a secure backend
- Connect a verified AI model
- Add official company-domain checking
- Add reporting links for local authorities
- Translate all dynamic analysis output
- Conduct WCAG accessibility testing
