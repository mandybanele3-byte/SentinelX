from flask import Flask, jsonify, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

SAFE_PAYMENT_PATTERNS = [
    r"\bno payment (?:is required|required|is needed|needed|is necessary|necessary)\b",
    r"\bno recruitment fees\b",
    r"\bthere (?:are|is) no recruitment fees\b",
    r"\bapplying is free\b",
    r"\bwe will never ask you to pay\b",
    r"\bno visa fee(?: is charged| is required| is needed| is necessary)?\b",
    r"\bno (?:recruitment|training|visa|application) fees?\b",
]

SUSPICIOUS_PAYMENT_PATTERNS = [
    r"\bpay\s+(?:aed|usd|dhs|eur|gbp|\$)?\s*\d{2,}\b",
    r"\bsend payment\b",
    r"\bregistration fee\b",
    r"\binterview fee\b",
    r"\bvisa processing fee\b",
    r"\bimmigration fee\b",
    r"\btraining fee\b",
    r"\bequipment fee\b",
    r"\bsecurity deposit\b",
    r"\brefundable deposit\b",
    r"\bprocessing charge\b",
    r"\bwire transfer\b",
    r"\bwestern union\b",
    r"\bmoneygram\b",
    r"\bgift card\b",
    r"\bbitcoin\b",
    r"\bcryptocurrency\b",
]

SENSITIVE_PATTERNS = [
    r"\bpassport copy\b",
    r"\bpassport\b",
    r"\bemirates id\b",
    r"\bnational id\b",
    r"\bbank account\b",
    r"\bbank details\b",
    r"\bcard number\b",
    r"\bcvv\b",
    r"\bpin\b",
    r"\bpassword\b",
    r"\botp\b",
    r"\bone-time password\b",
    r"\bverification code\b",
    r"\blogin details\b",
]

RECRUITMENT_PROCESS_PATTERNS = [
    r"\bno interview\b",
    r"\binstant hiring\b",
    r"\bhired immediately\b",
    r"\bguaranteed job\b",
    r"\bguaranteed employment\b",
    r"\bselected immediately\b",
    r"\bautomatic selection\b",
    r"\boffer letter without interview\b",
]

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bact now\b",
    r"\btoday only\b",
    r"\blast chance\b",
    r"\brespond immediately\b",
    r"\blimited time\b",
    r"\bwithin one hour\b",
    r"\boffer expires today\b",
    r"\bpay immediately\b",
]

UNREALISTIC_REWARD_PATTERNS = [
    r"\bvery high salary\b",
    r"\bhigh salary\b",
    r"\beasy money\b",
    r"\bearn per day\b",
    r"\bguaranteed income\b",
    r"\bhuge income\b",
    r"\bwork one hour per day\b",
    r"\bno experience required\b.*\bhigh pay\b",
]

MESSAGING_ONLY_PATTERNS = [
    r"\bwhatsapp only\b",
    r"\btelegram only\b",
    r"\bcontact only on whatsapp\b",
    r"\bmessage us only on telegram\b",
    r"\bno email communication\b",
    r"\bdo not contact the company\b",
]

SUSPICIOUS_LINK_KEYWORDS = [
    "visa-job",
    "instant-hiring",
    "recruitment-fee",
    "claim-job",
    "job-payment",
    "fast-visa",
]

UNCOMMON_TLDS = {
    "xyz",
    "top",
    "click",
    "buzz",
    "monster",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "t.co",
    "rb.gy",
    "is.gd",
    "shorturl.at",
}

EMAIL_PATTERN = re.compile(
    r"([a-zA-Z0-9.+_-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)


def normalize(text: str) -> str:
    return (text or "").strip().lower()


def extract_email(sender: str) -> str | None:
    match = EMAIL_PATTERN.search(sender)
    return match.group(1).lower() if match else None


def find_spans(text: str, patterns: list[str]) -> list[tuple[int, int]]:
    spans = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            spans.append((match.start(), match.end()))
    return spans


def overlaps_safe_span(start: int, end: int, safe_spans: list[tuple[int, int]]) -> bool:
    return any(start < safe_end and end > safe_start for safe_start, safe_end in safe_spans)


def contains_suspicious_payment(message: str) -> bool:
    safe_spans = find_spans(message, SAFE_PAYMENT_PATTERNS)
    for pattern in SUSPICIOUS_PAYMENT_PATTERNS:
        for match in re.finditer(pattern, message):
            if not overlaps_safe_span(match.start(), match.end(), safe_spans):
                return True
    return False


def contains_phrase(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def is_raw_ip(hostname: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname))


def has_suspicious_subdomain(hostname: str) -> bool:
    parts = hostname.split('.')
    if len(parts) > 3 and len(parts[0]) > 20:
        return True
    return any(keyword in hostname for keyword in SUSPICIOUS_LINK_KEYWORDS)


def analyze_link(link: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    score = 0
    if not link:
        return score, warnings

    parsed = urlparse(link.strip())
    hostname = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()

    if not hostname:
        return score, warnings

    if scheme != "https":
        score += 10
        warnings.append("The link does not use a secure HTTPS connection.")
    else:
        score += 3

    if hostname in SHORTENER_DOMAINS or any(hostname.endswith(f".{short}") for short in SHORTENER_DOMAINS):
        score += 12
        warnings.append("The link uses a shortened URL, which should be inspected before clicking.")

    if is_raw_ip(hostname):
        score += 12
        warnings.append("The link uses a raw IP address rather than a standard domain name.")

    if parsed.username or parsed.password or re.search(r"@[^/]+", link):
        score += 12
        warnings.append("The link contains embedded credentials or an unexpected @ sign.")

    if hostname.startswith("xn--"):
        score += 10
        warnings.append("The link uses punycode encoding and should be verified carefully.")

    if has_suspicious_subdomain(hostname) or any(keyword in parsed.path.lower() for keyword in SUSPICIOUS_LINK_KEYWORDS):
        score += 10
        warnings.append("The link includes suspicious words or a misleading domain structure.")

    tld = hostname.rsplit('.', 1)[-1]
    if tld in UNCOMMON_TLDS:
        score += 5
        warnings.append("The link uses an uncommon top-level domain and may require extra verification.")

    return score, warnings


def analyze_job_message(message: str, sender: str = "", link: str = "") -> dict:
    normalized_message = normalize(message)
    score = 5
    warnings: list[str] = []

    if contains_suspicious_payment(normalized_message):
        score += 28
        warnings.append("The recruiter asks you to pay money.")

    if contains_phrase(normalized_message, SENSITIVE_PATTERNS):
        score += 25
        warnings.append(
            "The message requests sensitive personal or financial information."
        )

    if contains_phrase(normalized_message, RECRUITMENT_PROCESS_PATTERNS):
        score += 24
        warnings.append(
            "The offer skips the normal recruitment process."
        )

    if contains_phrase(normalized_message, URGENCY_PATTERNS):
        score += 10
        warnings.append(
            "The message creates pressure or urgency."
        )

    if contains_phrase(normalized_message, UNREALISTIC_REWARD_PATTERNS):
        score += 12
        warnings.append(
            "The salary or reward may be unrealistic."
        )

    if contains_phrase(normalized_message, MESSAGING_ONLY_PATTERNS):
        score += 12
        warnings.append(
            "Recruitment is restricted to a messaging app, which may be suspicious."
        )

    email_address = extract_email(sender)
    if email_address:
        domain = email_address.split("@", 1)[-1]
        if domain in FREE_EMAIL_DOMAINS:
            score += 10
            warnings.append(
                "The recruiter appears to use a personal email provider instead of a verifiable company domain."
            )

    link_score, link_warnings = analyze_link(link)
    score += link_score
    for warning in link_warnings:
        if warning not in warnings:
            warnings.append(warning)

    if normalized_message.count("!") >= 3:
        score += 3
        warnings.append(
            "The message contains excessive punctuation, which is a common scam signal."
        )

    capital_words = re.findall(r"\b[A-Z]{4,}\b", message)
    if len(capital_words) >= 2:
        score += 3
        warnings.append(
            "Several words are written in all capitals, which can indicate aggressive or deceptive messaging."
        )

    score = max(0, min(score, 100))

    if score >= 85:
        level = "Critical Risk"
        explanation = (
            "This offer contains multiple strong warning signs. Do not send money, documents, banking information, passwords, or OTP codes until the employer is independently verified."
        )
    elif score >= 65:
        level = "High Risk"
        explanation = (
            "Multiple strong warning signs were detected. Verify this offer directly through the official company website before responding."
        )
    elif score >= 35:
        level = "Medium Risk"
        explanation = (
            "Some elements of this offer require caution and verification. Review the recruiter identity, email domain, and link destination carefully."
        )
    else:
        level = "Low Risk"
        explanation = (
            "Few obvious warning signs were found, but automated screening cannot prove that this offer is genuine."
        )

    if not warnings:
        warnings.append(
            "No major warning signs were detected, but the employer should still be verified."
        )

    actions = [
        "Do not pay recruitment, visa, training, registration, or equipment fees.",
        "Do not share passwords, OTP codes, card details, or banking credentials.",
        "Verify the vacancy on the organisation's official careers page.",
        "Contact the organisation using contact details found independently.",
        "Report and block the recruiter if the offer cannot be verified.",
    ]

    return {
        "score": score,
        "level": level,
        "warnings": warnings,
        "explanation": explanation,
        "actions": actions,
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}

    message = (data.get("message") or "").strip()
    sender = (data.get("sender") or "").strip()
    link = (data.get("link") or "").strip()

    if not message:
        return jsonify({"error": "Please enter a recruiter message."}), 400

    result = analyze_job_message(message=message, sender=sender, link=link)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
