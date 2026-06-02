import re
from analyzer import (
    analyze_url,
    safe_analyze,
    detect_typosquatting,
    SUSPICIOUS_KEYWORDS,
    KNOWN_BRANDS,
)

# =========================================================
# SCAM KEYWORD DETECTOR
# =========================================================

def detect_scam_message(message: str):
    message_lower = message.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in message_lower]

    if hits:
        return {
            "risk": True,
            "reason": f"Scam keywords detected: {', '.join(hits[:5])}"
        }

    return {"risk": False, "reason": ""}


# =========================================================
# SENDER REPUTATION
# =========================================================

SUSPICIOUS_SENDER_PATTERNS = [
    r"^\+?\d{10,15}$",  # raw phone numbers
    r"no.?reply",
    r"noreply",
    r"support@(?!paypal|apple|microsoft|amazon|google|stripe|github|netflix|linkedin|facebook|instagram)",
    r"alert@",
    r"verify@",
    r"security@",
    r"admin@",
    r"service@",
    r"helpdesk@",
    r"billing@",
    r"account@",
    r"update@",
    r"notice@",
    r"customer(care|support)@",
    r"team@",
]

LEGITIMATE_SENDER_DOMAINS = [
    "paypal.com", "apple.com", "microsoft.com", "amazon.com",
    "google.com", "stripe.com", "github.com", "netflix.com",
    "linkedin.com", "facebook.com", "instagram.com",
]


def analyze_sender(sender: str):
    if not sender:
        return {"score": 0, "reasons": []}

    sender = sender.strip().lower()
    score = 0
    reasons = []

    if "@" in sender:
        domain = sender.split("@")[-1]

        # typosquatting check
        typo = detect_typosquatting(domain)
        if typo.get("risk"):
            score += 25
            reasons.append(f"Sender domain looks suspicious: {typo.get('reason','')}")

        # legitimate domain check
        if any(domain == d or domain.endswith("." + d) for d in LEGITIMATE_SENDER_DOMAINS):
            score -= 10
            reasons.append("Sender domain appears legitimate")
        else:
            for pattern in SUSPICIOUS_SENDER_PATTERNS:
                if re.search(pattern, sender):
                    score += 10
                    reasons.append("Suspicious sender pattern detected")
                    break

    else:
        # phone number detection
        if re.match(r"^\+?\d[\d\s\-]{6,}$", sender):
            score += 5
            reasons.append("Sender is an unverified phone number")

        # brand impersonation
        from analyzer import is_typosquat

        tokens = [t.lower() for t in re.split(r"[^a-z0-9]+", sender) if t]
        matched = False

        for brand in KNOWN_BRANDS:
            for token in tokens:
                if token == brand and len(tokens) > 1:
                    score += 20
                    reasons.append(f"Sender ID may impersonate '{brand}'")
                    matched = True
                    break

                if is_typosquat(token, brand):
                    score += 20
                    reasons.append(f"Sender ID resembles '{brand}' (possible spoofing)")
                    matched = True
                    break

            if matched:
                break

    return {"score": max(0, score), "reasons": reasons}


# =========================================================
# URL EXTRACTION
# =========================================================

URL_REGEX = re.compile(
    r"(https?://[^\s\"'>]+|www\.[^\s\"'>]+|[a-z0-9\-]+\.[a-z]{2,}(?:/[^\s\"'>]*)?)",
    re.IGNORECASE,
)


def extract_urls(text: str):
    return URL_REGEX.findall(text)


# =========================================================
# URGENCY DETECTION
# =========================================================

URGENCY_PATTERNS = [
    r"\bact\s+now\b",
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bexpires?\b",
    r"\bverify\s+(your|account|identity)\b",
    r"\bclick\s+(here|below)\b",
    r"\bdo\s+not\s+ignore\b",
    r"\bfinal\s+(warning|notice|reminder)\b",
    r"\bunusual\s+activity\b",
    r"\bsuspicious\s+activity\b",
    r"\bconfirm\s+your\b",
    r"\bupdate\s+(your\s+)?(billing|payment|details|info)\b",
    r"\bprize|winner|congratulations|you\s+have\s+won\b",
    r"\blimited\s+time\b",
]


def detect_urgency(text: str):
    text_lower = text.lower()
    return [p for p in URGENCY_PATTERNS if re.search(p, text_lower)]


# =========================================================
# OBFUSCATION DETECTION
# =========================================================

def detect_obfuscation(text: str):
    reasons = []

    if re.search(r"[а-яА-ЯёЁ\u0430-\u044f]", text):
        reasons.append("Cyrillic characters used (possible spoofing)")

    if re.search(r"p[^a-z0-9]{0,3}a[^a-z0-9]{0,3}y[^a-z0-9]{0,3}p", text, re.I):
        reasons.append("Obfuscated brand-like pattern detected")

    shorteners = [
        "bit.ly", "tinyurl", "t.co", "ow.ly", "goo.gl",
        "rebrand.ly", "cutt.ly", "short.io", "is.gd", "buff.ly"
    ]

    lower = text.lower()
    for s in shorteners:
        if s in lower:
            reasons.append(f"URL shortener detected ({s})")
            break

    return reasons


# =========================================================
# CORE ANALYSIS ENGINE
# =========================================================

def analyze_message(sender: str, message: str):
    score = 0
    reasons = []

    # sender
    sender_result = analyze_sender(sender)
    score += sender_result["score"]
    reasons.extend(sender_result["reasons"])

    # keywords
    kw = detect_scam_message(message)
    if kw["risk"]:
        score += 30
        reasons.append(kw["reason"])

    # urgency
    urgency_hits = detect_urgency(message)
    if urgency_hits:
        score += min(25, len(urgency_hits) * 8)
        reasons.append("Urgency / manipulation language detected")

    # obfuscation
    obf = detect_obfuscation(message)
    for r in obf:
        score += 20
        reasons.append(r)

    # URL analysis
    urls = extract_urls(message)
    if urls:
        best_score = 0
        best_url = None
        best_reasons = []

        for u in urls[:5]:
            result = safe_analyze(u)
            if result["status"] != "invalid" and result["score"] > best_score:
                best_score = result["score"]
                best_url = result["url"]
                best_reasons = result["reasons"]

        if best_url:
            score += int(best_score * 0.4)

            if best_score >= 70:
                reasons.append(f"Dangerous URL detected: {best_url}")
            elif best_score >= 40:
                reasons.append(f"Suspicious URL detected: {best_url}")

            for r in best_reasons:
                if r not in reasons:
                    reasons.append(f"URL: {r}")

    # short message + link
    if urls and len(message.split()) < 15:
        score += 10
        reasons.append("Short message with link (smishing pattern)")

    # clamp
    score = max(0, min(100, score))

    if score <= 39:
        status = "safe"
    elif score <= 69:
        status = "suspicious"
    else:
        status = "dangerous"

    return {
        "sender": sender or "Unknown",
        "message": message[:200] + ("…" if len(message) > 200 else ""),
        "score": score,
        "status": status,
        "reasons": reasons or ["No threat indicators found"],
        "urls_found": urls[:5],
    }