import re
from urllib.parse import urlparse
import Levenshtein

# =========================================================
# DATASETS
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login","signin","verify","verification","secure","account","update",
    "confirm","password","reset","unlock","suspended","limited","urgent",
    "billing","invoice","payment","refund","security","alert","warning",
    "prize","winner","free","gift","bonus","claim","crypto","wallet",
    "seed","recovery","helpdesk","support"
]

KNOWN_BRANDS = [
    "paypal","apple","icloud","microsoft","google","facebook","amazon",
    "netflix","instagram","whatsapp","telegram","github","binance",
    "coinbase","stripe","shopify","linkedin","twitter","x"
]

TRUSTED_DOMAINS = [
    "google.com","youtube.com","github.com","stackoverflow.com",
    "wikipedia.org","mozilla.org","cloudflare.com","microsoft.com",
    "apple.com","amazon.com","facebook.com","instagram.com",
    "linkedin.com","netflix.com","spotify.com","discord.com",
    "openai.com","paypal.com","stripe.com","binance.com",
    "coinbase.com","dropbox.com","office.com","live.com","x.com"
]

# =========================================================
# NORMALIZATION
# =========================================================

CHAR_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "$": "s"
})
# =========================================================
# URL checker core functions
# =========================================================
def extract_root(domain):
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return domain
    return parts[-2] + "." + parts[-1]


def get_domain_name(domain):
    return domain.split(".")[0]


def normalize(domain):
    return domain.translate(CHAR_MAP)

# =========================================================
# TYPOSQUATTING CORE (FIXED)
# =========================================================

def is_typosquat(domain, brand):
    domain = domain.replace("-", "").lower()
    brand = brand.lower()

    domain_name = get_domain_name(domain)
    domain_name = normalize(domain_name)
    brand = normalize(brand)

    if len(domain_name) < 3:
        return False

    distance = Levenshtein.distance(domain_name, brand)
    max_len = max(len(domain_name), len(brand))

    similarity = 1 - (distance / max_len)

   
    return similarity >= 0.65 and similarity < 1.0


def detect_typosquatting(domain):
    domain = domain.lower().replace("-", "")
    domain_name = normalize(get_domain_name(domain))

    root = extract_root(domain)

    for brand in KNOWN_BRANDS:
        brand = brand.lower()

        # skip real domains
        if root == brand or root == brand + ".com":
            continue

        # strong impersonation patterns
        if domain_name.startswith(brand) or domain_name.endswith(brand):
            return {
                "risk": True,
                "reason": f"Brand impersonation pattern ({brand})"
            }

        # fuzzy similarity
        if is_typosquat(domain, brand):
            return {
                "risk": True,
                "reason": f"Typosquatting detected ({brand})"
            }

    return {"risk": False}

# =========================================================
# INPUT VALIDATION
# =========================================================

def is_valid_input(user_input):
    user_input = user_input.strip()

    if " " in user_input:
        return False, None

    if not (
        user_input.startswith("http://") or
        user_input.startswith("https://") or
        "." in user_input or
        re.match(r"^\d+\.", user_input)
    ):
        return False, None

    temp_input = user_input
    if not user_input.startswith(("http://", "https://")):
        temp_input = "https://" + user_input

    parsed = urlparse(temp_input)
    domain = parsed.netloc.lower()

    if not domain:
        return False, None

    ip_pattern = r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
    domain_pattern = r"^([a-z0-9-]+\.)+[a-z]{2,}$"

    if re.match(ip_pattern, domain):
        return True, temp_input

    if re.match(domain_pattern, domain):
        return True, temp_input

    return False, None

# =========================================================
# MAIN ENTRY
# =========================================================

def safe_analyze(user_input):
    valid, cleaned_url = is_valid_input(user_input)

    if not valid:
        return {
            "url": user_input,
            "score": 0,
            "status": "invalid",
            "reasons": ["Invalid input"]
        }

    return analyze_url(cleaned_url)

# =========================================================
# CORE ENGINE (FIXED ORDER)
# =========================================================

def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full = url.lower()

    score = 0
    reasons = []

    is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+", domain)
    has_login = "login" in full

    # =========================================================
    # HARD RULES
    # =========================================================

    if is_ip and has_login:
        return {
            "url": url,
            "score": 95,
            "status": "dangerous",
            "reasons": ["IP-based login endpoint (high phishing risk)"]
        }

    # =========================================================
    # STRUCTURE
    # =========================================================

    if parsed.scheme != "https":
        score += 10
        reasons.append("No HTTPS encryption")

    if len(url) > 75:
        score += 10
        reasons.append("Unusually long URL")

    if is_ip:
        score += 25
        reasons.append("IP address used instead of domain")

    # =========================================================
    # INTENT SIGNALS
    # =========================================================

    keyword_hits = sum(1 for w in SUSPICIOUS_KEYWORDS if w in full)
    if keyword_hits:
        score += min(30, keyword_hits * 15)
        reasons.append(f"Phishing keywords detected ({keyword_hits})")

    # =========================================================
    # TYPOSQUATTING
    # =========================================================

    typo = detect_typosquatting(domain)
    if typo["risk"]:
        score += 60
        reasons.append(typo["reason"])

    # =========================================================
    # BRAND RISK
    # =========================================================

    root = extract_root(domain)

    for brand in KNOWN_BRANDS:
        brand = brand.lower()

        if root == brand:
            score += 30
            reasons.append(f"Direct impersonation of {brand}")
            break

        if domain.startswith(brand + "-") or domain.endswith("-" + brand):
            score += 20
            reasons.append(f"Suspicious brand pattern ({brand})")
            break

    # =========================================================
    # INFRASTRUCTURE
    # =========================================================

    if domain.endswith((".xyz", ".top", ".tk", ".info", ".biz")):
        score += 15
        reasons.append("High-risk domain extension")

    is_trusted = any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS)

    if is_trusted:
        score = max(0, score - 40)
        reasons.append("Trusted domain")

    # =========================================================
    # FINAL CLASSIFICATION
    # =========================================================

    if score <= 39:
        status = "safe"
    elif score <= 69:
        status = "suspicious"
    else:
        status = "dangerous"

    return {
        "url": url,
        "score": min(100, score),
        "status": status,
        "reasons": reasons
    }