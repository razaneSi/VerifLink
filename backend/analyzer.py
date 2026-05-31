#core logic of VerifLink
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [

]

KNOWN_BRANDS = [

]

def analyze_url(url):
    score = 0
    reasons = []
 
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
   #https checking
    if parsed_url.scheme != "https":
        score += 20
        reasons.append("No HTTPS encryption")
 
     #ip addrs checking
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
         score += 30
         reasons.append("IP address used instad of domain name")
 
     #suspicious keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 15
            reasons.append(f"Suspicious keyword found: {word}")    
            break
     #url length checking
    if len(url) > 75:
          score += 10
          reasons.append("URL is unusually long")
 
     # Typosquatting sim
    for brand in KNOWN_BRANDS:
        if brand in domain:
            score += 40
            reasons.append(f"Possible Spoofing of {brand}")
            break
     
     #final classification
    if score<= 30:
        status = "Safe"
    elif score <= 60:
        status = "Suspicious"
    else:
          status = "dangerous"
    
    return {
        "url": url,
        "score": score,
        "status": status,
        "reasons": reasons
    }
       




