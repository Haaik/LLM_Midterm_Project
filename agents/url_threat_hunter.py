import re
import json
from pathlib import Path
from tools.url_extractor import extract_urls
from tools.whois_lookup import whois_lookup
from tools.virustotal import virustotal_lookup

BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "chase", "wellsfargo", "citibank", "irs", "ebay",
    "instagram", "twitter", "linkedin", "dropbox", "docusign",
]
SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "rb.gy",
    "is.gd", "short.ly", "cutt.ly", "tiny.cc", "buff.ly",
]
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".work", ".click", ".loan", ".download", ".zip", ".mov",
]


def _heuristics(url: str) -> dict:
    score = 0
    flags = []

    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 3
        flags.append("IP-based URL (no domain name)")

    if len(url) > 75:
        score += 1
        flags.append(f"Unusually long URL ({len(url)} chars)")

    if any(s in url.lower() for s in SHORTENERS):
        score += 2
        flags.append("URL shortener detected (hides final destination)")

    if url.count("http") > 1:
        score += 3
        flags.append("Embedded redirect chain in URL")

    if url.lower().startswith("http://"):
        score += 1
        flags.append("Unencrypted HTTP (not HTTPS)")

    raw_domain = re.sub(r"https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
    if raw_domain.count(".") > 3:
        score += 1
        flags.append("Excessive subdomains")

    for brand in BRANDS:
        if brand in raw_domain and not (
            raw_domain == f"{brand}.com"
            or raw_domain.endswith(f".{brand}.com")
        ):
            score += 3
            flags.append(f"Potential {brand.title()} brand impersonation in domain")
            break

    for tld in SUSPICIOUS_TLDS:
        if raw_domain.endswith(tld) or f"{tld}/" in url.lower():
            score += 2
            flags.append(f"Suspicious TLD detected: {tld}")
            break

    if re.search(r"[@%][0-9a-fA-F]{2}", url):
        score += 2
        flags.append("Encoded/obfuscated characters in URL")

    return {"heuristic_score": min(score, 10), "flags": flags}


class URLThreatHunter:
    def __init__(self, client):
        self.client = client
        self.model = "gpt-4o-mini"
        self._system_prompt = Path("prompts/url_threat_hunter.txt").read_text(encoding="utf-8")

    def analyze(self, email_text: str) -> dict:
        urls = extract_urls(email_text)
        tool_calls = []
        url_data = []

        for url in urls[:8]:
            info = {"url": url, "heuristics": _heuristics(url)}

            whois_data = whois_lookup(url)
            info["whois"] = whois_data
            tool_calls.append({"tool": "whois_lookup", "input": url, "output": whois_data})

            vt_data = virustotal_lookup(url)
            info["virustotal"] = vt_data
            tool_calls.append({"tool": "virustotal_lookup", "input": url, "output": vt_data})

            url_data.append(info)

        user_message = (
            f"Email snippet (first 800 chars):\n{email_text[:800]}\n\n"
            f"Extracted URLs with technical analysis ({len(urls)} total):\n"
            f"{json.dumps(url_data, indent=2, default=str)}\n\n"
            "Provide your structured threat analysis as JSON."
        )

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": user_message},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=1200,
        )

        raw = response.choices[0].message.content
        try:
            result = json.loads(raw)
        except Exception:
            result = {"parse_error": True, "raw_response": raw}

        result["urls_found"] = len(urls)
        result["tool_calls"] = tool_calls
        result["agent_system_prompt"] = self._system_prompt
        result["agent_user_prompt"] = user_message
        return result
