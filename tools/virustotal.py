import os
import re
import base64
import requests


def _extract_domain(url: str) -> str:
    domain = re.sub(r"https?://", "", url, flags=re.IGNORECASE)
    return domain.split("/")[0].split("?")[0].split("#")[0].split(":")[0].lower().strip()


def virustotal_lookup(url: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"skipped": True, "reason": "VIRUSTOTAL_API_KEY not set"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )

        if resp.status_code == 404:
            # URL not in VT cache — submit it
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            if submit.status_code not in (200, 202):
                return {"error": f"VT submit failed: {submit.status_code}"}
            return {"status": "submitted", "message": "URL submitted to VirusTotal for scanning; no results yet"}

        if resp.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}

        if resp.status_code != 200:
            return {"error": f"VirusTotal returned HTTP {resp.status_code}"}

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        flagged_by = [
            engine for engine, res in results.items()
            if res.get("category") in ("malicious", "suspicious")
        ]

        reputation = data.get("data", {}).get("attributes", {}).get("reputation", None)

        return {
            "domain": _extract_domain(url),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "flagged_by": flagged_by[:5],
            "reputation_score": reputation,
            "threat_label": data.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("suggested_threat_label"),
        }

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out"}
    except Exception as exc:
        return {"error": str(exc)}
