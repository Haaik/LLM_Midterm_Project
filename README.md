# Automated Cybersecurity Threat & Phishing Email Analyzer

**Python version:** 3.11+  
**Model:** OpenAI `gpt-4o-mini`  
**Domain:** Cybersecurity — Phishing Detection & Threat Intelligence

---

## Goal

Given the raw text of any email, the system automatically determines whether it is **SAFE**, **SUSPICIOUS**, or **PHISHING** by routing it through five specialized AI agents. Each agent performs a distinct analysis step; the output of each agent becomes the input to the next.

---

## Agents

| # | Agent | Role |
|---|-------|------|
| 1 | **Email Parser & Triage** | Extracts sender address, subject, spoofing indicators, detects mass vs spear phishing, classifies attack type (credential harvesting / BEC / malware delivery / etc.), and assigns an initial risk level. |
| 2 | **OSINT & URL Threat Hunter** | Extracts all URLs from the email. Runs heuristic analysis (IP-based URLs, brand impersonation, suspicious TLDs, URL shorteners, redirect chains) and WHOIS lookups on each domain. Produces a per-URL threat score and overall URL threat level. |
| 3 | **Social Engineering & Text Analyst** | Scans the email body for psychological manipulation tactics — urgency, fear, authority impersonation, reward bait, credential harvesting requests, generic greetings, and linguistic red flags. |
| 4 | **Threat Intelligence Synthesizer** | Cross-correlates the findings from Agents 1–3 to produce a unified threat profile: MITRE ATT&CK technique mapping, Cyber Kill Chain stage, likely victim profile, attacker goal, and threat actor type. |
| 5 | **Security Critic & Risk Scorer** | Reviews all four agents' outputs, validates that conclusions are supported by evidence, checks for false positives, resolves cross-agent conflicts, and delivers the final verdict (SAFE / SUSPICIOUS / PHISHING) with a 1–5 quality score on two dimensions: **Faithfulness** and **Completeness**. |

---

## Workflow

```
User email input
      │
      ▼
[Agent 1] Email Parser & Triage
      │  metadata, attack class, initial risk
      ▼
[Agent 2] OSINT & URL Threat Hunter
      │  URL heuristics, WHOIS data, domain scores
      ▼
[Agent 3] Social Engineering & Text Analyst
      │  psychological tactics, linguistic flags
      ▼
[Agent 4] Threat Intelligence Synthesizer
      │  MITRE mapping, kill chain, combined severity
      ▼
[Agent 5] Security Critic & Risk Scorer
      │  validation, false-positive check, quality scores
      ▼
Final structured output + run log saved to runs/<timestamp>.json
```

---

## Tools Used

- **URL extractor** (`tools/url_extractor.py`): regex-based URL extraction from raw text
- **WHOIS lookup** (`tools/whois_lookup.py`): domain registration data via `python-whois`
- **URL heuristics** (built into Agent 2): pattern-based threat scoring (brand impersonation, suspicious TLDs, shorteners, IP-based URLs, redirect chains)

---

## Setup

```bash
# 1. Clone the repository
git clone <repo-url>
cd LLM_Mid_proj

# 2. Create and activate a virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API key
# Create a .env file in the project root:
echo OPENAI_API_KEY=your-key-here > .env
```

> The `.env` file is listed in `.gitignore` and will NOT be committed.

---

## Running the System

**Interactive mode** (paste email text at the prompt):
```bash
python main.py
```

**Inline mode** (pass email as a string):
```bash
python main.py --email "From: attacker@evil.tk ..."
```

**File mode** (read email from a .txt file):
```bash
python main.py --file sample_emails/email2_suspicious.txt
```

---

## Output Description

The system prints five clearly labeled sections to the terminal, one per agent:

```
AGENT 1 — Email Parser & Triage
  Sender, Subject, Attack classification, Initial risk

AGENT 2 — OSINT & URL Threat Hunter
  Number of URLs, threat indicators, overall URL threat level

AGENT 3 — Social Engineering & Text Analyst
  Detected tactics with severity and evidence quotes, confidence %

AGENT 4 — Threat Intelligence Synthesizer
  MITRE technique, kill chain stage, attack goal, combined severity

AGENT 5 (FINAL) — Security Critic & Risk Scorer
  VERDICT: SAFE / SUSPICIOUS / PHISHING
  Confidence %
  Faithfulness score: X/5 + justification
  Completeness score: X/5 + justification
  Key evidence, false positives, recommendations, threat summary
```

Every run is also saved as a structured JSON trace to `runs/<YYYYMMDD_HHMMSS>.json` containing: user input, each agent's system prompt, user prompt, tool calls (Agent 2), and response.

---

## Sample Runs

Three example traces are included in `runs/`:

| File | Email type | Verdict |
|------|-----------|---------|
| `20260525_163045.json` | PayPal credential-harvest phishing | PHISHING (95%) |
| `20260525_163142.json` | Corporate HR benefits spear phishing | PHISHING (95%) |
| `20260525_163237.json` | Legitimate GitHub digest newsletter | SAFE (95%) |

---

## Limitations

- **WHOIS reliability**: WHOIS lookups can time out or return incomplete data for some TLDs. The system catches these errors and continues without the data.
- **No live URL scanning**: The system does not follow or render URLs. It performs static heuristic and domain-level analysis only.
- **Encoded/obfuscated content**: Emails with base64-encoded HTML bodies or heavy CSS obfuscation may confuse text extraction.
- **Context-free**: The system does not know the recipient's real email provider, company domain, or subscription history, so it may flag legitimate bulk emails as suspicious.
- **Language**: Optimized for English-language emails; performance degrades for other languages.
- **Rate limits**: The university OpenAI key has a spending cap. Processing large batches may exceed the limit.

---

## Possible Improvements

- Integrate VirusTotal or Shodan API for live URL/IP reputation lookup
- Add an HTML parser to extract and analyze links hidden inside HTML email bodies
- Add DKIM/SPF/DMARC header validation via a dedicated DNS agent
- Train a lightweight local classifier as a fast pre-filter before calling the LLM agents
- Build a Streamlit or Flask web UI for non-technical users
- Cache WHOIS results to avoid redundant lookups in batch mode
