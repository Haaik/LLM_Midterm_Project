#!/usr/bin/env python3
"""
Automated Cybersecurity Threat & Phishing Email Analyzer
Five-Agent AI System

Agents:
  1. Email Parser & Triage        — structural metadata extraction and initial risk triage
  2. OSINT & URL Threat Hunter    — URL heuristics, WHOIS lookups, domain reputation
  3. Social Engineering Analyst   — psychological manipulation and linguistic analysis
  4. Threat Intel Synthesizer     — cross-agent synthesis, MITRE mapping, kill chain
  5. Security Critic & Risk Scorer— validation, false-positive check, quality scoring (faithfulness + completeness)
"""
import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

import ssl
import certifi
import httpx
from dotenv import load_dotenv
from openai import OpenAI

from agents.email_parser import EmailParser
from agents.url_threat_hunter import URLThreatHunter
from agents.text_analyst import TextAnalyst
from agents.threat_synthesizer import ThreatSynthesizer
from agents.security_critic import SecurityCritic

load_dotenv()

WIDTH = 64


def _bar(title: str = "") -> None:
    if title:
        print(f"\n{'=' * WIDTH}")
        print(f"  {title}")
        print(f"{'=' * WIDTH}")
    else:
        print(f"\n{'=' * WIDTH}")


def _get_input(args) -> str:
    if args.email:
        return args.email
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")

    print("Paste the email content below.")
    print("Press ENTER twice when finished:\n")
    lines: list[str] = []
    blanks = 0
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            blanks += 1
            if blanks >= 2:
                break
            lines.append(line)
        else:
            blanks = 0
            lines.append(line)
    return "\n".join(lines).strip()


def _save_run(log: dict) -> Path:
    runs_dir = Path("runs")
    runs_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = runs_dir / f"{ts}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2, ensure_ascii=False, default=str)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="5-Agent Phishing Email Analyzer"
    )
    parser.add_argument("--email", help="Email text to analyze (pass inline)")
    parser.add_argument("--file", help="Path to a .txt file containing the email")
    args = parser.parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set. Add it to your .env file and retry.")
        sys.exit(1)

    http_client = httpx.Client(verify=certifi.where())
    client = OpenAI(api_key=api_key, http_client=http_client)

    _bar("Cybersecurity Threat & Phishing Email Analyzer")
    print("  Five-Agent AI System  |  Model: gpt-4o-mini")

    email_text = _get_input(args)
    if not email_text:
        print("ERROR: No email content provided.")
        sys.exit(1)

    run_log: dict = {
        "timestamp": datetime.now().isoformat(),
        "user_input": email_text,
        "agents": {},
        "final_answer": None,
    }

    _bar("USER INPUT")
    preview = email_text[:500] + ("..." if len(email_text) > 500 else "")
    print(preview)

    # ── Agent 1: Email Parser & Triage ────────────────────────
    _bar("AGENT 1 — Email Parser & Triage")
    print("Extracting email structure, metadata, and performing initial triage…\n")

    ep = EmailParser(client)
    parser_result = ep.analyze(email_text)
    run_log["agents"]["email_parser"] = parser_result

    print(f"Sender          : {parser_result.get('sender_address', 'unknown')}")
    print(f"Subject         : {parser_result.get('subject', 'unknown')}")
    print(f"Target type     : {parser_result.get('target_type', 'UNKNOWN')}")
    print(f"Attack class    : {parser_result.get('attack_classification', 'UNKNOWN')}")
    print(f"Initial risk    : {parser_result.get('initial_risk_level', 'UNKNOWN')}")
    spoofing = parser_result.get("spoofing_indicators", [])
    if spoofing:
        print(f"\nSpoofing indicators: {', '.join(spoofing[:3])}")
    if parser_result.get("triage_notes"):
        print(f"\nTriage notes: {parser_result['triage_notes']}")

    # ── Agent 2: OSINT & URL Threat Hunter ────────────────────
    _bar("AGENT 2 — OSINT & URL Threat Hunter")
    print("Extracting URLs, running heuristics, querying WHOIS…\n")

    hunter = URLThreatHunter(client)
    url_result = hunter.analyze(email_text)
    run_log["agents"]["url_threat_hunter"] = url_result

    print(f"URLs detected   : {url_result.get('urls_found', 0)}")
    print(f"Threat level    : {url_result.get('overall_threat', 'UNKNOWN')}")
    key_inds = url_result.get("key_indicators", [])
    if key_inds:
        print("\nKey indicators:")
        for ind in key_inds[:5]:
            print(f"  • {ind}")
    if url_result.get("summary"):
        print(f"\nSummary: {url_result['summary']}")

    # ── Agent 3: Social Engineering & Text Analyst ────────────
    _bar("AGENT 3 — Social Engineering & Text Analyst")
    print("Scanning for psychological manipulation patterns…\n")

    analyst = TextAnalyst(client)
    text_result = analyst.analyze(email_text)
    run_log["agents"]["text_analyst"] = text_result

    print(f"Threat level    : {text_result.get('overall_threat', 'UNKNOWN')}")
    print(f"Confidence      : {text_result.get('confidence', '?')}%")
    tactics = text_result.get("social_engineering_tactics", [])
    if tactics:
        print("\nDetected tactics:")
        for t in tactics[:4]:
            if isinstance(t, dict):
                sev = t.get("severity", "")
                name = t.get("tactic", "")
                ev = t.get("evidence", "")
                print(f"  [{sev}] {name}")
                if ev:
                    print(f"        Evidence: \"{str(ev)[:80]}\"")
            else:
                print(f"  • {t}")
    if text_result.get("summary"):
        print(f"\nSummary: {text_result['summary']}")

    # ── Agent 4: Threat Intel Synthesizer ────────────────────
    _bar("AGENT 4 — Threat Intelligence Synthesizer")
    print("Mapping attack patterns, MITRE techniques, kill chain stage…\n")

    synthesizer = ThreatSynthesizer(client)
    synth_result = synthesizer.synthesize(email_text, parser_result, url_result, text_result)
    run_log["agents"]["threat_synthesizer"] = synth_result

    print(f"Attack pattern  : {synth_result.get('attack_pattern', 'UNKNOWN')}")
    print(f"MITRE technique : {synth_result.get('mitre_technique', 'N/A')}")
    print(f"Kill chain stage: {synth_result.get('kill_chain_stage', 'UNKNOWN')}")
    print(f"Attack goal     : {synth_result.get('attack_goal', 'UNKNOWN')}")
    print(f"Combined severity: {synth_result.get('combined_severity', 'UNKNOWN')}")
    corr = synth_result.get("corroborating_evidence", [])
    if corr:
        print("\nCorroborating evidence:")
        for c in corr[:3]:
            print(f"  • {c}")
    if synth_result.get("synthesis_summary"):
        print(f"\nSummary: {synth_result['synthesis_summary']}")

    # ── Agent 5: Security Critic & Risk Scorer ───────────────
    _bar("AGENT 5 — Security Critic & Risk Scorer")
    print("Validating all findings, checking for false positives, scoring quality…\n")

    critic = SecurityCritic(client)
    critique = critic.evaluate(email_text, parser_result, url_result, text_result, synth_result)
    run_log["agents"]["security_critic"] = critique
    run_log["final_answer"] = critique

    # ── Final Structured Answer ───────────────────────────────
    _bar("FINAL STRUCTURED ANSWER")

    verdict = critique.get("verdict", "UNKNOWN").upper()
    confidence = critique.get("confidence", "?")

    print(f"\n  VERDICT   : {verdict}")
    print(f"  Confidence: {confidence}%\n")

    print("  Analysis Quality Scores:")
    print(
        f"    Faithfulness : {critique.get('faithfulness_score', '?')}/5"
        f" — {critique.get('faithfulness_justification', '')}"
    )
    print(
        f"    Completeness : {critique.get('completeness_score', '?')}/5"
        f" — {critique.get('completeness_justification', '')}"
    )

    evidence = critique.get("key_evidence", [])
    if evidence:
        print("\n  Key Evidence:")
        for ev in evidence[:5]:
            print(f"    • {ev}")

    fps = critique.get("false_positives", [])
    if fps:
        print("\n  Possible False Positives:")
        for fp in fps:
            print(f"    ~ {fp}")

    conflicts = critique.get("cross_agent_conflicts", [])
    if conflicts:
        print("\n  Cross-Agent Conflicts:")
        for c in conflicts:
            print(f"    ! {c}")

    recs = critique.get("recommendations", [])
    if recs:
        print("\n  Recommendations:")
        for r in recs:
            print(f"    → {r}")

    if critique.get("threat_summary"):
        print(f"\n  Threat Summary:\n  {critique['threat_summary']}")

    log_path = _save_run(run_log)
    _bar()
    print(f"  Run log saved → {log_path}")
    _bar()


if __name__ == "__main__":
    main()
