"""
Validates agent JSON outputs against expected schemas.
If an agent was manipulated into returning garbage, this catches it.
"""

VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "PHISHING"}
VALID_THREAT_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _check(result: dict, field: str, valid_values: set, default: str) -> str | None:
    val = result.get(field)
    if not isinstance(val, str) or val.upper() not in valid_values:
        return default
    return val.upper()


def validate_email_parser(result: dict) -> dict:
    required_str = ["sender_address", "sender_display_name", "reply_to", "subject",
                    "target_type", "attack_classification", "initial_risk_level"]
    for field in required_str:
        if field not in result or not isinstance(result[field], str):
            result[field] = "UNKNOWN"

    result["initial_risk_level"] = _check(result, "initial_risk_level", VALID_RISK_LEVELS, "UNKNOWN") or "UNKNOWN"

    for list_field in ["spoofing_indicators", "personalization_signals", "prompt_injection_indicators"]:
        if not isinstance(result.get(list_field), list):
            result[list_field] = []

    if not isinstance(result.get("attachments_mentioned"), bool):
        result["attachments_mentioned"] = False
    if not isinstance(result.get("html_content_detected"), bool):
        result["html_content_detected"] = False
    if not isinstance(result.get("prompt_injection_detected"), bool):
        result["prompt_injection_detected"] = False

    return result


def validate_url_hunter(result: dict) -> dict:
    result["overall_threat"] = _check(result, "overall_threat", VALID_THREAT_LEVELS, "UNKNOWN") or "UNKNOWN"

    if not isinstance(result.get("url_analyses"), list):
        result["url_analyses"] = []
    if not isinstance(result.get("key_indicators"), list):
        result["key_indicators"] = []
    if not isinstance(result.get("urls_found"), int):
        result["urls_found"] = 0

    return result


def validate_text_analyst(result: dict) -> dict:
    result["overall_threat"] = _check(result, "overall_threat", VALID_THREAT_LEVELS, "UNKNOWN") or "UNKNOWN"

    confidence = result.get("confidence")
    if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
        result["confidence"] = 50

    for list_field in ["social_engineering_tactics", "impersonation_targets",
                       "suspicious_requests", "ai_manipulation_evidence"]:
        if not isinstance(result.get(list_field), list):
            result[list_field] = []

    if not isinstance(result.get("ai_manipulation_attempt"), bool):
        result["ai_manipulation_attempt"] = False
    if not isinstance(result.get("generic_greeting"), bool):
        result["generic_greeting"] = False

    return result


def validate_threat_synthesizer(result: dict) -> dict:
    result["combined_severity"] = _check(result, "combined_severity", VALID_RISK_LEVELS, "UNKNOWN") or "UNKNOWN"

    for str_field in ["attack_pattern", "mitre_technique", "kill_chain_stage",
                      "likely_target", "attack_goal", "threat_actor_type"]:
        if not isinstance(result.get(str_field), str):
            result[str_field] = "UNKNOWN"

    for list_field in ["corroborating_evidence", "conflicting_signals", "secondary_techniques"]:
        if not isinstance(result.get(list_field), list):
            result[list_field] = []

    if not isinstance(result.get("prompt_injection_in_evidence"), bool):
        result["prompt_injection_in_evidence"] = False

    return result


def validate_security_critic(result: dict, prior_injection_detected: bool = False) -> dict:
    result["verdict"] = _check(result, "verdict", VALID_VERDICTS, "SUSPICIOUS") or "SUSPICIOUS"

    # Enforce: if injection was detected anywhere, verdict cannot be SAFE
    if prior_injection_detected and result["verdict"] == "SAFE":
        result["verdict"] = "SUSPICIOUS"
        result.setdefault("cross_agent_conflicts", []).append(
            "Verdict upgraded from SAFE to SUSPICIOUS: prompt injection was detected in the email."
        )

    confidence = result.get("confidence")
    if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
        result["confidence"] = 50

    for score_field in ["faithfulness_score", "completeness_score"]:
        val = result.get(score_field)
        if not isinstance(val, (int, float)) or not (1 <= val <= 5):
            result[score_field] = 3

    for list_field in ["key_evidence", "false_positives", "cross_agent_conflicts", "recommendations"]:
        if not isinstance(result.get(list_field), list):
            result[list_field] = []

    if not isinstance(result.get("agent_validations"), dict):
        result["agent_validations"] = {}

    if not isinstance(result.get("prompt_injection_detected"), bool):
        result["prompt_injection_detected"] = prior_injection_detected

    return result
