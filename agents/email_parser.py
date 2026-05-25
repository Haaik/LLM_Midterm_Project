import json
from pathlib import Path
from tools.input_sanitizer import scan_for_injection, wrap_email_for_agent
from tools.output_validator import validate_email_parser


class EmailParser:
    def __init__(self, client):
        self.client = client
        self.model = "gpt-4o-mini"
        self._system_prompt = Path("prompts/email_parser.txt").read_text(encoding="utf-8")

    def analyze(self, email_text: str) -> dict:
        injection_scan = scan_for_injection(email_text)
        wrapped = wrap_email_for_agent(email_text, injection_scan)

        user_message = (
            "Parse and triage the following email. Extract all structural metadata "
            "and perform initial risk classification.\n\n"
            f"{wrapped}\n\n"
            "Provide your structured analysis as JSON."
        )

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": user_message},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=1000,
        )

        raw = response.choices[0].message.content
        try:
            result = json.loads(raw)
        except Exception:
            result = {"parse_error": True, "raw_response": raw}

        result = validate_email_parser(result)

        # Merge pre-LLM injection scan findings
        if injection_scan["injection_detected"] and not result.get("prompt_injection_detected"):
            result["prompt_injection_detected"] = True
            existing = result.get("prompt_injection_indicators", [])
            result["prompt_injection_indicators"] = existing + injection_scan["injection_snippets"]

        result["_injection_scan"] = injection_scan
        result["agent_system_prompt"] = self._system_prompt
        result["agent_user_prompt"] = user_message
        return result
