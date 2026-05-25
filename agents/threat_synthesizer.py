import json
from pathlib import Path


class ThreatSynthesizer:
    def __init__(self, client):
        self.client = client
        self.model = "gpt-4o-mini"
        self._system_prompt = Path("prompts/threat_synthesizer.txt").read_text(encoding="utf-8")

    def synthesize(
        self,
        email_text: str,
        parser_result: dict,
        url_result: dict,
        text_result: dict,
    ) -> dict:
        # Strip verbose internal fields to save tokens
        def _trim(d: dict) -> dict:
            return {k: v for k, v in d.items()
                    if k not in ("agent_system_prompt", "agent_user_prompt", "tool_calls")}

        user_message = (
            "Synthesize the findings from three agents into a unified threat intelligence profile.\n\n"
            f"Email snippet (first 600 chars):\n{email_text[:600]}\n\n"
            f"--- AGENT 1 (Email Parser) ---\n{json.dumps(_trim(parser_result), indent=2, default=str)}\n\n"
            f"--- AGENT 2 (URL Threat Hunter) ---\n{json.dumps(_trim(url_result), indent=2, default=str)}\n\n"
            f"--- AGENT 3 (Social Engineering Analyst) ---\n{json.dumps(_trim(text_result), indent=2, default=str)}\n\n"
            "Provide your unified threat intelligence synthesis as JSON."
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

        result["agent_system_prompt"] = self._system_prompt
        result["agent_user_prompt"] = user_message
        return result
