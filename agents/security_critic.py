import json
from pathlib import Path


class SecurityCritic:
    def __init__(self, client):
        self.client = client
        self.model = "gpt-4o-mini"
        self._system_prompt = Path("prompts/security_critic.txt").read_text(encoding="utf-8")

    def evaluate(
        self,
        email_text: str,
        parser_result: dict,
        url_result: dict,
        text_result: dict,
        synth_result: dict,
    ) -> dict:
        def _trim(d: dict) -> dict:
            return {k: v for k, v in d.items()
                    if k not in ("agent_system_prompt", "agent_user_prompt", "tool_calls")}

        user_message = (
            "You are reviewing a complete phishing analysis produced by four specialized agents.\n\n"
            f"--- ORIGINAL EMAIL ---\n{email_text[:1000]}\n\n"
            f"--- AGENT 1 (Email Parser) ---\n{json.dumps(_trim(parser_result), indent=2, default=str)}\n\n"
            f"--- AGENT 2 (URL Threat Hunter) ---\n{json.dumps(_trim(url_result), indent=2, default=str)}\n\n"
            f"--- AGENT 3 (Social Engineering Analyst) ---\n{json.dumps(_trim(text_result), indent=2, default=str)}\n\n"
            f"--- AGENT 4 (Threat Synthesizer) ---\n{json.dumps(_trim(synth_result), indent=2, default=str)}\n\n"
            "Validate all four analyses, identify false positives, resolve conflicts, "
            "and provide your final verdict as JSON."
        )

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": user_message},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=1400,
        )

        raw = response.choices[0].message.content
        try:
            result = json.loads(raw)
        except Exception:
            result = {"parse_error": True, "raw_response": raw}

        result["agent_system_prompt"] = self._system_prompt
        result["agent_user_prompt"] = user_message
        return result
