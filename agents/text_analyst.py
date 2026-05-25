import json
from pathlib import Path


class TextAnalyst:
    def __init__(self, client):
        self.client = client
        self.model = "gpt-4o-mini"
        self._system_prompt = Path("prompts/text_analyst.txt").read_text(encoding="utf-8")

    def analyze(self, email_text: str) -> dict:
        user_message = (
            "Analyze the following email for phishing and social engineering indicators.\n\n"
            f"--- EMAIL START ---\n{email_text}\n--- EMAIL END ---\n\n"
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
            max_tokens=1200,
        )

        raw = response.choices[0].message.content
        try:
            result = json.loads(raw)
        except Exception:
            result = {"parse_error": True, "raw_response": raw}

        result["agent_system_prompt"] = self._system_prompt
        result["agent_user_prompt"] = user_message
        return result
