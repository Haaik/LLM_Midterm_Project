import os
import sys
import json

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

import certifi
import httpx
from flask import Flask, render_template, request, Response, stream_with_context
from dotenv import load_dotenv
from openai import OpenAI

from agents.email_parser import EmailParser
from agents.url_threat_hunter import URLThreatHunter
from agents.text_analyst import TextAnalyst
from agents.threat_synthesizer import ThreatSynthesizer
from agents.security_critic import SecurityCritic

load_dotenv()

app = Flask(__name__)


def _make_client():
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set in .env")
    http_client = httpx.Client(verify=certifi.where())
    return OpenAI(api_key=api_key, http_client=http_client)


def _event(name: str, data: dict) -> str:
    payload = json.dumps(data, default=str, ensure_ascii=False)
    return f"event: {name}\ndata: {payload}\n\n"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    email_text = request.form.get("email_text", "").strip()
    if not email_text:
        return Response(_event("error", {"message": "No email content provided."}),
                        mimetype="text/event-stream")

    def generate():
        try:
            client = _make_client()
        except RuntimeError as e:
            yield _event("error", {"message": str(e)})
            return

        yield _event("status", {"agent": 1, "message": "Email Parser & Triage running..."})
        ep = EmailParser(client)
        parser_result = ep.analyze(email_text)
        clean_parser = {k: v for k, v in parser_result.items()
                        if k not in ("agent_system_prompt", "agent_user_prompt")}
        yield _event("agent1", clean_parser)

        yield _event("status", {"agent": 2, "message": "OSINT & URL Threat Hunter running..."})
        hunter = URLThreatHunter(client)
        url_result = hunter.analyze(email_text)
        clean_url = {k: v for k, v in url_result.items()
                     if k not in ("agent_system_prompt", "agent_user_prompt")}
        yield _event("agent2", clean_url)

        yield _event("status", {"agent": 3, "message": "Social Engineering Analyst running..."})
        analyst = TextAnalyst(client)
        text_result = analyst.analyze(email_text)
        clean_text = {k: v for k, v in text_result.items()
                      if k not in ("agent_system_prompt", "agent_user_prompt")}
        yield _event("agent3", clean_text)

        yield _event("status", {"agent": 4, "message": "Threat Intel Synthesizer running..."})
        synthesizer = ThreatSynthesizer(client)
        synth_result = synthesizer.synthesize(email_text, parser_result, url_result, text_result)
        clean_synth = {k: v for k, v in synth_result.items()
                       if k not in ("agent_system_prompt", "agent_user_prompt")}
        yield _event("agent4", clean_synth)

        yield _event("status", {"agent": 5, "message": "Security Critic & Risk Scorer running..."})
        critic = SecurityCritic(client)
        critique = critic.evaluate(email_text, parser_result, url_result, text_result, synth_result)
        clean_critique = {k: v for k, v in critique.items()
                          if k not in ("agent_system_prompt", "agent_user_prompt")}
        yield _event("agent5", clean_critique)

        yield _event("done", {"message": "Analysis complete."})

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
