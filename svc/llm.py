"""Optional cloud AI second opinion on an incident (Google Gemini over plain HTTPS, stdlib only).
Advisory only: it never issues a command and its cause must be one of the known CAUSES, else it is discarded.
Off unless GEMINI_API_KEY is set (a Condense env var; never commit it). Any error/timeout -> None -> behaviour unchanged."""
import json
import os
import urllib.request

from .rca import CAUSES

URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
PROMPT = ("You are a vehicle fault analyst for a SYNTHETIC EV fleet simulator. Given the incident JSON, pick the single most likely "
          "root cause from this list: {causes}. Reply ONLY with JSON: "
          '{{"cause": "<one of the list>", "confidence": <0..1>, "rationale": "<max 2 short sentences for a service engineer>"}}.\n'
          "Incident: {inc}")


def _post(url, key, body, timeout):
    r = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "x-goog-api-key": key})
    return json.load(urllib.request.urlopen(r, timeout=timeout))


def second_opinion(rca, env=os.environ, post=_post):
    """rca = the dict from Rca.analyse. -> {"cause","confidence","rationale","model"} or None."""
    key = env.get("GEMINI_API_KEY", "").strip()
    if not key: return None
    model = env.get("GEMINI_MODEL", "gemini-2.5-flash")
    inc = {k: rca.get(k) for k in ("edge_cause", "reasons", "evidence", "edge_actions", "ambient_c", "security")}
    inc["bayes_top3"] = rca.get("hypotheses", [])[:3]
    inc["last_readings"] = (rca.get("ring") or [{}])[-1]
    body = {"contents": [{"parts": [{"text": PROMPT.format(causes=", ".join(CAUSES), inc=json.dumps(inc, default=str))}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}}
    try:
        out = post(URL.format(model=model), key, body, float(env.get("GEMINI_TIMEOUT_S", "6")))
        txt = out["candidates"][0]["content"]["parts"][0]["text"].strip().removeprefix("```json").removesuffix("```")
        j = json.loads(txt)
        cause = str(j["cause"]).strip()
        if cause not in CAUSES: return None
        return {"cause": cause, "confidence": round(max(0.0, min(1.0, float(j.get("confidence", 0.5)))), 2),
                "rationale": str(j.get("rationale", ""))[:300], "model": model}
    except Exception:
        return None
