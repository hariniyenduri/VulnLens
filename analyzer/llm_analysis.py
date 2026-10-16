
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = os.getenv(
    "OPENROUTER_MODEL",
    "openrouter/free",
)


def _get_api_key() -> str | None:
    try:
        import streamlit as st

        key = st.secrets.get("OPENROUTER_API_KEY")
        if key:
            return str(key).strip()
    except Exception:
        pass

    key = os.getenv("OPENROUTER_API_KEY")
    return key.strip() if key else None


def _fallback_assessment(context: dict[str, Any]) -> dict[str, Any]:
    detector = context.get("detector") or "unknown"
    impact = context.get("impact") or "Informational"

    if detector == "reentrancy-eth":
        return {
            "title": "Potential reentrancy vulnerability",
            "assessment": (
                "Static analysis reports an external call and a later "
                "balance update. Verify the execution order in the "
                "original Solidity source before confirming exploitability."
            ),
            "exploitability": (
                "Potentially exploitable if an external recipient can "
                "re-enter the withdrawal function before state updates."
            ),
            "attack_scenario": (
                "A recipient contract may call the withdrawal function "
                "again during the external call, if the contract's "
                "control flow and state permit it."
            ),
            "remediation": [
                "Review the Checks-Effects-Interactions pattern.",
                "Update sensitive state before external calls where appropriate.",
                "Consider a reentrancy guard.",
                "Add tests for malicious recipient contracts.",
            ],
        }

    if detector == "low-level-calls":
        return {
            "title": "Low-level external call",
            "assessment": (
                "The detector identifies a low-level external call. "
                "This finding alone does not prove a vulnerability."
            ),
            "exploitability": (
                "Depends on call-result handling, state-update ordering, "
                "and the surrounding contract logic."
            ),
            "attack_scenario": (
                "The recipient can execute code during the external call."
            ),
            "remediation": [
                "Review whether the low-level call is necessary.",
                "Check the returned success value.",
                "Review state updates around the external interaction.",
                "Test failure and reentrant-recipient scenarios.",
            ],
        }

    if detector == "solc-version":
        return {
            "title": "Solidity compiler version constraint",
            "assessment": (
                "The detector reports a compiler-version constraint. "
                "Review the specific compiler warnings and applicable "
                "known issues before determining its security impact."
            ),
            "exploitability": (
                "This finding alone does not establish a runtime exploit."
            ),
            "attack_scenario": (
                "A build may use a compiler version affected by a relevant "
                "compiler issue, if the issue applies to this contract."
            ),
            "remediation": [
                "Review Slither's compiler-version warning details.",
                "Select and test an appropriate compiler version.",
                "Run the contract's test suite after changing the compiler.",
            ],
        }

    return {
        "title": f"Finding: {detector}",
        "assessment": (
            f"Static analysis reported {detector}. Review the original "
            "source code and evidence to determine its significance."
        ),
        "exploitability": (
            f"Reported impact: {impact}. Exploitability has not been "
            "established by this fallback assessment."
        ),
        "attack_scenario": (
            "Determine whether an attacker can influence the reported "
            "code path under the contract's actual execution conditions."
        ),
        "remediation": [
            "Review the original source code and static evidence.",
            "Validate the finding against intended contract behavior.",
            "Apply an appropriate fix if the issue is confirmed.",
            "Re-run static analysis and regression tests.",
        ],
    }


def _request_openrouter(context: dict[str, Any]) -> dict[str, Any]:
    api_key = _get_api_key()

    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is missing. Check .streamlit/secrets.toml."
        )

    prompt = f"""
You are the contextual reasoning layer of VulnLens, a Solidity security analyzer.

Analyze only the supplied evidence and source context. Do not claim that a
vulnerability is confirmed unless the evidence supports that conclusion.
Clearly distinguish a detector warning from a verified exploit.

Return one valid JSON object with exactly these fields:
{{
  "title": "short finding title",
  "assessment": "evidence-grounded assessment",
  "exploitability": "qualified exploitability assessment",
  "attack_scenario": "plausible scenario or state that evidence is insufficient",
  "remediation": ["specific remediation step 1", "specific remediation step 2"]
}}

Detector: {context.get("detector")}
Impact: {context.get("impact")}
Confidence: {context.get("confidence")}
Affected function: {context.get("function")}
Reported source lines: {context.get("source_lines")}
Description: {context.get("description")}
Evidence: {context.get("evidence")}
Relevant Solidity code:
{context.get("relevant_code")}
""".strip()

    payload = {
        "model": OPENROUTER_MODEL,
        "temperature": 0.1,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a careful Solidity security reviewer. "
                    "Ground conclusions in the supplied evidence."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }

    request = urllib.request.Request(
        OPENROUTER_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8501",
            "X-Title": "VulnLens",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"OpenRouter HTTP {exc.code}: {detail[:1500]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not connect to OpenRouter: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise RuntimeError("OpenRouter request timed out.") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OpenRouter returned invalid JSON.") from exc

    if data.get("error"):
        raise RuntimeError(
            f"OpenRouter API error: {json.dumps(data['error'])[:1500]}"
        )

    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(
            f"OpenRouter returned no choices: {json.dumps(data)[:1000]}"
        )

    content = choices[0].get("message", {}).get("content", "")

    if isinstance(content, list):
        content = "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict)
        )

    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("OpenRouter returned an empty response.")

    # Handle models that wrap JSON in Markdown fences.
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[-1]
        if content.endswith("```"):
            content = content[:-3].strip()
        if content.startswith("json"):
            content = content[4:].strip()

    try:
        result = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"LLM response was not valid JSON: {content[:500]}"
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError("LLM response must be a JSON object.")

    required = ("title", "assessment", "exploitability", "attack_scenario", "remediation")
    missing = [field for field in required if field not in result]
    if missing:
        raise RuntimeError(
            f"LLM response is missing required fields: {', '.join(missing)}"
        )

    if not isinstance(result["remediation"], list):
        raise RuntimeError("LLM response 'remediation' must be a list.")

    for field in required[:-1]:
        if not isinstance(result[field], str):
            raise RuntimeError(
                f"LLM response field '{field}' must be a string."
            )

    return result


def analyze_context(
    context: dict[str, Any],
    max_attempts: int = 2,
) -> dict[str, Any]:
    last_error = None

    for attempt in range(max(1, max_attempts)):
        try:
            result = _request_openrouter(context)
            result["_llm_available"] = True
            result["_llm_model"] = OPENROUTER_MODEL
            result["_llm_error"] = None
            return result

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            RuntimeError,
            ValueError,
            OSError,
        ) as exc:
            last_error = str(exc)

            if attempt < max(1, max_attempts) - 1:
                time.sleep(2)

    fallback = _fallback_assessment(context)
    fallback["_llm_available"] = False
    fallback["_llm_model"] = OPENROUTER_MODEL
    fallback["_llm_error"] = last_error or "Unknown LLM error."
    return fallback


def analyze_all_contexts(
    contexts: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    results = {}

    for context in contexts:
        source_lines = context.get("source_lines") or []
        key = (
            f"{context.get('detector')}|"
            f"{context.get('function')}|"
            f"{','.join(map(str, source_lines))}"
        )
        results[key] = analyze_context(context)

    return results
