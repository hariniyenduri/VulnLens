from pathlib import Path
from typing import Any

from analyzer.context_builder import build_all_contexts
from analyzer.evidence import extract_all_evidence
from analyzer.preprocessor import preprocess_contract
from analyzer.static_analysis import run_slither


LLM_ELIGIBLE_IMPACTS = {
    "High",
    "Medium",
    "Low",
}


def analyze_contract(
    filename: str,
    source_code: str,
) -> dict[str, Any]:
    """
    Run the complete VulnLens analysis pipeline.

    Pipeline:
        Preprocessing
        -> Static Analysis
        -> Evidence Extraction
        -> Context Selection
        -> LLM-eligible finding selection
    """

    preprocessing = preprocess_contract(
        filename,
        source_code,
    )

    if not preprocessing["success"]:
        return {
            "success": False,
            "stage": "preprocessing",
            "message": preprocessing["message"],
        }

    temp_dir = Path(".vulnlens_temp")
    temp_dir.mkdir(exist_ok=True)

    contract_path = temp_dir / Path(filename).name

    contract_path.write_text(
        source_code,
        encoding="utf-8",
    )

    try:
        static_analysis = run_slither(
            str(contract_path)
        )

        if not static_analysis["success"]:
            return {
                "success": False,
                "stage": "static_analysis",
                "message": static_analysis["error"],
                "preprocessing": preprocessing,
            }

        evidence = extract_all_evidence(
            static_analysis["findings"]
        )

        contexts = build_all_contexts(
            evidence,
            source_code,
        )

        llm_contexts = [
            context
            for context in contexts
            if context.get("impact")
            in LLM_ELIGIBLE_IMPACTS
        ]

        informational_contexts = [
            context
            for context in contexts
            if context.get("impact")
            not in LLM_ELIGIBLE_IMPACTS
        ]

        return {
            "success": True,
            "filename": preprocessing["filename"],
            "solidity_version": preprocessing[
                "solidity_version"
            ],
            "line_count": preprocessing["line_count"],
            "static_analysis": static_analysis,
            "evidence": evidence,
            "contexts": contexts,
            "llm_contexts": llm_contexts,
            "informational_contexts": informational_contexts,
        }

    finally:
        if contract_path.exists():
            contract_path.unlink()

        if temp_dir.exists():
            try:
                temp_dir.rmdir()
            except OSError:
                pass