from typing import Any


def _get_primary_function(elements: list[dict[str, Any]]) -> str | None:
    for element in elements:
        if element.get("type") == "function":
            return element.get("name")

        parent = element.get("type_specific_fields", {}).get("parent", {})
        if parent.get("type") == "function":
            return parent.get("name")

    return None


def _get_direct_source_lines(elements: list[dict[str, Any]]) -> list[int]:
    """
    Extract the most specific source lines reported by Slither.

    We deliberately avoid collecting parent function/contract ranges when
    more specific node/pragma locations are available. This prevents a
    finding from incorrectly expanding into unrelated line numbers.
    """
    specific_lines: set[int] = set()
    fallback_function_lines: set[int] = set()

    for element in elements:
        element_type = element.get("type")
        source_mapping = element.get("source_mapping", {})

        lines = source_mapping.get("lines", [])
        valid_lines = {
            line for line in lines
            if isinstance(line, int) and line > 0
        }

        if not valid_lines:
            continue

        if element_type in {
            "node",
            "pragma",
            "variable",
            "event",
            "modifier",
            "solidity_variable",
        }:
            specific_lines.update(valid_lines)

        elif element_type == "function":
            fallback_function_lines.update(valid_lines)

    if specific_lines:
        return sorted(specific_lines)

    return sorted(fallback_function_lines)


def _extract_evidence_from_description(description: str) -> list[str]:
    evidence = []

    if not description:
        return evidence

    lines = [
        line.strip()
        for line in description.splitlines()
        if line.strip()
    ]

    for line in lines:
        if line.startswith("External calls:"):
            continue

        if line.startswith("State variables written after"):
            continue

        if line.startswith("ReentrancyVulnerable."):
            continue

        if line.startswith("It is used by:"):
            continue

        if line.startswith("-"):
            cleaned = line.lstrip("-").strip()
            if cleaned:
                evidence.append(cleaned)

    return evidence


def extract_finding_evidence(
    finding: dict[str, Any],
) -> dict[str, Any]:

    elements = finding.get("elements", [])
    description = finding.get("description", "")

    function_name = _get_primary_function(elements)
    source_lines = _get_direct_source_lines(elements)

    evidence_items = _extract_evidence_from_description(description)

    return {
        "detector": finding.get("check"),
        "impact": finding.get("impact"),
        "confidence": finding.get("confidence"),
        "function": function_name,
        "source_lines": source_lines,
        "description": description.strip(),
        "evidence": evidence_items,
    }


def extract_all_evidence(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    return [
        extract_finding_evidence(finding)
        for finding in findings
    ]