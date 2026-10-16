
from typing import Any


def get_source_lines(
    source_code: str,
    start_line: int,
    end_line: int,
) -> str:
    lines = source_code.splitlines()

    if not lines:
        return ""

    start_line = max(1, start_line)
    end_line = min(len(lines), end_line)

    if start_line > end_line:
        return ""

    selected_lines = lines[start_line - 1:end_line]

    return "\n".join(
        f"{line_number}: {line}"
        for line_number, line in enumerate(
            selected_lines,
            start=start_line,
        )
    )


def determine_context_range(
    source_lines: list[int],
    total_lines: int,
    context_padding: int = 5,
) -> tuple[int, int]:
    if total_lines <= 0:
        return 1, 0

    valid_lines = [
        line for line in source_lines
        if isinstance(line, int) and 1 <= line <= total_lines
    ]

    if not valid_lines:
        return 1, min(total_lines, 50)

    start_line = max(1, min(valid_lines) - context_padding)
    end_line = min(total_lines, max(valid_lines) + context_padding)

    return start_line, end_line


def build_finding_context(
    finding: dict[str, Any],
    source_code: str,
) -> dict[str, Any]:
    total_lines = len(source_code.splitlines())

    source_lines = finding.get("source_lines") or []

    if not isinstance(source_lines, list):
        source_lines = []

    start_line, end_line = determine_context_range(
        source_lines,
        total_lines,
    )

    relevant_code = get_source_lines(
        source_code,
        start_line,
        end_line,
    )

    # Fallback: if detector lines are unavailable or invalid,
    # provide the beginning of the source rather than an empty string.
    if not relevant_code and total_lines:
        start_line = 1
        end_line = min(total_lines, 50)
        relevant_code = get_source_lines(
            source_code,
            start_line,
            end_line,
        )

    return {
        "detector": finding.get("detector"),
        "impact": finding.get("impact"),
        "confidence": finding.get("confidence"),
        "function": finding.get("function"),
        "source_lines": source_lines,
        "context_range": {
            "start": start_line,
            "end": end_line,
        },
        "description": finding.get("description", ""),
        "evidence": finding.get("evidence", []),
        "relevant_code": relevant_code,
    }


def build_all_contexts(
    findings: list[dict[str, Any]],
    source_code: str,
) -> list[dict[str, Any]]:
    return [
        build_finding_context(finding, source_code)
        for finding in findings
    ]
