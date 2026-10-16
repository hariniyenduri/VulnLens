from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)


SEVERITY_ORDER = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
    "Informational": 3,
}


def _severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(
        value or "Informational",
        3,
    )


def _finding_sort_key(
    finding: dict[str, Any],
) -> tuple:

    source_lines = finding.get(
        "source_lines",
        [],
    )

    first_line = (
        min(source_lines)
        if source_lines
        else 999999
    )

    return (
        _severity_rank(
            finding.get("impact")
        ),
        first_line,
        finding.get("detector") or "",
    )


def _llm_key(
    context: dict[str, Any],
) -> str:

    return (
        f"{context.get('detector')}|"
        f"{context.get('function')}|"
        f"{','.join(map(str, context.get('source_lines', [])))}"
    )


def _styles():
    styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "VulnLensTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#182230"),
            spaceAfter=5 * mm,
        ),

        "subtitle": ParagraphStyle(
            "VulnLensSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#667085"),
            spaceAfter=8 * mm,
        ),

        "section": ParagraphStyle(
            "VulnLensSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#182230"),
            spaceBefore=4 * mm,
            spaceAfter=3 * mm,
        ),

        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#182230"),
            spaceAfter=4 * mm,
        ),

        "body": ParagraphStyle(
            "VulnLensBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#344054"),
            spaceAfter=2.5 * mm,
        ),

        "small": ParagraphStyle(
            "VulnLensSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#667085"),
        ),

        "label": ParagraphStyle(
            "VulnLensLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#475467"),
        ),

        "code": ParagraphStyle(
            "VulnLensCode",
            fontName="Courier",
            fontSize=7.8,
            leading=11,
            textColor=colors.HexColor("#101828"),
            backColor=colors.HexColor("#F8FAFC"),
            borderColor=colors.HexColor("#D0D5DD"),
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=2 * mm,
            spaceAfter=4 * mm,
        ),

        "remediation": ParagraphStyle(
            "VulnLensRemediation",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            leftIndent=5 * mm,
            firstLineIndent=-3 * mm,
            textColor=colors.HexColor("#344054"),
            spaceAfter=2 * mm,
        ),
    }


def _safe(text: Any) -> str:
    if text is None:
        return ""

    return str(text)


def _severity_color(severity: str) -> colors.Color:
    if severity == "High":
        return colors.HexColor("#B42318")

    if severity == "Medium":
        return colors.HexColor("#B54708")

    if severity == "Low":
        return colors.HexColor("#175CD3")

    return colors.HexColor("#475467")


def _page_header_footer(
    canvas,
    doc,
):
    canvas.saveState()

    width, height = A4

    canvas.setStrokeColor(
        colors.HexColor("#D0D5DD")
    )
    canvas.line(
        18 * mm,
        height - 14 * mm,
        width - 18 * mm,
        height - 14 * mm,
    )

    canvas.setFont(
        "Helvetica",
        7.5,
    )
    canvas.setFillColor(
        colors.HexColor("#98A2B3")
    )

    canvas.drawString(
        18 * mm,
        9 * mm,
        "VulnLens — Smart Contract Security Analysis",
    )

    canvas.drawRightString(
        width - 18 * mm,
        9 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


def _build_metadata_table(
    analysis: dict[str, Any],
):
    data = [
        [
            "Contract",
            _safe(
                analysis.get("filename")
            ),
        ],
        [
            "Solidity Version",
            _safe(
                analysis.get("solidity_version")
            ),
        ],
        [
            "Source Lines",
            _safe(
                analysis.get("line_count")
            ),
        ],
        [
            "Generated",
            datetime.now().strftime(
                "%d %B %Y, %H:%M"
            ),
        ],
    ]

    table = Table(
        data,
        colWidths=[
            42 * mm,
            125 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F2F4F7"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#475467"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8.5,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#D0D5DD"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    return table


def _build_summary_table(
    findings: list[dict[str, Any]],
):

    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for finding in findings:
        severity = finding.get(
            "impact",
            "Informational",
        )

        counts.setdefault(
            severity,
            0,
        )

        counts[severity] += 1

    data = [
        [
            "High",
            "Medium",
            "Low",
            "Informational",
        ],
        [
            str(counts["High"]),
            str(counts["Medium"]),
            str(counts["Low"]),
            str(counts["Informational"]),
        ],
    ]

    table = Table(
        data,
        colWidths=[
            41 * mm,
            41 * mm,
            41 * mm,
            41 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#F2F4F7"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, 1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#344054"),
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#D0D5DD"),
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    return table


def _build_finding_block(
    rank: int,
    context: dict[str, Any],
    llm_result: dict[str, Any],
    styles: dict,
):

    severity = (
        context.get("impact")
        or "Informational"
    )

    severity_color = _severity_color(
        severity
    )

    elements = []

    title = Paragraph(
        (
            f'<font color="{severity_color.hexval()}">'
            f"Finding {rank} — {severity}"
            f"</font>"
        ),
        styles["finding_title"],
    )

    elements.append(title)

    detector = _safe(
        context.get("detector")
    )

    function = (
        _safe(
            context.get("function")
        )
        or "Not available"
    )

    source_lines = context.get(
        "source_lines",
        [],
    )

    source_line_text = (
        ", ".join(
            str(line)
            for line in source_lines
        )
        if source_lines
        else "Not available"
    )

    confidence = (
        _safe(
            context.get("confidence")
        )
        or "Not available"
    )

    details = [
        [
            "Detector",
            detector,
        ],
        [
            "Affected Function",
            function,
        ],
        [
            "Detected Source Lines",
            source_line_text,
        ],
        [
            "Static Confidence",
            confidence,
        ],
    ]

    detail_table = Table(
        details,
        colWidths=[
            45 * mm,
            122 * mm,
        ],
    )

    detail_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F8FAFC"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8.3,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#344054"),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#D0D5DD"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    elements.append(
        detail_table
    )

    elements.append(
        Paragraph(
            "Static Analysis Evidence",
            styles["section"],
        )
    )

    evidence = context.get(
        "evidence",
        [],
    )

    if evidence:

        for item in evidence:
            elements.append(
                Paragraph(
                    f"• {_safe(item)}",
                    styles["body"],
                )
            )

    else:
        description = _safe(
            context.get("description")
        )

        if description:
            elements.append(
                Paragraph(
                    description.replace(
                        "\n",
                        "<br/>",
                    ),
                    styles["body"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    "No additional textual evidence was extracted.",
                    styles["small"],
                )
            )

    elements.append(
        Paragraph(
            "Relevant Solidity Context",
            styles["section"],
        )
    )

    relevant_code = (
        context.get(
            "relevant_code",
            "",
        )
        or "No source context available."
    )

    elements.append(
        Preformatted(
            relevant_code,
            styles["code"],
            maxLineLength=100,
        )
    )

    elements.append(
        Paragraph(
            "Contextual LLM Assessment",
            styles["section"],
        )
    )

    assessment = _safe(
        llm_result.get("assessment")
    )

    if assessment:
        elements.append(
            Paragraph(
                assessment,
                styles["body"],
            )
        )
    else:
        elements.append(
            Paragraph(
                "No contextual assessment was returned.",
                styles["body"],
            )
        )

    exploitability = _safe(
        llm_result.get(
            "exploitability"
        )
    )

    if exploitability:
        elements.append(
            Paragraph(
                f"<b>Exploitability:</b> {exploitability}",
                styles["body"],
            )
        )

    attack_scenario = _safe(
        llm_result.get(
            "attack_scenario"
        )
    )

    if attack_scenario:
        elements.append(
            Paragraph(
                f"<b>Attack Scenario:</b> {attack_scenario}",
                styles["body"],
            )
        )

    elements.append(
        Paragraph(
            "Remediation Steps",
            styles["section"],
        )
    )

    remediation = llm_result.get(
        "remediation",
        [],
    )

    if not isinstance(
        remediation,
        list,
    ):
        remediation = [
            str(remediation)
        ]

    if remediation:

        for step_number, step in enumerate(
            remediation,
            start=1,
        ):
            elements.append(
                Paragraph(
                    f"{step_number}. {_safe(step)}",
                    styles["remediation"],
                )
            )

    else:
        elements.append(
            Paragraph(
                "Review the affected code path and re-run "
                "static analysis after applying the appropriate "
                "secure coding pattern.",
                styles["body"],
            )
        )

    llm_available = llm_result.get(
        "_llm_available",
        False,
    )

    if not llm_available:

        elements.append(
            Spacer(1, 2 * mm)
        )

        elements.append(
            Paragraph(
                "Note: OpenRouter contextual reasoning was not "
                "available for this finding. The remediation and "
                "assessment shown above are deterministic "
                "fallback guidance based on the Slither detector.",
                styles["small"],
            )
        )

    return elements


def generate_pdf_report(
    analysis: dict[str, Any],
    llm_results: dict[str, dict[str, Any]] | None = None,
) -> bytes:

    llm_results = llm_results or {}

    findings = sorted(
        analysis.get(
            "contexts",
            [],
        ),
        key=_finding_sort_key,
    )

    styles = _styles()

    buffer = BytesIO()

    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=17 * mm,
        title="VulnLens Security Report",
        author="VulnLens",
    )

    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="normal",
    )

    doc.addPageTemplates(
        [
            PageTemplate(
                id="VulnLensTemplate",
                frames=frame,
                onPage=_page_header_footer,
            )
        ]
    )

    story = []

    # ---------------------------------------------------------
    # Cover / summary
    # ---------------------------------------------------------

    story.append(
        Spacer(1, 6 * mm)
    )

    story.append(
        Paragraph(
            "VulnLens",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            "Smart Contract Security Analysis Report",
            styles["subtitle"],
        )
    )

    story.append(
        Paragraph(
            "Contract Information",
            styles["section"],
        )
    )

    story.append(
        _build_metadata_table(
            analysis
        )
    )

    story.append(
        Spacer(1, 5 * mm)
    )

    story.append(
        Paragraph(
            "Executive Summary",
            styles["section"],
        )
    )

    total = len(findings)

    story.append(
        Paragraph(
            (
                f"VulnLens identified <b>{total}</b> "
                "finding(s) in the submitted Solidity contract. "
                "Findings are ranked from High to Medium to Low "
                "to Informational. Each finding contains static "
                "evidence, relevant source context, contextual "
                "reasoning, and remediation guidance."
            ),
            styles["body"],
        )
    )

    story.append(
        _build_summary_table(
            findings
        )
    )

    story.append(
        Spacer(1, 6 * mm)
    )

    story.append(
        Paragraph(
            "Ranked Security Findings",
            styles["section"],
        )
    )

    if not findings:

        story.append(
            Paragraph(
                "No Slither findings were returned for this contract.",
                styles["body"],
            )
        )

    # ---------------------------------------------------------
    # Individual findings
    # ---------------------------------------------------------

    for rank, context in enumerate(
        findings,
        start=1,
    ):

        result = llm_results.get(
            _llm_key(context),
            {},
        )

        story.extend(
            _build_finding_block(
                rank,
                context,
                result,
                styles,
            )
        )

        if rank != len(findings):
            story.append(
                PageBreak()
            )

    # ---------------------------------------------------------
    # Methodology
    # ---------------------------------------------------------

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Analysis Methodology",
            styles["section"],
        )
    )

    methodology = [
        "The Solidity source file is validated before analysis.",
        "Slither performs static analysis on the submitted contract.",
        "Detector results are converted into structured security evidence.",
        "Relevant Solidity source context is selected around reported locations.",
        "High, medium, and low impact findings are supplied to the configured LLM for contextual reasoning.",
        "Findings are ranked from High to Medium to Low to Informational.",
        "The final report combines static-analysis evidence, source context, contextual reasoning, and remediation guidance.",
    ]

    for item in methodology:
        story.append(
            Paragraph(
                f"• {item}",
                styles["body"],
            )
        )

    story.append(
        Paragraph(
            "Scope and Limitations",
            styles["section"],
        )
    )

    limitations = [
        "VulnLens is a pre-deployment smart-contract analysis system.",
        "The system does not deploy contracts.",
        "The system does not interact with a blockchain or ledger.",
        "The system does not use wallets or private keys.",
        "Static-analysis findings identify suspicious or security-relevant patterns and require contextual review.",
        "LLM output is contextual reasoning over supplied evidence and source code and should not replace independent security review.",
        "The absence of a finding does not prove that a contract is completely secure.",
    ]

    for item in limitations:
        story.append(
            Paragraph(
                f"• {item}",
                styles["body"],
            )
        )

    story.append(
        Spacer(1, 6 * mm)
    )

    story.append(
        Paragraph(
            "Generated by VulnLens",
            styles["small"],
        )
    )

    doc.build(story)

    return buffer.getvalue()