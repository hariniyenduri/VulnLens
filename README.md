# VulnLens

**Evidence-Grounded Solidity Smart Contract Vulnerability Analysis**

VulnLens is an academic project that analyzes Solidity smart contracts using static analysis and LLM-assisted contextual assessment.

## Version 1 Features

- Upload and analyze Solidity smart contracts.
- Detect potential security issues using Slither.
- Extract findings and relevant source-code evidence.
- Build contextual information for LLM assessment.
- Generate PDF security reports with findings and remediation suggestions.

## Technology Stack

- **Language:** Python
- **Static Analysis:** Slither
- **LLM Integration:** OpenRouter
- **Interface:** Streamlit
- **Reporting:** PDF reports

## Project Workflow

1. Upload a Solidity contract.
2. Run static analysis using Slither.
3. Extract findings and source context.
4. Generate contextual LLM assessments.
5. Produce a PDF security report.

## Current Status

**Version 1 — Baseline Prototype**

Initial testing has been performed using three sample Solidity contracts. Broader validation and comprehensive detection-accuracy evaluation remain pending.

See [`docs/V1_BASELINE_LIMITATIONS.md`](docs/V1_BASELINE_LIMITATIONS.md) for documented limitations and the planned Version 2 improvements.

## Disclaimer

VulnLens is an academic research prototype. Its findings and LLM-generated assessments require independent verification and should not be treated as proof that a contract is secure or exploitable.

## Future Work

Version 2 aims to introduce an evidence-validation layer to improve finding validation, source-context accuracy, and the reliability of contextual assessments.