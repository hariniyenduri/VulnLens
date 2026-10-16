# VulnLens Version 1 — Baseline Results and Limitations

## 1. Version Overview

**Project:** VulnLens  
**Version:** V1.0 — Baseline Prototype  
**Purpose:** Solidity smart contracts లో potential vulnerabilities గుర్తించి, static analysis evidence ఆధారంగా LLM-generated assessment and remediation suggestions అందించడం.

### Workflow

1. Solidity contract upload
2. Slither static analysis
3. Finding and source evidence extraction
4. Relevant source context construction
5. LLM-based contextual assessment
6. PDF report generation

## 2. Baseline Testing

Three sample Solidity contracts were tested.

| Test contract | Observed results |
|---|---|
| `reentrancy.sol` | High-impact reentrancy finding and informational findings |
| `safe.sol` | Informational compiler-version finding; no confirmed logic vulnerability reported |
| `access_control.sol` | Missing-zero-check finding and informational findings; unrestricted functions were not independently flagged as access-control vulnerabilities |

These results represent initial prototype testing, not comprehensive validation.

## 3. Known Limitations

### 3.1 Access-Control Detection

The `access_control.sol` test showed that unrestricted functions may not receive a dedicated access-control finding from the current Slither-based pipeline.

**Limitation:** Version 1 does not comprehensively detect every unauthorized-access or missing-access-control issue.

### 3.2 Compiler-Version Findings

Slither may report compiler-version-related issues even when the specific compiler bug's applicability to the contract has not been established.

**Limitation:** An informational compiler finding must not automatically be treated as a confirmed exploitable vulnerability.

### 3.3 LLM Assessment Reliability

LLM assessments depend on the supplied source context and model response. The LLM may overstate severity, make unsupported claims, or recommend a fix that requires further verification.

**Limitation:** LLM-generated explanations and recommendations are not independently verified security proofs.

### 3.4 Limited Test Coverage

Only three sample contracts have been tested in this initial baseline.

**Limitation:** The current results do not establish general detection accuracy, precision, recall, or false-positive rate.

### 3.5 Evidence Validation

Version 1 extracts findings and source context, but it does not yet provide a dedicated validation layer that independently verifies every finding against vulnerability-specific conditions and supporting or contradicting evidence.

**Limitation:** A reported finding is not necessarily a confirmed vulnerability.

## 4. Scope of Version 1

Version 1 demonstrates the integration of static analysis, evidence extraction, contextual LLM assessment, and PDF reporting.

It is a working baseline prototype. It has not yet been validated sufficiently to claim comprehensive vulnerability detection or production-level security assurance.

## 5. Planned Improvements for Version 2

The planned Version 2 evidence-validation engine will aim to:

1. Normalize static-analysis findings.
2. Validate source locations and relevant code context.
3. Apply vulnerability-specific validation checks.
4. Identify supporting and contradicting evidence.
5. Represent uncertainty when evidence is insufficient.
6. Provide validated evidence to the LLM before generating its assessment.
7. Compare Version 2 against the Version 1 baseline using the same labeled test contracts.

## 6. Evaluation Plan

Version 2 should be evaluated against Version 1 using labeled contracts and consistent test conditions.

Planned measurements include:

- Precision, recall, and F1-score
- False-positive rate
- Source-location accuracy
- Evidence validity
- Runtime

No evaluation metrics or performance improvements are claimed until the experiments are completed.

## 7. Baseline Status

**Status:** Initial baseline testing completed; broader validation remains pending.

The three existing PDF reports should be preserved with the Version 1 code. Known limitations must remain documented when Version 2 development begins.