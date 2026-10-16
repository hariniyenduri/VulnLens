import re
from pathlib import Path


SUPPORTED_EXTENSION = ".sol"


def validate_contract_file(filename: str, source_code: str) -> tuple[bool, str]:
    """
    Validate the uploaded Solidity contract.
    """

    if not filename.lower().endswith(SUPPORTED_EXTENSION):
        return False, "Only Solidity (.sol) files are supported."

    if not source_code or not source_code.strip():
        return False, "The uploaded Solidity file is empty."

    if "pragma solidity" not in source_code:
        return False, "No Solidity pragma declaration was found."

    return True, "Contract validation successful."


def extract_solidity_version(source_code: str) -> str | None:
    """
    Extract the Solidity version expression from a pragma declaration.

    Example:
        pragma solidity ^0.8.20;

    Returns:
        ^0.8.20
    """

    pattern = r"pragma\s+solidity\s+([^;]+);"

    match = re.search(pattern, source_code)

    if match:
        return match.group(1).strip()

    return None


def preprocess_contract(filename: str, source_code: str) -> dict:
    """
    Validate and preprocess an uploaded Solidity contract.
    """

    is_valid, message = validate_contract_file(
        filename,
        source_code,
    )

    if not is_valid:
        return {
            "success": False,
            "message": message,
            "filename": filename,
            "source_code": source_code,
            "solidity_version": None,
            "line_count": 0,
        }

    solidity_version = extract_solidity_version(source_code)

    line_count = len(source_code.splitlines())

    return {
        "success": True,
        "message": message,
        "filename": Path(filename).name,
        "source_code": source_code,
        "solidity_version": solidity_version,
        "line_count": line_count,
    }