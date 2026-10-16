
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_slither(contract_path: str) -> dict:
    """Run Slither on a Solidity contract and return structured output."""

    contract = Path(contract_path).resolve()

    if not contract.exists():
        return {
            "success": False,
            "error": f"Contract file not found: {contract}",
            "findings": [],
        }

    if not contract.is_file():
        return {
            "success": False,
            "error": f"Contract path is not a file: {contract}",
            "findings": [],
        }

    if contract.suffix.lower() != ".sol":
        return {
            "success": False,
            "error": f"Expected a Solidity (.sol) file: {contract}",
            "findings": [],
        }

    try:
        with tempfile.TemporaryDirectory(
            prefix="vulnlens_"
        ) as temp_dir:

            temp_root = Path(temp_dir).resolve()
            temp_contract = temp_root / contract.name
            json_output = temp_root / "slither_output.json"

            # Copy source into a dedicated temporary directory.
            temp_contract.write_bytes(contract.read_bytes())

            if not temp_contract.is_file():
                raise FileNotFoundError(
                    f"Temporary contract was not created: {temp_contract}"
                )

            command = [
                sys.executable,
                "-m",
                "slither",
                str(temp_contract),
                "--json",
                str(json_output),
            ]

            result = subprocess.run(
                command,
                cwd=str(temp_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
            )

            if not json_output.is_file():
                details = [
                    "Slither did not produce a JSON result file.",
                    f"Original contract: {contract}",
                    f"Temporary contract: {temp_contract}",
                    f"Return code: {result.returncode}",
                    f"Stdout:\n{result.stdout}",
                    f"Stderr:\n{result.stderr}",
                ]

                return {
                    "success": False,
                    "error": "\n\n".join(details),
                    "findings": [],
                    "return_code": result.returncode,
                }

            try:
                slither_data = json.loads(
                    json_output.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError) as exc:
                return {
                    "success": False,
                    "error": (
                        f"Could not read valid Slither JSON: {exc}\n"
                        f"Stdout:\n{result.stdout}\n"
                        f"Stderr:\n{result.stderr}"
                    ),
                    "findings": [],
                    "return_code": result.returncode,
                }

            detectors = (
                slither_data.get("results", {})
                .get("detectors", [])
            )

            findings = [
                {
                    "check": detector.get("check"),
                    "impact": detector.get("impact"),
                    "confidence": detector.get("confidence"),
                    "description": detector.get("description"),
                    "elements": detector.get("elements", []),
                }
                for detector in detectors
            ]

            # Slither can return a nonzero exit code when findings exist.
            # A valid JSON result means analysis produced usable output.
            return {
                "success": True,
                "findings": findings,
                "error": None,
                "return_code": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Slither timed out after 180 seconds.",
            "findings": [],
        }

    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to run Slither: {exc}",
            "findings": [],
        }
