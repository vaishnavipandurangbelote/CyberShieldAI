from datetime import datetime
from pathlib import Path
import json
from zoneinfo import ZoneInfo
from uuid import uuid4

REPORTS_FOLDER = Path("reports")
REPORTS_FOLDER.mkdir(exist_ok=True)


def create_temporary_incident(
    scanner_type,
    result,
    affected_item=""
):
    """Create an incident from a scanner result without saving a file."""

    now = datetime.now(ZoneInfo("Asia/Kolkata"))

    risk = str(result.get("risk", "Unknown")).strip()
    status = str(result.get("status", "Unknown")).strip()

    incident_type_map = {
        "File Scan": "Malware / File Security",
        "Folder Scan": "Folder Security",
        "URL Scan": "URL / Phishing",
        "Email Scan": "Email Phishing",
        "Password Scan": "Password Security",
        "Network Scan": "Network Security",
    }

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
    }

    severity = severity_map.get(risk.lower(), "Unknown")

    findings = result.get("findings", [])
    if isinstance(findings, list):
        findings_text = "; ".join(str(item) for item in findings)
    else:
        findings_text = str(findings or "")

    description = (
        f"Scanner: {scanner_type}\n"
        f"Result: {status}\n"
        f"Risk: {risk}\n"
        f"Findings: {findings_text or 'No detailed findings provided.'}"
    )

    return {
        "incident_id": f"INC-{now.strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6].upper()}",
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S IST"),
        "incident_type": incident_type_map.get(scanner_type, scanner_type),
        "scanner_type": scanner_type,
        "severity": severity,
        "description": description,
        "affected_item": affected_item or "Not specified",
        "status": "Open",
    }

def create_incident_report(
    incident_type,
    severity,
    description,
    affected_item=""
):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "incident_id": datetime.now().strftime(
            "INC-%Y%m%d%H%M%S"
        ),
        "timestamp": timestamp,
        "incident_type": incident_type,
        "severity": severity,
        "description": description,
        "affected_item": affected_item,
        "status": "Open"
    }

    filename = report["incident_id"] + ".json"
    report_path = REPORTS_FOLDER / filename

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report
