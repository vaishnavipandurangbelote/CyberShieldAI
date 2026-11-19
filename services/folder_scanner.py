
from pathlib import Path
import re
import subprocess
import time

from database.folder_scan_history import (
    initialize_database,
    save_folder_scan,
)

CLAMSCAN_PATH = Path(r"C:\Program Files\ClamAV\clamscan.exe")
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "clamav-data"


def analyze_folder_threats(threats, files_scanned, scan_complete=True):
    """Generate an explainable threat assessment from ClamAV results."""

    infected_count = len(threats)

    if not scan_complete:
        threat_score = 0
        threat_level = "Unknown"
        priority = "Review Required"
        summary = (
            "The scan did not finish successfully. "
            "The folder cannot be confirmed safe."
        )
        recommendations = [
            "Check the scan error and folder permissions.",
            "Verify that the ClamAV database is available.",
            "Run the scan again before trusting the folder."
        ]

    elif infected_count:
        threat_score = min(100, 70 + infected_count * 5)
        threat_level = "High"
        priority = "Critical"
        summary = (
            f"ClamAV detected threats in {infected_count} file(s). "
            "Treat the detected files as unsafe until reviewed."
        )
        recommendations = [
            "Do not open or execute detected files.",
            "Review the detection name and affected file path.",
            "Quarantine affected files using a safe, verified process.",
            "Update ClamAV signatures and rescan after handling the threat."
        ]

    elif files_scanned > 0:
        threat_score = 10
        threat_level = "Low"
        priority = "Low"
        summary = (
            "ClamAV did not detect known malware in the scanned files. "
            "This does not guarantee that every file is safe."
        )
        recommendations = [
            "Keep ClamAV signatures updated.",
            "Continue scanning new downloads and email attachments.",
            "Treat unexpected files and suspicious links cautiously."
        ]

    else:
        threat_score = 0
        threat_level = "Unknown"
        priority = "Review Required"
        summary = "No files were confirmed as scanned."
        recommendations = [
            "Check the folder path and scan output.",
            "Resolve the issue and run the scan again."
        ]

    identified_threats = [
        {
            "file": item["file"],
            "detection": item["detection"]
        }
        for item in threats
    ]

    return {
        "threat_score": threat_score,
        "threat_level": threat_level,
        "priority": priority,
        "summary": summary,
        "threats": identified_threats,
        "indicators": [
            f"Files scanned: {files_scanned}",
            f"Detected files: {infected_count}",
            f"Scan complete: {'Yes' if scan_complete else 'No'}"
        ],
        "recommendations": recommendations
    }


def _parse_clamav_output(output):
    """Extract per-file results and scan totals from ClamAV output."""

    file_results = []
    threats = []

    for line in output.splitlines():
        line = line.strip()

        if line.endswith(" FOUND"):
            detected_part = line[:-len(" FOUND")]
            parts = detected_part.rsplit(": ", 1)

            if len(parts) == 2:
                file_path = parts[0].strip()
                detection = parts[1].strip()

                item = {
                    "file": file_path,
                    "filename": Path(file_path).name,
                    "status": "Threat Detected",
                    "risk": "High",
                    "detection": detection
                }

                file_results.append(item)
                threats.append({
                    "file": file_path,
                    "detection": detection
                })

        elif line.endswith(": OK"):
            file_path = line[:-len(": OK")].strip()

            file_results.append({
                "file": file_path,
                "filename": Path(file_path).name,
                "status": "Safe",
                "risk": "Low",
                "detection": None
            })

    files_match = re.search(r"Scanned files:\s*(\d+)", output)
    directories_match = re.search(
        r"Scanned directories:\s*(\d+)", output
    )
    infected_match = re.search(r"Infected files:\s*(\d+)", output)

    files_scanned = (
        int(files_match.group(1)) if files_match else None
    )
    directories_scanned = (
        int(directories_match.group(1))
        if directories_match else None
    )
    infected_files = (
        int(infected_match.group(1))
        if infected_match else len(threats)
    )

    return (
        file_results,
        threats,
        files_scanned,
        directories_scanned,
        infected_files
    )


def scan_folder(folder_path):
    """Scan a folder recursively using ClamAV."""

    start_time = time.perf_counter()
    folder = Path(folder_path).expanduser()

    if not folder.exists() or not folder.is_dir():
        return {
            "success": False,
            "message": "The selected folder does not exist or is not a folder."
        }

    if not CLAMSCAN_PATH.is_file():
        return {
            "success": False,
            "message": "ClamAV clamscan.exe was not found at the configured path."
        }

    if not DATABASE_PATH.is_dir():
        return {
            "success": False,
            "message": "The ClamAV signature database folder was not found."
        }

    command = [
        str(CLAMSCAN_PATH),
        "--recursive",
        f"--database={DATABASE_PATH}",
        str(folder)
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            check=False
        )

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Folder scan timed out after 10 minutes."
        }

    except OSError as error:
        return {
            "success": False,
            "message": f"Could not execute ClamAV: {error}"
        }

    scan_time = round(time.perf_counter() - start_time, 2)
    output = process.stdout or ""

    if process.stderr:
        output += "\n" + process.stderr

    (
        file_results,
        threats,
        files_scanned,
        directories_scanned,
        infected_files
    ) = _parse_clamav_output(output)

    # ClamAV normally returns 0 when no infection is found
    # and 1 when a threat is found. Other codes indicate an error.
    scan_complete = (
        process.returncode in (0, 1)
        and files_scanned is not None
        and directories_scanned is not None
        and infected_files is not None
    )

    if not scan_complete:
        ai_result = analyze_folder_threats(
            threats,
            files_scanned or 0,
            scan_complete=False
        )

        result = {
            "success": False,
            "status": "Scan Incomplete",
            "risk": "Unknown",
            "folder": str(folder.resolve()),
            "files_scanned": (
                files_scanned
                if files_scanned is not None
                else len(file_results)
            ),
            "directories_scanned": (
                directories_scanned
                if directories_scanned is not None
                else 0
            ),
            "threats_detected": len(threats),
            "safe_files": sum(
                item["status"] == "Safe"
                for item in file_results
            ),
            "threats": threats,
            "file_results": file_results,
            "scan_time": scan_time,
            "ai_result": ai_result,
            "message": (
                "ClamAV could not confirm a complete scan. "
                "Review the scan output before relying on these results."
            ),
            "clamav_output": output[-12000:]
        }

        # DATABASE ADDITION: save incomplete scans too.
        try:
            initialize_database()
            result["database_scan_id"] = save_folder_scan(result)
            result["history_saved"] = True
        except Exception as error:
            result["history_saved"] = False
            print(f"[CyberShield Folder Scan History] {error}")

        return result

    risk = "High" if infected_files > 0 else "Low"
    status = (
        "Threats Detected"
        if infected_files > 0
        else "No Threats Detected"
    )

    ai_result = analyze_folder_threats(
        threats,
        files_scanned,
        scan_complete=True
    )

    result = {
        "success": True,
        "status": status,
        "risk": risk,
        "folder": str(folder.resolve()),
        "files_scanned": files_scanned,
        "directories_scanned": directories_scanned,
        "threats_detected": infected_files,
        "safe_files": sum(
            item["status"] == "Safe"
            for item in file_results
        ),
        "threats": threats,
        "file_results": file_results,
        "scan_time": scan_time,
        "clamav_version": "1.5.4",
        "ai_result": ai_result
    }

    # DATABASE ADDITION: save successful scans.
    try:
        initialize_database()
        result["database_scan_id"] = save_folder_scan(result)
        result["history_saved"] = True
    except Exception as error:
        result["history_saved"] = False
        print(f"[CyberShield Folder Scan History] {error}")

    return result
