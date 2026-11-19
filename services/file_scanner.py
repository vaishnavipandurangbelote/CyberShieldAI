from pathlib import Path
import hashlib
import json
import subprocess
from time import perf_counter
from database.scan_history import initialize_database, save_scan


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

THREAT_DATABASE = BASE_DIR / "data" / "threat_hashes.json"

CLAMSCAN_PATH = Path(
    r"C:\Program Files\ClamAV\clamscan.exe"
)

CLAMAV_DATABASE = BASE_DIR / "clamav-data"

ALLOWED_EXTENSIONS = {
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".jpg",
    ".jpeg",
    ".png",
    ".zip",
    ".py",
    ".js",
    ".html",
    ".css"
}


# --------------------------------------------------
# SHA-256 Calculation
# --------------------------------------------------

def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for block in iter(
            lambda: file.read(1024 * 1024),
            b""
        ):
            sha256.update(block)

    return sha256.hexdigest()


# --------------------------------------------------
# Load Threat Hash Database
# --------------------------------------------------

def load_threat_database():

    if not THREAT_DATABASE.exists():

        return {
            "test_hashes": {}
        }

    try:

        with open(
            THREAT_DATABASE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return {
            "test_hashes": {}
        }


# --------------------------------------------------
# Hash Reputation Check
# --------------------------------------------------

def check_hash_reputation(file_hash):

    database = load_threat_database()

    test_hashes = database.get(
        "test_hashes",
        {}
    )

    if file_hash in test_hashes:

        return {
            "matched": True,
            "category": test_hashes[file_hash]
        }

    return {
        "matched": False,
        "category": None
    }


# --------------------------------------------------
# ClamAV Scan
# --------------------------------------------------

def scan_with_clamav(file_path):

    """
    Scan a file using the locally installed ClamAV engine.

    Returns:
        {
            "available": True/False,
            "infected": True/False,
            "finding": "..."
        }
    """

    if not CLAMSCAN_PATH.exists():

        return {
            "available": False,
            "infected": False,
            "finding": "ClamAV scanner was not found."
        }

    if not CLAMAV_DATABASE.exists():

        return {
            "available": False,
            "infected": False,
            "finding": "ClamAV virus database was not found."
        }

    try:

        process = subprocess.run(
            [
                str(CLAMSCAN_PATH),
                f"--database={CLAMAV_DATABASE}",
                "--no-summary",
                str(file_path)
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        output = (
            process.stdout.strip()
            + "\n"
            + process.stderr.strip()
        ).strip()

        # ClamAV exit code 0 = clean
        if process.returncode == 0:

            return {
                "available": True,
                "infected": False,
                "finding": "ClamAV scan completed successfully. No malware was detected."
            }

        # ClamAV exit code 1 = malware detected
        if process.returncode == 1:

            detection_line = ""

            for line in output.splitlines():

                if "FOUND" in line:

                    detection_line = line.strip()

                    break

            if not detection_line:

                detection_line = "ClamAV detected a malicious file."

            return {
                "available": True,
                "infected": True,
                "finding": detection_line
            }

        # Any other exit code indicates a scan problem
        return {
            "available": False,
            "infected": False,
            "finding": (
                "ClamAV could not complete the scan. "
                f"Exit code: {process.returncode}"
            )
        }

    except subprocess.TimeoutExpired:

        return {
            "available": False,
            "infected": False,
            "finding": "ClamAV scan timed out."
        }

    except OSError as error:

        return {
            "available": False,
            "infected": False,
            "finding": f"ClamAV execution error: {error}"
        }


# --------------------------------------------------
# File Analysis
# --------------------------------------------------


def analyze_file(file_path, session_id=None):
    path = Path(file_path)

    total_start = perf_counter()

    hash_start = perf_counter()
    file_hash = calculate_sha256(path)
    hash_time = perf_counter() - hash_start

    reputation_start = perf_counter()
    hash_result = check_hash_reputation(file_hash)
    reputation_time = perf_counter() - reputation_start

    clamav_start = perf_counter()
    clamav_result = scan_with_clamav(path)
    clamav_time = perf_counter() - clamav_start

    file_size = path.stat().st_size
    extension = path.suffix.lower()
    supported_type = extension in ALLOWED_EXTENSIONS

    result = {
        "filename": path.name,
        "extension": extension,
        "size": file_size,
        "sha256": file_hash,
        "status": "Scan Incomplete",
        "risk": "Unknown",
        "findings": [],
        "hash_match": hash_result["matched"],
        "hash_category": hash_result["category"],
        "clamav_available": clamav_result["available"],
        "clamav_infected": clamav_result["infected"],
    }

    if not supported_type:
        result["findings"].append(
            "This file type is not in the supported file-type list. "
            "ClamAV results are reported separately."
        )

    if file_size == 0:
        result["findings"].append(
            "The file is empty and needs review."
        )

    if hash_result["matched"]:
        result["status"] = "Threat Detected"
        result["risk"] = "High"
        result["findings"].append(
            "The SHA-256 hash matched an entry in the local threat database."
        )
        result["findings"].append(
            f"Threat category: {hash_result['category']}"
        )

    if clamav_result["infected"]:
        result["status"] = "Threat Detected"
        result["risk"] = "High"
        result["findings"].append(
            "ClamAV detected malware in the file."
        )
        result["findings"].append(
            f"ClamAV finding: {clamav_result['finding']}"
        )

    elif clamav_result["available"]:
        result["findings"].append(clamav_result["finding"])

        if not hash_result["matched"]:
            if supported_type and file_size > 0:
                result["status"] = "No Threat Detected"
                result["risk"] = "Low"
            else:
                result["status"] = "Needs Review"
                result["risk"] = "Unknown"

    else:
        result["findings"].append(clamav_result["finding"])

        if not hash_result["matched"]:
            result["status"] = "Scan Incomplete"
            result["risk"] = "Unknown"

    result["scan_time"] = round(perf_counter() - total_start, 3)
    result["hash_time"] = round(hash_time, 3)
    result["reputation_time"] = round(reputation_time, 3)
    result["clamav_time"] = round(clamav_time, 3)

    print(
        f"[CyberShield Scan] {path.name} | "
        f"Hash: {hash_time:.3f}s | "
        f"Reputation: {reputation_time:.3f}s | "
        f"ClamAV: {clamav_time:.3f}s | "
        f"Total: {result['scan_time']:.3f}s"
    )

        # Existing scan-processing code
    # ...

    try:
        initialize_database()
        save_scan(
    filename=result.get("filename", "Unknown"),
    scan_status=result.get("status", "Unknown"),
    risk_level=result.get("risk", "Unknown"),
    scan_type="File Scan",
    session_id=session_id
)
    except Exception as error:
        print(f"[CyberShield Scan History] Could not save scan: {error}")



    return result
