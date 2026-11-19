
import sqlite3
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

DATABASE_PATH = Path(__file__).resolve().parent / "scan_history.db"
INDIA_TIMEZONE = ZoneInfo("Asia/Kolkata")

SCAN_TYPES = (
    "File Scan",
    "Folder Scan",
    "URL Scan",
    "Email Scan",
    "Password Scan",
    "Network Scan",
)


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                scan_status TEXT NOT NULL,
                risk_level TEXT NOT NULL DEFAULT 'Unknown',
                scan_date TEXT NOT NULL,
                scan_type TEXT NOT NULL DEFAULT 'File Scan'
            )
        """)

        # Safely upgrade an existing database without deleting its records.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scan_history)"
            ).fetchall()
        }

        if "scan_type" not in columns:
            connection.execute("""
                ALTER TABLE scan_history
                ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'File Scan'
            """)
        if "session_id" not in columns:
            connection.execute("""
                ALTER TABLE scan_history
                ADD COLUMN session_id TEXT
            """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_date
            ON scan_history(scan_date)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_type
            ON scan_history(scan_type)
        """)


def save_scan(filename, scan_status, risk_level="Unknown",
              scan_type="File Scan", session_id=None):
    """Save one scan result. Existing three-argument calls still work."""
    initialize_database()

    if not filename or not scan_status:
        raise ValueError("Filename and scan status are required.")

    if scan_type not in SCAN_TYPES:
        raise ValueError(
            f"Invalid scan_type. Allowed values: {SCAN_TYPES}"
        )

    filename = str(filename).strip()
    scan_status = str(scan_status).strip()
    risk_level = str(risk_level or "Unknown").strip()

    if not filename or not scan_status:
        raise ValueError("Filename and scan status are required.")

    scan_date = datetime.now(INDIA_TIMEZONE).isoformat(
        timespec="seconds"
    )

    with get_connection() as connection:
        cursor = connection.execute("""
    INSERT INTO scan_history
        (filename, scan_status, risk_level, scan_date, scan_type, session_id)
    VALUES (?, ?, ?, ?, ?, ?)
""", (
    filename, scan_status, risk_level, scan_date, scan_type, session_id
))
        return cursor.lastrowid


def get_scan_history(limit=100, scan_type=None):
    initialize_database()
    limit = max(1, min(int(limit), 1000))

    with get_connection() as connection:
        if scan_type is not None:
            if scan_type not in SCAN_TYPES:
                raise ValueError("Invalid scan_type.")

            rows = connection.execute("""
                SELECT id, filename, scan_status, risk_level,
                       scan_date, scan_type
                FROM scan_history
                WHERE scan_type = ?
                ORDER BY id DESC
                LIMIT ?
            """, (scan_type, limit)).fetchall()
        else:
            rows = connection.execute("""
                SELECT id, filename, scan_status, risk_level,
                       scan_date, scan_type
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

    return [dict(row) for row in rows]




def get_scan_statistics(session_id=None):
    initialize_database()

    with get_connection() as connection:
        if session_id is not None:
            rows = connection.execute("""
                SELECT scan_type, scan_status
                FROM scan_history
                WHERE session_id = ?
            """, (session_id,)).fetchall()
        else:
            rows = connection.execute("""
                SELECT scan_type, scan_status
                FROM scan_history
            """).fetchall()

    total = len(rows)
    threats = 0
    clean = 0
    by_type = {}

    threat_statuses = {
        "threat detected",
        "threats detected",
        "infected",
        "malicious",
        "phishing detected",
        "potential phishing",
        "suspicious",
        "high risk",
        "critical risk",
    }

    clean_statuses = {
        "clean",
        "safe",
        "no threat detected",
        "no threats detected",
        "no strong indicators found",
    }

    for row in rows:
        status = row["scan_status"].strip().lower()
        category = row["scan_type"]

        by_type[category] = by_type.get(category, 0) + 1

        if status in threat_statuses:
            threats += 1
        elif status in clean_statuses:
            clean += 1

    return {
        "total_scans": total,
        "threats_detected": threats,
        "clean_scans": clean,
        "other_scans": total - threats - clean,
        "scans_by_type": by_type,
    }


def get_risk_chart_data(session_id=None, limit=200):
    """Return recent scan records for the risk-over-time chart."""
    initialize_database()
    limit = max(1, min(int(limit), 1000))

    with get_connection() as connection:
        if session_id is not None:
            rows = connection.execute("""
                SELECT id, scan_type, scan_status, risk_level, scan_date
                FROM scan_history
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT ?
            """, (session_id, limit)).fetchall()
        else:
            rows = connection.execute("""
                SELECT id, scan_type, scan_status, risk_level, scan_date
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

    return [dict(row) for row in reversed(rows)]



def get_cyber_health_score():
    """
    Calculate a 0-100 score using the latest valid result
    from each scanner category.
    """

    initialize_database()

    risk_points = {
        "low": 85,
        "medium": 60,
        "high": 25,
        "critical": 0,
    }

    safe_statuses = {
        "clean",
        "safe",
        "likely safe",
        "no threat detected",
        "no threats detected",
    }

    threat_statuses = {
        "threat detected",
        "threats detected",
        "infected",
        "malicious",
        "phishing detected",
        "high risk",
        "critical risk",
    }

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT scan_type, scan_status, risk_level
            FROM scan_history
            ORDER BY id DESC
        """).fetchall()

    latest_by_type = {}

    for row in rows:
        category = row["scan_type"]

        if category not in SCAN_TYPES:
            continue

        if category in latest_by_type:
            continue

        status = str(row["scan_status"] or "").strip().lower()
        risk = str(row["risk_level"] or "").strip().lower()

        if status in safe_statuses:
            points = 100

        elif status == "critical risk" or risk == "critical":
            points = 0

        elif status in threat_statuses:
            points = risk_points.get(risk, 25)

        elif risk in risk_points:
            points = risk_points[risk]

        else:
            continue

        latest_by_type[category] = points

    if not latest_by_type:
        return {
            "score": None,
            "label": "Not Enough Data",
            "scanners_counted": 0,
            "scanners_total": len(SCAN_TYPES),
            "details": {},
        }

    score = round(
        sum(latest_by_type.values()) / len(latest_by_type)
    )

    if score >= 90:
        label = "Excellent"
    elif score >= 75:
        label = "Good"
    elif score >= 50:
        label = "Needs Attention"
    else:
        label = "At Risk"

    return {
        "score": score,
        "label": label,
        "scanners_counted": len(latest_by_type),
        "scanners_total": len(SCAN_TYPES),
        "details": latest_by_type,
    }



if __name__ == "__main__":
    initialize_database()
    print("Scan history database initialized.")
    print("Statistics:", get_scan_statistics())
    print("Cyber Health:", get_cyber_health_score())
    print("Recent scans:", get_scan_history(5))
