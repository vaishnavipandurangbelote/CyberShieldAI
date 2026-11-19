
import sqlite3
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

# --------------------------------------------------
# Configuration
# --------------------------------------------------

DATABASE_PATH = Path(__file__).resolve().parent / "folder_scan_history.db"
INDIA_TIMEZONE = ZoneInfo("Asia/Kolkata")


# --------------------------------------------------
# Database Connection
# --------------------------------------------------

def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=15
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# --------------------------------------------------
# Initialize Database
# --------------------------------------------------

def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS folder_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_files INTEGER NOT NULL DEFAULT 0,
                safe_files INTEGER NOT NULL DEFAULT 0,
                infected_files INTEGER NOT NULL DEFAULT 0,
                directories_scanned INTEGER NOT NULL DEFAULT 0,
                scan_status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                threat_score INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL DEFAULT 'Unknown',
                summary TEXT,
                scan_duration REAL NOT NULL DEFAULT 0
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS folder_scan_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                threat_name TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES folder_scans(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_folder_scans_date
            ON folder_scans(scan_date)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_folder_files_scan_id
            ON folder_scan_files(scan_id)
        """)


# --------------------------------------------------
# Save Folder Scan Summary and Detected Files
# --------------------------------------------------

def save_folder_scan(result):
    ai_result = result.get("ai_result", {})

    # Current date and time in India
    scan_date = datetime.now(INDIA_TIMEZONE).isoformat(
        timespec="seconds"
    )

    total_files = int(result.get("files_scanned", 0))
    infected_files = int(result.get("threats_detected", 0))
    safe_files = int(result.get("safe_files", 0))

    # Prevent invalid numeric values
    total_files = max(total_files, 0)
    infected_files = max(infected_files, 0)
    safe_files = max(safe_files, 0)

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO folder_scans (
                folder_path,
                scan_date,
                total_files,
                safe_files,
                infected_files,
                directories_scanned,
                scan_status,
                risk_level,
                threat_score,
                priority,
                summary,
                scan_duration
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("folder", ""),
            scan_date,
            total_files,
            safe_files,
            infected_files,
            int(result.get("directories_scanned", 0)),
            result.get("status", "Unknown"),
            result.get("risk", "Unknown"),
            int(ai_result.get("threat_score", 0)),
            ai_result.get("priority", "Unknown"),
            ai_result.get("summary", ""),
            float(result.get("scan_time", 0))
        ))

        scan_id = cursor.lastrowid

        # Store detected files with their paths
        file_rows = []

        for threat in result.get("threats", []):
            file_path = threat.get("file", "")

            file_rows.append((
                scan_id,
                file_path,
                Path(file_path).name if file_path else "Unknown",
                "Threat Detected",
                result.get("risk", "High"),
                threat.get("detection", "Unknown")
            ))

        if file_rows:
            connection.executemany("""
                INSERT INTO folder_scan_files (
                    scan_id,
                    file_path,
                    filename,
                    file_status,
                    risk_level,
                    threat_name
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, file_rows)

    return scan_id


# --------------------------------------------------
# Get Folder Scan History
# --------------------------------------------------

def get_folder_scan_history(limit=100):
    limit = max(1, min(int(limit), 1000))

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                folder_path,
                scan_date,
                total_files,
                safe_files,
                infected_files,
                scan_status,
                risk_level,
                threat_score,
                priority,
                summary,
                scan_duration
            FROM folder_scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# --------------------------------------------------
# Get Detected Files for a Scan
# --------------------------------------------------

def get_folder_scan_files(scan_id):
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM folder_scan_files
            WHERE scan_id = ?
            ORDER BY id
        """, (scan_id,)).fetchall()

    return [dict(row) for row in rows]
