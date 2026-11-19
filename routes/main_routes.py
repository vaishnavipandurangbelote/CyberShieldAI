from flask import Blueprint, render_template, request
from pathlib import Path
from uuid import uuid4
from services.file_scanner import analyze_file
from services.folder_scanner import scan_folder as run_folder_scan
from services.url_scanner import analyze_url
from services.email_scanner import analyze_email
from services.password_scanner import analyze_password
from database.scan_history import (
    save_scan,
    get_cyber_health_score,
    get_scan_statistics,
    get_risk_chart_data
)
from services.network_scanner import analyze_network
from services.ai_threat_analyzer import analyze_security_data
from services.incident_reporter import (
    create_incident_report,
    create_temporary_incident
)
from services.security_reports import get_security_reports
from flask import Blueprint, render_template, request, session

main_bp = Blueprint("main", __name__)
@main_bp.before_request
def initialize_dashboard_session():
    if "dashboard_session_id" not in session:
        session["dashboard_session_id"] = str(uuid4())

def update_session_health(scan_type, result):
    """Update the temporary Cyber Health Score for this session."""

    from flask import session

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

    status = str(result.get("status", "")).strip().lower()
    risk = str(result.get("risk", "Unknown")).strip().lower()

    if status in safe_statuses:
        points = 100
    elif status == "critical risk" or risk == "critical":
        points = 0
    elif status in threat_statuses:
        points = risk_points.get(risk, 25)
    elif risk in risk_points:
        points = risk_points[risk]
    else:
        return

    health = session.get("cyber_health", {
        "details": {}
    })

    details = health.get("details", {})
    details[scan_type] = points

    score = round(sum(details.values()) / len(details))

    if score >= 90:
        label = "Excellent"
    elif score >= 75:
        label = "Good"
    elif score >= 50:
        label = "Needs Attention"
    else:
        label = "At Risk"

    session["cyber_health"] = {
        "score": score,
        "label": label,
        "scanners_counted": len(details),
        "scanners_total": 6,
        "details": details,
    }
    
    session.modified = True


UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)


# ==================================================
# DASHBOARD
# ==================================================

@main_bp.route("/")
def home():
    return render_template("welcome.html")


@main_bp.route("/dashboard")
def dashboard():
    cyber_health = session.get(
        
        "cyber_health",
        {
            "score": None,
            "label": "Not Enough Data",
            "scanners_counted": 0,
            "scanners_total": 6,
            "details": {}
        }
    )
    statistics = get_scan_statistics(session["dashboard_session_id"])

    return render_template(
    "index.html",
    cyber_health=cyber_health,
    statistics=statistics
)


# ==================================================
# FILE SCANNER
# ==================================================

@main_bp.route("/file-scanner")
def file_scanner():
    return render_template("file_scanner.html")


@main_bp.route("/scan-file", methods=["POST"])
def scan_file():

    uploaded_file = request.files.get("file")

    if not uploaded_file or uploaded_file.filename == "":
        return "No file selected.", 400

    safe_filename = Path(uploaded_file.filename).name

    file_path = UPLOAD_FOLDER / safe_filename

    uploaded_file.save(file_path)

    result = analyze_file(
    file_path,
    session_id=session["dashboard_session_id"]
)
    session["last_scan_result"] = result
    session["last_scan_type"] = "File Scan"

    update_session_health("File Scan", result)

    ai_result = analyze_security_data(result)

    return render_template(
        "scan_result.html",
        result=result,
        ai_result=ai_result
    )


# ==================================================
# FOLDER SCANNER
# ==================================================

@main_bp.route("/scan-folder", methods=["POST"])
def scan_folder_route():

    folder_path = request.form.get(
        "folder_path",
        ""
    ).strip().strip('"')

    if not folder_path:
        return "Please enter a folder path.", 400

    result = run_folder_scan(folder_path)
    update_session_health("Folder Scan", result)
    save_scan(
        filename=f"Folder: {folder_path}",
        scan_status=result.get("status", "Unknown"),
        risk_level=result.get("risk", "Unknown"),
        scan_type="Folder Scan",
        session_id=session["dashboard_session_id"]
    )
    session["last_scan_result"] = result
    session["last_scan_type"] = "Folder Scan"

    return render_template(
        "folder_scan_result.html",
        result=result
    )

# ==================================================
# URL & PHISHING SCANNER
# ==================================================

@main_bp.route("/url-scanner")
def url_scanner():
    return render_template("url_scanner.html")



@main_bp.route("/scan-url", methods=["POST"])
def scan_url():
    url = request.form.get("url", "").strip()

    if not url:
        return "Please enter a URL.", 400

    result = analyze_url(url)
    update_session_health("URL Scan", result)
    save_scan(
        filename=result.get("domain") or "URL Scan",
        scan_status=result.get("status", "Unknown"),
        risk_level=result.get("risk", "Unknown"),
        scan_type="URL Scan",
        session_id=session["dashboard_session_id"]
    )
    session["last_scan_result"] = result
    session["last_scan_type"] = "URL Scan"

    return render_template(
        "url_result.html",
        result=result
    )



# ==================================================
# EMAIL SECURITY
# ==================================================

@main_bp.route("/email-security")
def email_security():
    return render_template("email_scanner.html")


@main_bp.route("/scan-email", methods=["POST"])
def scan_email():

    sender = request.form.get("sender", "").strip()

    email_content = request.form.get(
        "email_content",
        ""
    ).strip()

    if not email_content:
        return "Please enter email content.", 400

    result = analyze_email(
        email_content,
        sender
    )
    update_session_health("Email Scan", result)
    save_scan(
    filename="Email Analysis",
    scan_status=result.get("status", "Unknown"),
    risk_level=result.get("risk", "Unknown"),
    scan_type="Email Scan",
    session_id=session["dashboard_session_id"]
)
    session["last_scan_result"] = result
    session["last_scan_type"] = "Email Scan"
    return render_template(
        "email_result.html",
        result=result
    )




# --------------------------------------------------
# Password Security
# --------------------------------------------------

from datetime import datetime


@main_bp.route("/password-security")
def password_security():
    return render_template("password_security.html")


@main_bp.route("/scan-password", methods=["POST"])
def scan_password():

    password = request.form.get("password", "")
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    birth_date = request.form.get("birth_date", "").strip()

    # Validate required inputs
    if not password or not first_name or not last_name:
        return "Please complete all required fields.", 400

    # Validate birth date (DDMMYYYY)
    try:
        if len(birth_date) != 8 or not birth_date.isdigit():
            raise ValueError

        datetime.strptime(birth_date, "%d%m%Y")

    except ValueError:
        return "Enter a valid birth date in DDMMYYYY format.", 400

    # Analyze password without storing it
    result = analyze_password(
        password,
        first_name,
        last_name,
        birth_date
    )
    update_session_health("Password Scan", result)
    save_scan(
    filename="Password Analysis",
    scan_status=result.get("status", "Unknown"),
    risk_level=result.get("risk", "Unknown"),
    scan_type="Password Scan",
    session_id=session["dashboard_session_id"]
)
    session["last_scan_result"] = result
    session["last_scan_type"] = "Password Scan"
    return render_template(
        "password_result.html",
        result=result
    )


# --------------------------------------------------
# Network Security
# --------------------------------------------------

@main_bp.route("/network-security")
def network_security():
    return render_template("network_security.html")


@main_bp.route("/scan-network", methods=["POST"])
def scan_network():

    result = analyze_network()
    update_session_health("Network Scan", result)
    save_scan(
    filename="Network Scan",
    scan_status=result.get("status", "Unknown"),
    risk_level=result.get("risk", "Unknown"),
    scan_type="Network Scan",
    session_id=session["dashboard_session_id"]
)
    session["last_scan_result"] = result
    session["last_scan_type"] = "Network Scan"
    return render_template(
        "network_result.html",
        result=result
    )

# --------------------------------------------------
# AI Threat Analysis
# --------------------------------------------------

@main_bp.route("/ai-threat-analysis")
def ai_threat_analysis():
    return render_template("ai_threat_analysis.html")


@main_bp.route("/analyze-threat", methods=["POST"])
def analyze_threat():

    findings_text = request.form.get(
        "findings",
        ""
    ).strip()

    risk = request.form.get(
        "risk",
        ""
    ).strip()

    score = request.form.get(
        "score",
        "0"
    ).strip()

    findings = []

    if findings_text:

        findings = [
            item.strip()
            for item in findings_text.splitlines()
            if item.strip()
        ]

    data = {
        "source": "CyberShield AI",
        "risk": risk,
        "score": score,
        "findings": findings,
    }

    result = analyze_security_data(data)

    return render_template(
        "ai_threat_result.html",
        result=result
    )

# --------------------------------------------------
# Incident Reporting
# --------------------------------------------------

@main_bp.route("/incident-reporting")
def incident_reporting():
    incidents = session.get("incident_reports", [])

    return render_template(
        "incident_reporting.html",
        incidents=incidents
    )


@main_bp.route("/submit-incident", methods=["POST"])
def submit_incident():

    incident_type = request.form.get(
        "incident_type",
        ""
    ).strip()

    severity = request.form.get(
        "severity",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    affected_item = request.form.get(
        "affected_item",
        ""
    ).strip()

    if not incident_type:
        return "Please select an incident type.", 400

    if not severity:
        return "Please select severity.", 400

    if not description:
        return "Please enter incident description.", 400

    report = create_incident_report(
        incident_type,
        severity,
        description,
        affected_item
    )

    return render_template(
        "incident_result.html",
        report=report
    )


@main_bp.route("/report-incident", methods=["POST"])
def report_incident():
    scanner_type = session.get("last_scan_type", "")
    affected_item = request.form.get("affected_item", "").strip()
    result = session.get("last_scan_result")

    if not result or not scanner_type:
        return "No recent scan result is available to report.", 400

    incident = create_temporary_incident(
        scanner_type,
        result,
        affected_item
    )

    incidents = session.get("incident_reports", [])

    # Prevent reporting the same scan repeatedly.
    last_reported_type = session.get("last_reported_scan_type")
    last_reported_result = session.get("last_reported_result")

    if (
        last_reported_type == scanner_type
        and last_reported_result == str(result)
    ):
        return "This scan has already been reported.", 400

    incidents.insert(0, incident)
    session["incident_reports"] = incidents[:20]
    session["last_reported_scan_type"] = scanner_type
    session["last_reported_result"] = str(result)

    return render_template(
        "incident_result.html",
        report=incident
    )




# --------------------------------------------------
# Security Analytics
# --------------------------------------------------

@main_bp.route("/security-analytics")
def security_analytics():
    chart_data = get_risk_chart_data(
        session["dashboard_session_id"]
    )

    return render_template(
        "security_analytics.html",
        chart_data=chart_data
    )
