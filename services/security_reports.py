from pathlib import Path
import json


REPORTS_FOLDER = Path("reports")


def get_security_reports():
    """
    Read all locally stored incident reports.
    """

    REPORTS_FOLDER.mkdir(exist_ok=True)

    reports = []

    for report_file in REPORTS_FOLDER.glob("*.json"):

        try:

            with open(
                report_file,
                "r",
                encoding="utf-8"
            ) as file:

                report = json.load(file)

            reports.append(report)

        except (json.JSONDecodeError, OSError):
            continue


    # Newest reports first
    reports.sort(
        key=lambda item: item.get(
            "timestamp",
            ""
        ),
        reverse=True
    )


    total_reports = len(reports)

    open_reports = sum(
        1
        for report in reports
        if report.get("status") == "Open"
    )

    high_risk_reports = sum(
        1
        for report in reports
        if report.get("severity") in [
            "High",
            "Critical"
        ]
    )


    return {
        "success": True,
        "total_reports": total_reports,
        "open_reports": open_reports,
        "high_risk_reports": high_risk_reports,
        "reports": reports
    }