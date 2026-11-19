from typing import Any, Dict, List


def _add_unique(items: List[str], value: str):
    if value and value not in items:
        items.append(value)


def analyze_security_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    CyberShield AI local threat-analysis engine.

    Receives results from CyberShield security scanners and
    automatically generates a unified threat assessment.

    No external API or paid AI service is required.
    """

    if not isinstance(data, dict):
        data = {}

    threats = []
    indicators = []
    recommendations = []

    threat_score = 0

    source = str(
        data.get("source", "CyberShield AI")
    )

    risk = str(
        data.get("risk", "")
    ).lower()

    status = str(
        data.get("status", "")
    ).lower()

    # ==================================================
    # 1. Scanner Risk
    # ==================================================

    if risk == "high":

        threat_score += 40

        _add_unique(
            threats,
            "The security scanner reported a high-risk finding."
        )

    elif risk == "medium":

        threat_score += 25

        _add_unique(
            threats,
            "The security scanner reported a medium-risk finding."
        )

    elif risk == "low":

        threat_score += 0

    # ==================================================
    # 2. Scanner Status
    # ==================================================

    
    negative_statuses = [
        "no threat detected",
        "no threats detected",
        "no malware detected",
        "not infected",
        "scan incomplete",
        "needs review",
    ]

    is_negative_status = any(
        phrase in status
        for phrase in negative_statuses
    )

    if not is_negative_status and any(
        word in status
        for word in [
            "threat detected",
            "threats detected",
            "infected",
            "malicious",
        ]
    ):
        threat_score += 20

        _add_unique(
            threats,
            "The security scanner detected a potential threat."
        )


    # ==================================================
    # 3. File Information
    # ==================================================

    filename = data.get("filename")

    if filename:

        _add_unique(
            indicators,
            f"File analyzed: {filename}"
        )

    extension = data.get("extension")

    if extension:

        _add_unique(
            indicators,
            f"File type: {extension}"
        )

    size = data.get("size")

    if size is not None:

        _add_unique(
            indicators,
            f"File size: {size} bytes"
        )

    sha256 = data.get("sha256")

    if sha256:

        _add_unique(
            indicators,
            f"SHA-256: {sha256}"
        )

    # ==================================================
    # 4. ClamAV Analysis
    # ==================================================

    clamav_available = data.get(
        "clamav_available",
        False
    )

    clamav_infected = data.get(
        "clamav_infected",
        False
    )

    if clamav_available:

        _add_unique(
            indicators,
            "ClamAV antivirus engine was available for scanning."
        )

    if clamav_infected:

        # ClamAV is the strongest indicator here.
        threat_score += 40

        _add_unique(
            threats,
            "ClamAV detected a malware signature in the file."
        )

        _add_unique(
            recommendations,
            "Do not open or execute the detected file."
        )

        _add_unique(
            recommendations,
            "Quarantine or remove the detected file."
        )

        _add_unique(
            recommendations,
            "Perform a full system scan to check for additional threats."
        )

    # ==================================================
    # 5. Hash Reputation
    # ==================================================

    hash_match = data.get(
        "hash_match",
        False
    )

    if hash_match:

        threat_score += 35

        category = data.get(
            "hash_category",
            "Unknown"
        )

        _add_unique(
            threats,
            "The file SHA-256 hash matched an entry in the local threat database."
        )

        _add_unique(
            indicators,
            f"Threat-hash category: {category}"
        )

        _add_unique(
            recommendations,
            "Do not trust or execute the detected file."
        )

   
    # ==================================================
    # 6. Scanner Findings
    # ==================================================

    findings = data.get("findings", [])

    if isinstance(findings, list):

        for finding in findings:

            finding_text = str(finding).strip()

            if not finding_text:
                continue

            _add_unique(indicators, finding_text)

            lower = finding_text.lower()

            # Do not treat successful or negative scan messages
            # as evidence of malware.
            benign_scan_message = any(
                phrase in lower
                for phrase in [
                    "no malware was detected",
                    "no threat was detected",
                    "scan completed successfully",
                    "no threats found",
                    "no virus found",
                    "no infection found",
                ]
            )

            if benign_scan_message:
                continue

            # Malware: count explicit positive findings only.
            if any(
                phrase in lower
                for phrase in [
                    "detected malware",
                    "malware detected",
                    "virus detected",
                    "trojan detected",
                    "eicar-signature found",
                    "clamav detected",
                    "hash matched an entry",
                    "infected",
                    "malicious file detected",
                ]
            ):
                threat_score += 20

                _add_unique(
                    threats,
                    "A positive malware-related finding was reported."
                )

            # Phishing indicators
            if any(
                phrase in lower
                for phrase in [
                    "phishing",
                    "suspicious url",
                    "malicious url",
                    "credential theft",
                ]
            ):
                threat_score += 25

                _add_unique(
                    threats,
                    "Potential phishing indicators were identified."
                )

                _add_unique(
                    recommendations,
                    "Avoid opening the suspicious URL or entering credentials."
                )

            # HTTP security
            if (
                "does not use https" in lower
                or "http connection" in lower
            ):
                threat_score += 5

                _add_unique(
                    recommendations,
                    "Prefer HTTPS websites and avoid entering sensitive information over unsecured connections."
                )


    # ==================================================
    # 7. Scanner Recommendations
    # ==================================================

    supplied_recommendations = data.get(
        "recommendations",
        []
    )

    if isinstance(
        supplied_recommendations,
        list
    ):

        for recommendation in supplied_recommendations:

            recommendation = str(
                recommendation
            ).strip()

            if recommendation:

                _add_unique(
                    recommendations,
                    recommendation
                )

    # ==================================================
    # 8. Normalize Score
    # ==================================================

    threat_score = max(
        0,
        min(
            threat_score,
            100
        )
    )

    # ==================================================
    # 9. Threat Classification
    # ==================================================

    if threat_score >= 80:

        threat_level = "Critical"

        priority = "Immediate"

        summary = (
            "Critical security indicators were detected. "
            "Immediate action is recommended."
        )

    elif threat_score >= 60:

        threat_level = "High"

        priority = "High"

        summary = (
            "Significant security threats were detected. "
            "The affected item should be investigated and secured promptly."
        )

    elif threat_score >= 30:

        threat_level = "Medium"

        priority = "Moderate"

        summary = (
            "Potential security weaknesses were identified. "
            "Recommended security improvements should be applied."
        )

    else:

        threat_level = "Low"

        priority = "Routine"

        summary = (
            "No major threat indicators were identified "
            "from the supplied scanner results."
        )

    # ==================================================
    # 10. Default Results
    # ==================================================

    if not threats:

        threats.append(
            "No significant threat pattern was identified."
        )

    if not indicators:

        indicators.append(
            "No specific security indicators were supplied."
        )

    if not recommendations:

        recommendations.append(
            "Continue using updated security software "
            "and maintain good cybersecurity practices."
        )

    # ==================================================
    # 11. Final Result
    # ==================================================

    return {

        "success": True,

        "source": source,

        "threat_score": threat_score,

        "threat_level": threat_level,

        "priority": priority,

        "summary": summary,

        "threats": threats,

        "indicators": indicators,

        "recommendations": recommendations
    }