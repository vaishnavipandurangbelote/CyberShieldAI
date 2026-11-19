
import re
import math
import json
from urllib.parse import urlparse, unquote
from email import policy
from email.parser import Parser


# ============================================================
# CYBERSHIELD AI - LOCAL EMAIL PHISHING ANALYZER
# Standard-library only; no network requests or code execution
# ============================================================

SPOOFED_BRANDS = {
    "microsoft.com": "Microsoft",
    "google.com": "Google",
    "paypal.com": "PayPal",
    "chase.com": "Chase",
    "bankofamerica.com": "Bank of America",
}

URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)

IPV4_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".msi", ".msp", ".dll", ".hta",
    ".jar", ".reg", ".lnk", ".iso", ".img",
}

SCRIPT_PATTERNS = {
    "HTML script injection": re.compile(
        r"<\s*script\b", re.IGNORECASE
    ),
    "JavaScript execution scheme": re.compile(
        r"javascript\s*:", re.IGNORECASE
    ),
    "PowerShell execution indicator": re.compile(
        r"\bpowershell(?:\.exe)?\b", re.IGNORECASE
    ),
    "Command shell execution indicator": re.compile(
        r"\bcmd(?:\.exe)?\s*/c\b", re.IGNORECASE
    ),
    "Encoded PowerShell indicator": re.compile(
        r"\b-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{12,}",
        re.IGNORECASE,
    ),
}

# Contextual patterns: each category represents a behavior,
# not simply one isolated keyword.
BEHAVIOR_PATTERNS = {
    "credential_theft": [
        r"\b(?:enter|submit|send|share|confirm|verify)"
        r"\b.{0,45}\b(?:password|passcode|otp|one[- ]time code)"
        r"\b",
        r"\b(?:sign in|log in|authenticate)\b.{0,55}"
        r"\b(?:to avoid|to prevent|to restore|to release)\b",
    ],
    "financial_pressure": [
        r"\b(?:wire transfer|bank transfer|verification deposit|"
        r"refundable deposit|release fee|processing fee)\b",
        r"\b(?:pay|transfer|deposit|remit)\b.{0,50}"
        r"\b(?:today|immediately|before release|to receive)\b",
    ],
    "employment_lure": [
        r"\b(?:job offer|job shortlist|shortlisted|recruiter|"
        r"joining documents|interview selection|employment offer)\b",
        r"\b(?:recruitment|onboarding|joining)\b.{0,60}"
        r"\b(?:fee|deposit|payment|bank details|identity documents)\b",
    ],
    "document_lure": [
        r"\b(?:shared document|document review|review the document|"
        r"view the file|document is ready|signature required)\b",
        r"\b(?:esign|e-sign|docusign|sharepoint|onedrive)\b",
    ],
    "account_threat": [
        r"\b(?:account|mailbox|profile|access)\b.{0,45}"
        r"\b(?:suspend|suspension|disable|locked|terminate|expire)\b",
        r"\b(?:restore|unlock|reactivate)\b.{0,40}"
        r"\b(?:account|access|mailbox|profile)\b",
    ],
    "impersonation": [
        r"\b(?:on behalf of|acting for|from the office of|"
        r"our ceo|our cfo|the managing director)\b",
        r"\b(?:payroll|human resources|hr department|finance team)\b",
    ],
    "data_exfiltration": [
        r"\b(?:send|upload|forward|provide|share)\b.{0,45}"
        r"\b(?:customer data|employee records|database export|"
        r"confidential files|identity documents)\b",
    ],
}

URGENCY_PATTERN = re.compile(
    r"\b(?:urgent|immediately|right now|act now|within \d+\s+hours?|"
    r"final warning|last chance|without delay|before the deadline|"
    r"expires today|time sensitive)\b",
    re.IGNORECASE,
)

REWARD_PATTERN = re.compile(
    r"\b(?:you have won|claim your prize|guaranteed income|"
    r"exclusive reward|selected winner|unclaimed funds|"
    r"unexpected refund)\b",
    re.IGNORECASE,
)

SUSPICIOUS_DOMAIN_WORDS = {
    "login", "verify", "secure", "account", "update",
    "payment", "password", "wallet", "support", "confirm",
    "validation", "recovery", "authentication",
}


def _unique(items):
    """Preserve order while removing duplicate values."""
    return list(dict.fromkeys(items))


def _extract_urls(text):
    """Extract HTTP(S) and www links without visiting them."""
    results = []

    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,;:!?)\"]}")
        if url.lower().startswith("www."):
            url = "http://" + url

        if url not in results:
            results.append(url)

    return results


def _normalize_domain(domain):
    """Normalize a hostname for comparisons without DNS lookups."""
    domain = domain.strip().strip(".").lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def _valid_ipv4(host):
    """Validate dotted-decimal IPv4 without network access."""
    if not IPV4_PATTERN.fullmatch(host):
        return False

    try:
        parts = [int(part) for part in host.split(".")]
        return all(0 <= part <= 255 for part in parts)
    except ValueError:
        return False


def _levenshtein_distance(first, second):
    """Compute Levenshtein edit distance using bounded memory."""
    if first == second:
        return 0

    if len(first) < len(second):
        first, second = second, first

    if not second:
        return len(first)

    previous = list(range(len(second) + 1))

    for i, char_a in enumerate(first, start=1):
        current = [i]

        for j, char_b in enumerate(second, start=1):
            insertion = current[j - 1] + 1
            deletion = previous[j] + 1
            substitution = previous[j - 1] + (char_a != char_b)

            current.append(
                min(insertion, deletion, substitution)
            )

        previous = current

    return previous[-1]


def _extract_sender_domain(sender):
    """Extract a sender domain from an address or display-name form."""
    sender = sender.strip()

    if not sender:
        return ""

    try:
        parsed = Parser(policy=policy.default).parsestr(
            "From: " + sender + "\n\n"
        )
        addresses = parsed.get_all("From", [])
        if addresses:
            address_list = addresses[0].addresses
            if address_list:
                return _normalize_domain(address_list[0].domain or "")
    except (ValueError, TypeError, AttributeError):
        pass

    match = re.search(r"@([A-Za-z0-9.-]+)", sender)

    if match:
        return _normalize_domain(match.group(1))

    return ""


def _extract_email_content(email_text):
    """
    If the input is a raw email with headers, parse it locally.
    Otherwise treat the supplied text as the message body.
    """
    result = {
        "body": email_text,
        "subject": "",
        "from": "",
        "reply_to": "",
        "headers_present": False,
    }

    if not re.search(
        r"(?im)^(From|To|Subject|Date|MIME-Version|"
        r"Content-Type|Reply-To):\s*",
        email_text,
    ):
        return result

    try:
        message = Parser(policy=policy.default).parsestr(email_text)

        result["headers_present"] = True
        result["subject"] = str(message.get("Subject", ""))
        result["from"] = str(message.get("From", ""))
        result["reply_to"] = str(message.get("Reply-To", ""))

        parts = []

        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue

                if part.get_content_type() == "text/plain":
                    try:
                        payload = part.get_content()
                        if isinstance(payload, str):
                            parts.append(payload)
                    except (LookupError, UnicodeError, ValueError):
                        continue
        else:
            try:
                payload = message.get_content()
                if isinstance(payload, str):
                    parts.append(payload)
            except (LookupError, UnicodeError, ValueError):
                pass

        if parts:
            result["body"] = "\n".join(parts)

    except (ValueError, TypeError, AttributeError):
        pass

    return result


def _analyze_domain(domain, findings, categories):
    """Assess structural domain indicators; no DNS or reputation lookup."""
    domain = _normalize_domain(domain)

    if not domain:
        return 0

    score = 0
    labels = domain.split(".")

    if any(not label for label in labels):
        findings.append("Malformed hostname structure detected.")
        categories.add("suspicious_url")
        score += 10

    if len(labels) >= 5:
        findings.append(
            f"URL hostname contains many subdomain labels: {domain}"
        )
        categories.add("suspicious_url")
        score += 12

    hyphens = domain.count("-")

    if hyphens >= 3:
        findings.append(
            f"Domain contains multiple routing or brand-like hyphens: {domain}"
        )
        categories.add("suspicious_url")
        score += 12

    if _valid_ipv4(domain):
        findings.append(
            f"URL uses a raw IPv4 address instead of a domain: {domain}"
        )
        categories.add("ip_url")
        score += 25

    suspicious_matches = sorted(
        word for word in SUSPICIOUS_DOMAIN_WORDS
        if word in domain
    )

    if len(suspicious_matches) >= 3:
        findings.append(
            "Domain combines several security-related terms: "
            + ", ".join(suspicious_matches[:6])
        )
        categories.add("suspicious_url")
        score += 12

    # Non-ASCII and punycode hostnames deserve scrutiny but are
    # not proof of a homograph attack.
    if any(ord(char) > 127 for char in domain) or "xn--" in domain:
        findings.append(
            f"Internationalized or punycode hostname requires review: {domain}"
        )
        categories.add("homograph")
        score += 18

    return score


def _check_brand_similarity(domain, findings, categories):
    """
    Compare the hostname's last two labels with protected brand domains.
    This is a heuristic, not a complete public-suffix implementation.
    """
    domain = _normalize_domain(domain)
    labels = domain.split(".")

    if len(labels) < 2:
        return 0

    root_candidate = ".".join(labels[-2:])

    if root_candidate in SPOOFED_BRANDS:
        return 0

    candidate_label = labels[-2]
    score = 0

    for brand_domain, brand_name in SPOOFED_BRANDS.items():
        brand_label = brand_domain.split(".")[0]

        distance = _levenshtein_distance(
            candidate_label, brand_label
        )

        max_length = max(len(candidate_label), len(brand_label), 1)
        similarity = 1 - distance / max_length

        # Require a similar length and close edit distance to reduce
        # false positives from ordinary unrelated domains.
        if (
            distance in (1, 2)
            and abs(len(candidate_label) - len(brand_label)) <= 2
            and similarity >= 0.75
        ):
            findings.append(
                f"Possible lookalike of {brand_name}: "
                f"{domain} resembles {brand_domain}."
            )
            categories.add("brand_spoofing")
            score = max(score, 40)

    return score


def _collect_behavior_signals(text, findings, categories):
    """Detect contextual social-engineering themes."""
    lower_text = text.lower()
    detected = {}

    for category, patterns in BEHAVIOR_PATTERNS.items():
        matched = []

        for pattern in patterns:
            if re.search(pattern, lower_text, re.IGNORECASE | re.DOTALL):
                matched.append(pattern)

        if matched:
            detected[category] = len(matched)
            categories.add(category)

    if detected:
        labels = {
            "credential_theft": "credential harvesting",
            "financial_pressure": "financial or payment pressure",
            "employment_lure": "employment or recruitment lure",
            "document_lure": "document-sharing or signature lure",
            "account_threat": "account access threat",
            "impersonation": "possible organizational impersonation",
            "data_exfiltration": "sensitive data request",
        }

        for category in detected:
            findings.append(
                "Contextual social-engineering indicator: "
                + labels[category] + "."
            )

    if URGENCY_PATTERN.search(text):
        categories.add("urgency")
        findings.append("Urgency or time-pressure language detected.")

    if REWARD_PATTERN.search(text):
        categories.add("reward_lure")
        findings.append("Unexpected reward or prize language detected.")

    return detected


def analyze_email(email_text, sender=""):
    """
    Analyze email text locally.

    Compatible primary result fields:
    success, status, risk, score, sender, email_length, urls,
    url_count, findings, recommendations.

    Scores are heuristic indicators, not calibrated probabilities.
    """
    if not isinstance(email_text, str) or not email_text.strip():
        return {
            "success": False,
            "status": "Invalid",
            "risk": "Unknown",
            "score": 0,
            "sender": sender or "",
            "email_length": 0,
            "urls": [],
            "url_count": 0,
            "findings": ["No email content was provided."],
            "recommendations": [
                "Paste an email body or provide raw email text."
            ],
            "categories": [],
            "confidence": "Not assessed",
        }

    raw_text = email_text.strip()
    parsed = _extract_email_content(raw_text)

    body = parsed["body"]
    subject = parsed["subject"]
    effective_sender = sender.strip() if isinstance(sender, str) else ""

    if not effective_sender:
        effective_sender = parsed["from"]

    analysis_text = "\n".join(
        value for value in (subject, body) if value
    )

    # Include metadata fields for inspection, but do not treat arbitrary
    # header text as proof of maliciousness.
    metadata_text = "\n".join(
        value for value in (
            parsed["from"], parsed["reply_to"], subject
        ) if value
    )

    findings = []
    recommendations = []
    categories = set()
    score = 0

    # 1. Contextual social engineering
    behaviors = _collect_behavior_signals(
        analysis_text, findings, categories
    )

    behavior_weights = {
        "credential_theft": 22,
        "financial_pressure": 22,
        "employment_lure": 12,
        "document_lure": 10,
        "account_threat": 15,
        "impersonation": 12,
        "data_exfiltration": 20,
    }

    for category, weight in behavior_weights.items():
        if category in behaviors:
            score += weight

    if "urgency" in categories:
        score += 10

    if "reward_lure" in categories:
        score += 10

    # 2. Extract and inspect URLs, without visiting them
    urls = _extract_urls(analysis_text + "\n" + metadata_text)
    url_domains = []

    for url in urls:
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname

            if not hostname:
                findings.append(
                    f"URL has no recognizable hostname: {url[:160]}"
                )
                categories.add("suspicious_url")
                score += 12
                continue

            domain = _normalize_domain(hostname)
            url_domains.append(domain)

            if parsed_url.scheme.lower() == "http":
                findings.append(
                    f"Unencrypted HTTP destination detected: {domain}"
                )
                categories.add("http_url")
                score += 10

            score += _analyze_domain(domain, findings, categories)
            score += _check_brand_similarity(
                domain, findings, categories
            )

            decoded_url = unquote(url)

            if re.search(r"@[^/]+", parsed_url.netloc):
                findings.append(
                    f"URL contains user-information syntax: {domain}"
                )
                categories.add("suspicious_url")
                score += 18

            if "\\" in url or "\\" in decoded_url:
                findings.append(
                    "URL contains backslash characters that may confuse readers."
                )
                categories.add("suspicious_url")
                score += 10

        except (ValueError, UnicodeError):
            findings.append("A URL could not be parsed safely.")
            categories.add("suspicious_url")
            score += 10

    if urls:
        findings.append(
            f"{len(urls)} unique URL(s) extracted for static analysis."
        )

    # 3. Sender format, lookalikes, and reply-to mismatches
    sender_domain = _extract_sender_domain(effective_sender)

    if effective_sender and not EMAIL_PATTERN.fullmatch(
        effective_sender.strip().strip("<>")
    ):
        # Display-name forms can be valid; the parser's domain extraction
        # is more useful than rejecting them categorically.
        if not sender_domain:
            findings.append(
                "Sender does not contain a recognizable email domain."
            )
            categories.add("sender_anomaly")
            score += 8

    if sender_domain:
        score += _check_brand_similarity(
            sender_domain, findings, categories
        )

    reply_to_domain = _extract_sender_domain(parsed["reply_to"])

    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        findings.append(
            "Reply-To domain differs from the sender domain."
        )
        categories.add("reply_to_mismatch")
        score += 18

    # 4. Script, command execution, and double-extension indicators
    attack_text = raw_text + "\n" + metadata_text

    for label, pattern in SCRIPT_PATTERNS.items():
        if pattern.search(attack_text):
            findings.append(f"Potential attack indicator: {label}.")
            categories.add("execution_indicator")
            score += 25

    double_extension_pattern = re.compile(
        r"\b[\w-]+\.(?:pdf|docx?|xlsx?|jpg|jpeg|png|txt|zip)"
        r"\.(?:" + "|".join(
            re.escape(ext.lstrip("."))
            for ext in sorted(DANGEROUS_EXTENSIONS)
        ) + r")\b",
        re.IGNORECASE,
    )

    for match in double_extension_pattern.findall(attack_text):
        findings.append(
            f"Potential deceptive double-extension filename: {match}"
        )
        categories.add("dangerous_attachment")
        score += 30

    
    for extension in DANGEROUS_EXTENSIONS:
        pattern = re.compile(
            r"(?<![\w.-])[\w-]+"
            + re.escape(extension)
            + r"(?![\w.-])",
            re.IGNORECASE,
        )

        if pattern.search(attack_text):
            if "dangerous_attachment" not in categories:
                findings.append(
                    f"Potentially dangerous file extension mentioned: {extension}"
                )
                categories.add("dangerous_attachment")
                score += 12


    # 5. Composite behavioral matrix
    # Compound scores when independent categories co-occur.
    compound_pairs = [
        (
            {"urgency", "suspicious_url"},
            1.30,
            "Urgency combined with suspicious URL structure.",
        ),
        (
            {"credential_theft", "suspicious_url"},
            1.35,
            "Credential request combined with a suspicious URL.",
        ),
        (
            {"financial_pressure", "urgency"},
            1.25,
            "Financial pressure combined with urgency.",
        ),
        (
            {"brand_spoofing", "credential_theft"},
            1.40,
            "Possible brand spoofing combined with credential collection.",
        ),
        (
            {"employment_lure", "financial_pressure"},
            1.35,
            "Recruitment lure combined with payment pressure.",
        ),
        (
            {"document_lure", "suspicious_url"},
            1.25,
            "Document lure combined with suspicious URL structure.",
        ),
        (
            {"execution_indicator", "dangerous_attachment"},
            1.40,
            "Execution indicators combined with a risky attachment name.",
        ),
        (
            {"impersonation", "financial_pressure"},
            1.35,
            "Possible impersonation combined with financial pressure.",
        ),
    ]

    multiplier = 1.0

    for required, factor, explanation in compound_pairs:
        if required.issubset(categories):
            multiplier *= factor
            findings.append(
                "Composite risk factor: " + explanation
            )

    # Bound the multiplier so many correlated indicators do not
    # make the score grow without limit.
    multiplier = min(multiplier, 2.25)
    score = min(100, int(math.ceil(score * multiplier)))

    # 6. Final risk assessment
    if score >= 70:
        status = "High Risk"
        risk = "High"
    elif score >= 35:
        status = "Suspicious"
        risk = "Medium"
    else:
        status = "No Strong Indicators Found"
        risk = "Low"

    if not findings:
        findings.append(
            "No indicators covered by this static analysis were identified."
        )

    if risk == "High":
        recommendations.extend([
            "Do not click links, reply, send money, or open attachments.",
            "Verify the sender using an independently obtained contact method.",
            "Report the message to your security team or email provider.",
        ])
    elif risk == "Medium":
        recommendations.extend([
            "Verify the sender and destination independently before acting.",
            "Do not provide credentials, OTPs, payment details, or confidential data.",
            "Inspect complete email headers and authentication results if available.",
        ])
    else:
        recommendations.extend([
            "No strong indicators covered by these rules were detected; this does not prove the email is safe.",
            "Verify unexpected requests through a separate trusted channel.",
        ])

    if categories.intersection({
        "brand_spoofing", "homograph", "suspicious_url",
        "ip_url", "http_url",
    }):
        recommendations.append(
            "Avoid visiting suspicious destinations; this analyzer does not check live website reputation."
        )

    recommendations = _unique(recommendations)
    findings = _unique(findings)

    return {
        "success": True,
        "status": status,
        "risk": risk,
        "score": score,
        "sender": effective_sender,
        "email_length": len(raw_text),
        "urls": urls,
        "url_count": len(urls),
        "findings": findings,
        "recommendations": recommendations,
        "categories": sorted(categories),
        "confidence": "Heuristic score; not a calibrated probability",
        "analysis_mode": "Local static analysis",
        "network_access": False,
        "header_analysis_available": parsed["headers_present"],
    }
