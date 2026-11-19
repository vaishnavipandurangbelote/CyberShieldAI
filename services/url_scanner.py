
import socket
import ipaddress
import re
import json
import math

from urllib.parse import urlparse, parse_qsl, unquote


# ==================================================
# CYBERSHIELD AI - URL PHISHING ENGINE
# Standard library only; no HTTP requests or browsing
# ==================================================

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "password",
    "confirm", "bank", "payment", "wallet", "free", "bonus",
    "reward", "claim", "urgent", "suspended", "limited",
    "reset", "authenticate", "credential", "unlock",
    "webscr", "recover", "validate", "invoice", "transfer",
}

TARGET_BRANDS = {
    "microsoft", "google", "paypal", "chase",
    "bankofamerica", "apple", "netflix",
}

SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "shorturl.at",
    "cutt.ly", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "rb.gy", "t.ly", "lnkd.in",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".msi", ".msp", ".dll", ".hta",
    ".jar", ".reg", ".lnk", ".iso", ".img",
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)"
    r"\.(?:exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|"
    r"wsf|wsh|ps1|msi|dll|hta|jar|lnk)\b",
    re.IGNORECASE,
)

INJECTION_PATTERNS = [
    (
        re.compile(r"<\s*script\b", re.IGNORECASE),
        "Script-injection pattern found in the URL.",
        25,
    ),
    (
        re.compile(r"javascript\s*:", re.IGNORECASE),
        "JavaScript execution scheme found in the URL.",
        25,
    ),
    (
        re.compile(r"(?:%3c|<)\s*iframe\b", re.IGNORECASE),
        "Embedded-frame injection pattern found in the URL.",
        20,
    ),
    (
        re.compile(r"(?:\.\./|%2e%2e%2f){2,}", re.IGNORECASE),
        "Repeated path-traversal sequences found in the URL.",
        15,
    ),
]


# ==================================================
# HELPERS
# ==================================================

def _add_finding(findings, message):
    if message not in findings:
        findings.append(message)


def _decode_repeatedly(value, rounds=2):
    """Decode URL encoding a limited number of times."""
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _get_registrable_candidate(hostname):
    """
    Approximate the registrable domain using the final two labels.
    This is not a Public Suffix List implementation.
    """
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    labels = hostname.rstrip(".").split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname


def _levenshtein_distance(first, second):
    """Calculate edit distance using O(min(n, m)) memory."""
    if len(first) < len(second):
        first, second = second, first

    previous = list(range(len(second) + 1))

    for i, char_first in enumerate(first, start=1):
        current = [i]

        for j, char_second in enumerate(second, start=1):
            insertion = current[j - 1] + 1
            deletion = previous[j] + 1
            substitution = previous[j - 1] + (
                char_first != char_second
            )
            current.append(min(insertion, deletion, substitution))

        previous = current

    return previous[-1]



def _brand_similarity(hostname):
    """Check hostname labels for brand impersonation."""
    labels = hostname.rstrip(".").lower().split(".")

    visual_map = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
    })

    for label in labels:
        if not label or label in {
            "www", "com", "net", "org", "co", "uk", "example"
        }:
            continue

        normalized = label.translate(visual_map)

        for brand in TARGET_BRANDS:
            # Do not flag the exact brand label.
            if label == brand:
                continue

            # Detect a brand name embedded in a longer label.
            if brand in label:
                return brand, _levenshtein_distance(normalized, brand)

            distance = min(
                _levenshtein_distance(label, brand),
                _levenshtein_distance(normalized, brand),
            )

            threshold = 1 if len(brand) <= 5 else 2

            if distance <= threshold:
                return brand, distance

    return None, None



def _is_public_ip(ip_text):
    try:
        address = ipaddress.ip_address(ip_text)
        return address.is_global
    except ValueError:
        return False


def _resolve_hostname(hostname):
    """
    Resolve only the hostname. This never opens the submitted URL.
    DNS resolution may still contact the configured DNS resolver.
    """
    try:
        return socket.gethostbyname(hostname), None
    except (socket.gaierror, socket.timeout, OSError) as exc:
        return None, str(exc)


def _valid_hostname(hostname):
    if not hostname or len(hostname) > 253:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    labels = hostname.rstrip(".").split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False

    return True


# ==================================================
# MAIN URL ANALYSIS
# ==================================================

def analyze_url(url):

    original_url = str(url or "").strip()

    if not original_url:
        return {
            "success": False,
            "status": "Invalid",
            "risk": "Unknown",
            "url": original_url,
            "domain": "",
            "score": 0,
            "findings": ["No URL was provided."],
            "resolved_ip": None,
        }

    # Reject control characters and whitespace that can make
    # URL interpretation ambiguous.
    if any(ord(char) < 32 or char.isspace() for char in original_url):
        return {
            "success": False,
            "status": "Invalid",
            "risk": "Unknown",
            "url": original_url,
            "domain": "",
            "score": 0,
            "findings": [
                "The URL contains whitespace or control characters."
            ],
            "resolved_ip": None,
        }

    # Keep compatibility with inputs lacking a scheme.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original_url):
        normalized_url = "http://" + original_url
    else:
        normalized_url = original_url

    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, TypeError):
        return {
            "success": False,
            "status": "Invalid",
            "risk": "Unknown",
            "url": normalized_url,
            "domain": "",
            "score": 0,
            "findings": ["The URL could not be parsed safely."],
            "resolved_ip": None,
        }

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or not _valid_hostname(hostname.lower())
        or (port is not None and not 1 <= port <= 65535)
    ):
        return {
            "success": False,
            "status": "Invalid",
            "risk": "Unknown",
            "url": normalized_url,
            "domain": hostname or "",
            "score": 0,
            "findings": [
                "The URL has an unsupported scheme or invalid authority."
            ],
            "resolved_ip": None,
        }

    hostname = hostname.rstrip(".").lower()
    scheme = parsed.scheme.lower()

    # Analyze each component independently.
    path_text = _decode_repeatedly(parsed.path.lower())
    query_text = _decode_repeatedly(parsed.query.lower())
    fragment_text = _decode_repeatedly(parsed.fragment.lower())
    full_text = _decode_repeatedly(normalized_url.lower())

    query_pairs = parse_qsl(
        query_text,
        keep_blank_values=True,
        max_num_fields=200,
    )

    query_values = " ".join(
        f"{key} {value}" for key, value in query_pairs
    )

    score = 0
    findings = []
    categories = set()
    resolved_ip = None

    def add_score(category, points, message):
        nonlocal score
        score += points
        categories.add(category)
        _add_finding(findings, message)

    # --------------------------------------------------
    # 1. Transport security
    # --------------------------------------------------

    if scheme == "http":
        add_score(
            "unencrypted_transport",
            15,
            "The URL uses unencrypted HTTP instead of HTTPS.",
        )

    # --------------------------------------------------
    # 2. Literal IP address
    # --------------------------------------------------

    try:
        literal_ip = ipaddress.ip_address(hostname)
        resolved_ip = str(literal_ip)

        if not literal_ip.is_global:
            add_score(
                "non_public_address",
                20,
                "The URL points to a non-public IP address.",
            )
        else:
            add_score(
                "literal_ip",
                20,
                "The URL uses an IP address instead of a domain name.",
            )

    except ValueError:
        literal_ip = None

    # --------------------------------------------------
    # 3. DNS resolution and network scope
    # --------------------------------------------------

    if literal_ip is None:
        resolved_ip, dns_error = _resolve_hostname(hostname)

        if resolved_ip:
            try:
                resolved_address = ipaddress.ip_address(resolved_ip)

                if not resolved_address.is_global:
                    add_score(
                        "non_public_address",
                        20,
                        "DNS resolved the domain to a non-public IP address. "
                        "This may be expected in a local lab or private network.",
                    )
            except ValueError:
                resolved_ip = None

        else:
            # DNS failure can be temporary or intentional. Use a modest
            # penalty rather than treating it as proof of phishing.
            add_score(
                "dns_resolution_failure",
                5,
                "The hostname could not be resolved by the configured DNS resolver.",
            )

    # --------------------------------------------------
    # 4. URL shortener / masked gateway
    # --------------------------------------------------

    if hostname in SHORTENING_DOMAINS:
        add_score(
            "shortened_url",
            20,
            "The hostname belongs to a known URL-shortening service; "
            "the final destination is not visible from this URL alone.",
        )

    # --------------------------------------------------
    # 5. Hostname structure
    # --------------------------------------------------

    labels = hostname.split(".")

    if len(labels) >= 5:
        add_score(
            "excessive_subdomains",
            15,
            "The hostname contains many domain labels and subdomains.",
        )

    if hostname.count("-") >= 3:
        add_score(
            "many_hyphens",
            10,
            "The hostname contains multiple hyphens.",
        )

    if re.search(r"\d{4,}", hostname):
        add_score(
            "numeric_hostname",
            10,
            "The hostname contains an unusually long numeric sequence.",
        )

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_score(
            "punycode_hostname",
            15,
            "The hostname contains a punycode label; inspect for deceptive characters.",
        )

    # --------------------------------------------------
    # 6. Brand impersonation / typosquatting
    # --------------------------------------------------

    brand, distance = _brand_similarity(hostname)

    if brand:
        add_score(
            "brand_impersonation",
            25,
            f"The domain resembles the brand '{brand}' "
            f"(edit distance: {distance}).",
        )

    # --------------------------------------------------
    # 7. Suspicious words in each component
    # --------------------------------------------------

    matched_keywords = set()

    components = {
        "hostname": hostname,
        "path": path_text,
        "query": query_values,
        "fragment": fragment_text,
    }

    for component_name, component_value in components.items():
        padded_value = re.sub(r"[^a-z0-9]+", " ", component_value)

        for keyword in SUSPICIOUS_KEYWORDS:
            # Match tokens, not arbitrary substrings such as "bank"
            # inside an unrelated longer word.
            if re.search(
                r"(?<![a-z0-9])"
                + re.escape(keyword)
                + r"(?![a-z0-9])",
                padded_value,
            ):
                matched_keywords.add(keyword)

    if matched_keywords:
        add_score(
            "phishing_keywords",
            min(5 * len(matched_keywords), 20),
            "Potential phishing-related terms found: "
            + ", ".join(sorted(matched_keywords)),
        )

    # --------------------------------------------------
    # 8. URL length and authority tricks
    # --------------------------------------------------

    if len(normalized_url) > 200:
        add_score(
            "long_url",
            10,
            "The URL is unusually long.",
        )

    if "@" in parsed.netloc:
        add_score(
            "authority_at_symbol",
            25,
            "The URL authority contains an '@' symbol, which can mislead readers.",
        )

    
    
    if len(query_pairs) > 12:
        add_score(
            "complex_query",
            10,
            "The URL contains more than 12 query parameters.",
        )



    # --------------------------------------------------
    # 9. Injection patterns across all URL components
    # --------------------------------------------------

    for pattern, message, points in INJECTION_PATTERNS:
        if pattern.search(full_text):
            add_score(
                "url_injection",
                points,
                message,
            )

    # --------------------------------------------------
    # 10. Double-extension payloads
    # --------------------------------------------------

    if DOUBLE_EXTENSION_PATTERN.search(full_text):
        add_score(
            "double_extension",
            25,
            "A potentially deceptive double-extension filename was found.",
        )

    # Check dangerous-looking filename extensions in the path only.
    # This avoids treating a normal domain suffix such as .com as a file.
    path_segments = path_text.rstrip("/").split("/")

    if path_segments:
        last_segment = path_segments[-1]
        filename = last_segment.split("?")[0]

        if "." in filename:
            extension = "." + filename.rsplit(".", 1)[-1]

            if extension in DANGEROUS_EXTENSIONS:
                add_score(
                    "dangerous_file_extension",
                    15,
                    "The URL path ends with a potentially dangerous file extension: "
                    + extension,
                )

    # --------------------------------------------------
    # 11. Composite hazard multiplier
    # --------------------------------------------------

    # Escalate only when unencrypted HTTP co-occurs with a
    # phishing keyword or brand-impersonation signal.
    if (
        scheme == "http"
        and (
            "phishing_keywords" in categories
            or "brand_impersonation" in categories
        )
    ):
        score = math.ceil(score * 1.35)
        _add_finding(
            findings,
            "Combined hazard: HTTP is used alongside phishing-related "
            "or brand-impersonation indicators.",
        )

    # Cap score after all additive and multiplicative adjustments.
    score = max(0, min(int(score), 100))

    # --------------------------------------------------
    # 12. Final classification
    # --------------------------------------------------

    if score >= 60:
        risk = "High"
        status = "Potential Phishing"
    elif score >= 30:
        risk = "Medium"
        status = "Suspicious"
    else:
        risk = "Low"
        status = "Likely Safe"

    if not findings:
        findings.append(
            "No strong indicators covered by these rules were identified."
        )

    # Return existing frontend fields plus resolved_ip.
    return {
        "success": True,
        "status": status,
        "risk": risk,
        "url": normalized_url,
        "domain": hostname,
        "score": score,
        "findings": findings,
        "resolved_ip": resolved_ip,
    }
