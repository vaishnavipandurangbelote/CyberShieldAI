import socket


# Common services that are useful for a basic local security check.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Proxy/Alternative HTTP",
}


def get_local_ip():
    """
    Get the local machine's IP address.
    """

    try:
        hostname = socket.gethostname()

        local_ip = socket.gethostbyname(hostname)

        # Avoid returning loopback when possible.
        if local_ip.startswith("127."):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            try:
                sock.connect(("8.8.8.8", 80))
                local_ip = sock.getsockname()[0]
            finally:
                sock.close()

        return local_ip

    except Exception:
        return "127.0.0.1"


def check_port(host, port, timeout=0.5):
    """
    Safely check whether a TCP port is accepting connections.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((host, port))

        return result == 0

    except Exception:
        return False

    finally:
        sock.close()


def analyze_network():
    """
    Perform a basic security check on the local computer only.
    """

    hostname = socket.gethostname()

    local_ip = get_local_ip()

    target = "127.0.0.1"

    scan_results = []

    open_ports = []

    security_findings = []

    recommendations = []

    # --------------------------------------------------
    # Check common ports
    # --------------------------------------------------

    for port, service in COMMON_PORTS.items():
        is_open = check_port(target, port)


        result = {
            "port": port,
            "service": service,
            "status": "Open" if is_open else "Closed",
        }

        scan_results.append(result)

        if is_open:
            open_ports.append(result)

    # --------------------------------------------------
    # Security findings
    # --------------------------------------------------

    if not open_ports:

        security_findings.append(
            "No commonly monitored TCP services were detected "
            "as open on the local machine."
        )

    else:

        for item in open_ports:

            port = item["port"]
            service = item["service"]

            if port == 21:

                security_findings.append(
                    "FTP is open. FTP may transmit credentials "
                    "without encryption."
                )

                recommendations.append(
                    "Disable FTP if it is not required or use "
                    "a secure alternative such as SFTP."
                )

            elif port == 23:

                security_findings.append(
                    "Telnet is open. Telnet is an insecure "
                    "remote-access protocol."
                )

                recommendations.append(
                    "Disable Telnet and use SSH where remote "
                    "administration is required."
                )

            elif port == 445:

                security_findings.append(
                    "SMB is open on the local system."
                )

                recommendations.append(
                    "Ensure SMB is protected by firewall rules "
                    "and disable unnecessary file sharing."
                )

            elif port == 3389:

                security_findings.append(
                    "Remote Desktop (RDP) is open."
                )

                recommendations.append(
                    "Use strong authentication and restrict "
                    "RDP access when it is not required."
                )

            elif port == 5900:

                security_findings.append(
                    "VNC remote-access service appears to be open."
                )

                recommendations.append(
                    "Disable VNC when unnecessary and protect "
                    "remote access with strong authentication."
                )

            else:

                security_findings.append(
                    f"{service} service is listening on port {port}."
                )

                recommendations.append(
                    f"Verify that {service} on port {port} "
                    "is required and properly secured."
                )

    
    # --------------------------------------------------
    # Risk calculation
    # --------------------------------------------------

    # These results check localhost only.
    # An open local port does not prove network exposure.

    high_risk_ports = {21, 23, 3389, 5900}

    high_risk_count = sum(
        1
        for item in open_ports
        if item["port"] in high_risk_ports
    )

    if high_risk_count > 0:
        risk = "Medium"
        score = 70
        status = "Security Review Recommended"

    elif open_ports:
        risk = "Low"
        score = 85
        status = "Local Services Detected"

    else:
        risk = "Low"
        score = 95
        status = "No Common Local Services Detected"


    # --------------------------------------------------
    # Remove duplicate recommendations
    # --------------------------------------------------

    recommendations = list(dict.fromkeys(recommendations))

    if not recommendations:

        recommendations.append(
            "Continue using firewall protection and "
            "keep operating-system security updates enabled."
        )

    # --------------------------------------------------
    # Final result
    # --------------------------------------------------

    return {
        "success": True,
        "hostname": hostname,
        "local_ip": local_ip,
        "target": target,
        "status": status,
        "risk": risk,
        "score": score,
        "total_ports_checked": len(COMMON_PORTS),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "scan_results": scan_results,
        "findings": security_findings,
        "recommendations": recommendations,
    }