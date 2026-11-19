
"""
CyberShield AI - Password Security Analyzer

Features:
1. Identity Shield: name, initials, and birthdate checks.
2. Entropy and illustrative crack-time estimate.
3. Dictionary, keyboard, sequential, and substitution checks.
4. Long passphrase bonus.
5. Explanations, findings, and recommendations.
6. Four-word passphrase recommendation.

Privacy: Never print, log, or store the submitted password.
"""

import math
import re
import secrets
import string


# --------------------------------------------------
# COMMON PASSWORDS AND WEAK WORDS
# --------------------------------------------------

COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "password",
    "password123",
    "passw0rd",
    "p@ssw0rd",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "letmein",
    "monkey",
    "dragon",
    "abc123",
    "iloveyou",
    "111111",
    "000000",
    "123123",
    "654321",
    "india123",
    "computer",
    "changeme",
}

WEAK_TERMS = {
    "password",
    "admin",
    "welcome",
    "letmein",
    "iloveyou",
    "qwerty",
    "abc123",
    "changeme",
    "monkey",
    "dragon",
}

KEYBOARD_SEQUENCES = (
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "qwert",
    "asdf",
    "zxcv",
    "12345",
    "23456",
    "34567",
    "45678",
    "56789",
    "98765",
    "87654",
    "76543",
    "65432",
    "54321",
    "abcdef",
    "fedcba",
)


# --------------------------------------------------
# PASSphrase WORD LIST
# --------------------------------------------------

# A small demonstration word list.
# A larger vetted word list would be needed for production use.

PASSPHRASE_WORDS = (
    "amber",
    "apricot",
    "badger",
    "bamboo",
    "beacon",
    "bluejay",
    "cactus",
    "candle",
    "cedar",
    "comet",
    "coral",
    "daisy",
    "falcon",
    "fern",
    "forest",
    "galaxy",
    "garden",
    "glacier",
    "harbor",
    "hazel",
    "island",
    "jasmine",
    "lantern",
    "maple",
    "meadow",
    "meteor",
    "nectar",
    "ocean",
    "olive",
    "orchid",
    "otter",
    "pebble",
    "pepper",
    "pigeon",
    "planet",
    "plum",
    "puzzle",
    "raven",
    "river",
    "saffron",
    "silver",
    "sprout",
    "sunrise",
    "thunder",
    "tulip",
    "velvet",
    "willow",
    "zephyr",
)


# Exact warning requested for the Identity Shield.

PERSONAL_WARNING = (
    "Critical Risk: Do not use your own name, initials, or birthdate. "
    "Hackers can find this on your social media!"
)


# --------------------------------------------------
# TEXT NORMALIZATION
# --------------------------------------------------

def _normalize(value):
    """
    Convert text to lowercase and remove separators.

    Example:
        Amber-123 -> amber123
    """
    return re.sub(
        r"[^a-z0-9]",
        "",
        str(value or "").lower()
    )


# --------------------------------------------------
# IDENTITY SHIELD
# --------------------------------------------------

def extract_personal_markers(
    first_name="",
    last_name="",
    birth_date=""
):
    """
    Create possible personal markers from supplied details.

    Birth date format: DDMMYYYY.
    """

    first = _normalize(first_name)
    last = _normalize(last_name)

    markers = set()

    # Full names.
    if len(first) >= 3:
        markers.add(first)

    if len(last) >= 3:
        markers.add(last)

    # First name + last name and reversed combination.
    if len(first) >= 2 and len(last) >= 2:
        markers.add(first + last)
        markers.add(last + first)

    # Initials and common name combinations.
    if first and last:
        markers.add(first[0] + last[0])

        if len(last) >= 2:
            markers.add(first[0] + last)

        if len(first) >= 2:
            markers.add(first + last[0])

    # Birth date patterns.
    digits = re.sub(
        r"\D",
        "",
        str(birth_date or "")
    )

    if len(digits) == 8:
        day = digits[:2]
        month = digits[2:4]
        year = digits[4:8]

        markers.update({
            digits,
            day + month,
            month + day,
            year,
            year + month + day,
            year + day + month,
            day + year,
            month + year,
        })

    elif len(digits) == 4:
        # Supports a year-only value if supplied.
        markers.add(digits)

    return {
        marker
        for marker in markers
        if len(marker) >= 2
    }


def find_personal_match(
    password,
    first_name="",
    last_name="",
    birth_date=""
):
    """
    Return personal markers found in the normalized password.

    Short initials can occasionally cause false positives.
    This check only considers the personal information supplied.
    """

    normalized_password = _normalize(password)

    markers = extract_personal_markers(
        first_name,
        last_name,
        birth_date
    )

    if not normalized_password or not markers:
        return []

    return sorted(
        marker
        for marker in markers
        if marker in normalized_password
    )


# --------------------------------------------------
# SEQUENTIAL AND REPEATED CHARACTERS
# --------------------------------------------------

def has_sequential_characters(password):
    """
    Detect common keyboard and sequential patterns,
    including reversed patterns.
    """

    value = str(password or "").lower()

    sequences = (
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    )

    for sequence in sequences:
        for index in range(len(sequence) - 2):
            pattern = sequence[index:index + 3]

            if pattern in value:
                return True

            if pattern[::-1] in value:
                return True

    return any(
        pattern in value
        for pattern in KEYBOARD_SEQUENCES
    )


def has_repeated_characters(password):
    """Detect three or more consecutive repeated characters."""

    return bool(
        re.search(
            r"(.)\1\1",
            str(password or ""),
            re.IGNORECASE
        )
    )


# --------------------------------------------------
# ENTROPY ESTIMATION
# --------------------------------------------------

def calculate_entropy(password):
    """
    Estimate theoretical entropy using character-pool size.

    This is an estimate, not a guarantee of real-world security.
    """

    password = str(password or "")

    if not password:
        return 0.0

    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26

    if re.search(r"[A-Z]", password):
        charset_size += 26

    if re.search(r"[0-9]", password):
        charset_size += 10

    if re.search(r"[^a-zA-Z0-9\s]", password):
        charset_size += 32

    if re.search(r"\s", password):
        charset_size += 1

    if charset_size == 0:
        return 0.0

    entropy = len(password) * math.log2(charset_size)

    return round(entropy, 1)


# --------------------------------------------------
# CRACK-TIME ESTIMATE
# --------------------------------------------------

def estimate_crack_time(
    entropy_bits,
    guesses_per_second=1_000_000_000_000
):
    """
    Give an illustrative average brute-force estimate.

    Assumes half the search space must be tested and a fixed
    hypothetical guessing rate. Real attack speeds vary widely.
    """

    if entropy_bits <= 0:
        return "Instant"

    # Limit the exponent to prevent numeric overflow.
    seconds = (
        2 ** min(entropy_bits, 1023)
    ) / (2 * guesses_per_second)

    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365.25 * day

    if seconds < minute:
        return "Instant"

    if seconds < hour:
        return "Minutes"

    if seconds < day:
        return "Hours"

    if seconds < year:
        return "Days"

    years = seconds / year

    if years < 100:
        return "Years"

    return "Centuries"


# --------------------------------------------------
# DICTIONARY AND SUBSTITUTION CHECKS
# --------------------------------------------------

def check_dictionary_and_patterns(password):
    """
    Detect common passwords, weak words, predictable
    substitutions, and keyboard sequences.
    """

    normalized = _normalize(password)
    lower = str(password or "").lower()

    # Reverse common substitutions:
    # @ -> a, 3 -> e, 0 -> o, 1 -> i, etc.
    substitution_table = str.maketrans({
        "@": "a",
        "4": "a",
        "3": "e",
        "0": "o",
        "1": "i",
        "!": "i",
        "$": "s",
        "5": "s",
        "7": "t",
    })

    normalized_substitutions = _normalize(
        lower.translate(substitution_table)
    )

    normalized_common_passwords = {
        _normalize(item)
        for item in COMMON_PASSWORDS
    }

    common_password = (
        normalized in normalized_common_passwords
        or normalized_substitutions
        in normalized_common_passwords
    )

    weak_term = next(
        (
            term
            for term in sorted(
                WEAK_TERMS,
                key=len,
                reverse=True
            )
            if _normalize(term) in normalized_substitutions
        ),
        None
    )

    sequential = has_sequential_characters(lower)

    return common_password, weak_term, sequential


# --------------------------------------------------
# PASSPHRASE DETECTION
# --------------------------------------------------

def _is_passphrase_like(password):
    """
    Recognize a long passphrase containing multiple words
    separated by spaces or hyphens.
    """

    value = str(password or "").strip()

    words = [
        word
        for word in re.split(r"[\s-]+", value)
        if word
    ]

    return (
        len(value) > 14
        and len(words) >= 3
        and all(
            re.fullmatch(r"[A-Za-z]+", word)
            for word in words
        )
    )


# --------------------------------------------------
# SMART PASSPHRASE GENERATOR
# --------------------------------------------------

def generate_passphrase(
    first_name="",
    last_name="",
    birth_date="",
    word_count=4
):
    """
    Generate four unrelated words joined with hyphens.

    Reject generated phrases containing markers derived
    from the supplied personal details.
    """

    word_count = max(
        4,
        min(int(word_count), 6)
    )

    for _ in range(200):
        words = [
            secrets.choice(PASSPHRASE_WORDS)
            for _ in range(word_count)
        ]

        phrase = "-".join(words)

        if not find_personal_match(
            phrase,
            first_name,
            last_name,
            birth_date
        ):
            return phrase

    # Fallback after repeated rejected combinations.
    # This is extremely unlikely with the demonstration list.
    return "-".join(
        secrets.choice(PASSPHRASE_WORDS)
        for _ in range(word_count)
    )


# --------------------------------------------------
# MAIN PASSWORD ANALYZER
# --------------------------------------------------

def analyze_password(
    password,
    first_name="",
    last_name="",
    birth_date=""
):
    """
    Analyze password security without storing the password.

    Keeps the result keys used by the existing
    password_result.html template and adds new feature data.
    """

    password = str(password or "")

    length = len(password)

    has_lowercase = bool(
        re.search(r"[a-z]", password)
    )

    has_uppercase = bool(
        re.search(r"[A-Z]", password)
    )

    has_number = bool(
        re.search(r"[0-9]", password)
    )

    has_special = bool(
        re.search(r"[^a-zA-Z0-9\s]", password)
    )

    (
        common_password,
        weak_term,
        sequential
    ) = check_dictionary_and_patterns(password)

    repeated = has_repeated_characters(password)

    entropy = calculate_entropy(password)

    crack_time = estimate_crack_time(entropy)

    personal_matches = find_personal_match(
        password,
        first_name,
        last_name,
        birth_date
    )

    passphrase_like = _is_passphrase_like(password)

    findings = []
    recommendations = []
    explanations = []

    score = 0

    # --------------------------------------------------
    # IDENTITY SHIELD OVERRIDE
    # --------------------------------------------------

    if personal_matches:

        score = 0

        strength = "Weak"
        risk = "High"
        status = "Critical Risk"

        findings.append(PERSONAL_WARNING)

        explanations.append(
            "Personal information matched the password. "
            "The security score has been overridden to zero."
        )

        recommendations.append(
            "Choose a password that does not contain your "
            "name, initials, or birthdate."
        )

    else:

        # ----------------------------------------------
        # LENGTH SCORING
        # ----------------------------------------------

        if length >= 16:

            score += 45  # Increased from 35 to give length a higher baseline

            explanations.append(
                "Length: 16 or more characters earns "
                "the highest length credit."
            )

        elif length >= 12:

            score += 38  # Increased from 28 so 12-char passwords clear the weak threshold easily

            explanations.append(
                "Length: 12–15 characters provides "
                "useful password length."
            )

        elif length >= 8:

            score += 25  # Increased from 18 to better support standard requirements

            explanations.append(
                "Length: 8–11 characters is a basic "
                "minimum; a longer password is preferable."
            )

        else:

            score += length * 2

            findings.append(
                "The password is shorter than 8 characters."
            )

            recommendations.append(
                "Use at least 12 characters; longer is generally better."
            )

        # ----------------------------------------------
        # CHARACTER DIVERSITY
        # ----------------------------------------------

        variety = sum((
            has_lowercase,
            has_uppercase,
            has_number,
            has_special
        ))

        variety_points = {
            1: 15,  # Increased from 4 so a single character pool isn't overly penalized if long
            2: 22,  # Increased from 10
            3: 28,  # Increased from 17
            4: 33,  # Increased from 22
        }

        score += variety_points.get(variety, 0)


        if variety < 3 and not passphrase_like:

            findings.append(
                "The password uses a limited mix "
                "of character types."
            )

            recommendations.append(
                "Add character variety, or use a long "
                "passphrase made from unrelated words."
            )

        if not has_lowercase:

            recommendations.append(
                "Consider adding lowercase letters."
            )

        if not has_uppercase and not passphrase_like:

            recommendations.append(
                "Consider adding uppercase letters if useful."
            )

        if not has_number and not passphrase_like:

            recommendations.append(
                "Consider adding numbers if useful."
            )

        if not has_special and not passphrase_like:

            recommendations.append(
                "A special character may help, but length "
                "and unpredictability matter more."
            )

        # ----------------------------------------------
        # COMMON PASSWORD AND WEAK WORD CHECK
        # ----------------------------------------------

        if common_password:

            score -= 35

            findings.append(
                "This matches a known common password "
                "or predictable variation."
            )

            recommendations.append(
                "Avoid common passwords and predictable variations."
            )

        elif weak_term:

            score -= 20

            findings.append(
                "A common word or predictable substitution "
                "pattern was detected."
            )

            recommendations.append(
                "Avoid predictable substitutions such as "
                "@ for a, 3 for e, or 0 for o."
            )

        # ----------------------------------------------
        # SEQUENTIAL PATTERN CHECK
        # ----------------------------------------------

        if sequential:

            score -= 15

            findings.append(
                "A keyboard or sequential pattern was detected."
            )

            recommendations.append(
                "Avoid sequences such as 12345, abcdef, or qwerty."
            )

        # ----------------------------------------------
        # REPEATED CHARACTER CHECK
        # ----------------------------------------------

        if repeated:

            score -= 10

            findings.append(
                "Three or more consecutive repeated "
                "characters were detected."
            )

            recommendations.append(
                "Avoid repeated characters such as aaa or 111."
            )

        # ----------------------------------------------
        # LONG PASSPHRASE BONUS
        # ----------------------------------------------

        if passphrase_like:

            score = max(score, 80)

            explanations.append(
                "Passphrase bonus: the password is a long "
                "multiword phrase. Memorable passphrases can "
                "be strong without requiring symbols."
            )

        # ----------------------------------------------
        # FINAL SCORE
        # ----------------------------------------------

        score = max(
            0,
            min(100, int(round(score)))
        )

        if score >= 80:

            strength = "Strong"
            risk = "Low"
            status = "Strong Password"

        elif score >= 55:

            strength = "Medium"
            risk = "Medium"
            status = "Needs Improvement"

        else:

            strength = "Weak"
            risk = "High"
            status = "Weak Password"

        # ----------------------------------------------
        # INTELLIGENT EXPLANATIONS
        # ----------------------------------------------

        if length >= 12:

            explanations.append(
                "Password length contributes positively "
                "to the rating."
            )

        if variety >= 3:

            explanations.append(
                "Several character types increase the "
                "theoretical search space."
            )

        if common_password or weak_term:

            explanations.append(
                "Dictionary-based patterns reduce practical "
                "strength even when symbols are added."
            )

        if sequential:

            explanations.append(
                "Predictable sequences make passwords "
                "easier to guess."
            )

        if repeated:

            explanations.append(
                "Repeated characters reduce unpredictability."
            )

        if not findings:

            findings.append(
                "No common weak pattern was detected "
                "by the checks performed."
            )

        if not recommendations:

            recommendations.append(
                "Use a unique password for every account "
                "and store it in a reputable password manager."
            )

    # --------------------------------------------------
    # RESISTANCE LABEL
    # --------------------------------------------------

    if (
        entropy >= 60
        and not personal_matches
        and not common_password
        and not weak_term
        and not sequential
        and not repeated
    ):

        resistance = "High"

    elif entropy >= 35 and not personal_matches:

        resistance = "Moderate"

    else:

        resistance = "Low"

    # --------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------

    suggested_passphrase = generate_passphrase(
        first_name,
        last_name,
        birth_date,
        word_count=4
    )

    return {
        # Existing template fields
        "success": True,
        "status": status,
        "risk": risk,
        "score": score,
        "strength": strength,
        "length": length,
        "has_lowercase": has_lowercase,
        "has_uppercase": has_uppercase,
        "has_number": has_number,
        "has_special": has_special,
        "common_password": common_password,
        "sequential": sequential,
        "repeated": repeated,
        "entropy": entropy,
        "resistance": resistance,
        "findings": findings,
        "recommendations": recommendations,

        # New feature fields
        "estimated_crack_time": (
            "Not estimated because personal information was detected"
            if personal_matches
            else crack_time
        ),
        "personal_match": bool(personal_matches),
        "personal_match_types": (
            ["Personal information pattern detected"]
            if personal_matches
            else []
        ),
        "passphrase_like": passphrase_like,
        "explanation": explanations,
        "weak_dictionary_term_detected": bool(weak_term),
        "suggested_passphrase": suggested_passphrase,
    }
