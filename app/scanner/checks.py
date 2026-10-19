from __future__ import annotations

import re
from collections.abc import Mapping

from app.scanner.models import CheckResult, Endpoint, Finding, Severity, Verification


def _finding(
    endpoint: Endpoint,
    name: str,
    title: str,
    desc: str,
    severity: Severity,
    verification: Verification,
    evidence: dict,
    remediation: str,
) -> Finding:
    return Finding(
        endpoint=endpoint.path,
        method=endpoint.method,
        check_name=name,
        title=title,
        description=desc,
        severity=severity,
        verification=verification,
        evidence=evidence,
        remediation=remediation,
    )


def header_check(endpoint: Endpoint, headers: Mapping[str, str], scheme: str) -> CheckResult:
    h = {k.lower(): v for k, v in headers.items()}
    result = CheckResult(tested=1)
    absent = [
        name for name in ("x-content-type-options", "content-security-policy") if not h.get(name)
    ]
    if scheme == "https" and not h.get("strict-transport-security"):
        absent.append("strict-transport-security")
    if absent:
        result.findings.append(
            _finding(
                endpoint,
                "security_headers",
                "Recommended security headers absent",
                "One or more defense-in-depth response headers were not observed. This is a hardening observation, not proof of exploitability.",
                Severity.low,
                Verification.potential,
                {"missing_headers": absent},
                "Set appropriate security headers for the API and validate them at the edge and application layers.",
            )
        )
    return result


def cors_check(
    endpoint: Endpoint, headers: Mapping[str, str], request_origin: str = "https://scanner.invalid"
) -> CheckResult:
    h = {k.lower(): v for k, v in headers.items()}
    result = CheckResult(tested=1)
    origin = h.get("access-control-allow-origin")
    creds = h.get("access-control-allow-credentials", "").lower() == "true"
    if origin == "*" and creds:
        result.findings.append(
            _finding(
                endpoint,
                "cors",
                "Contradictory permissive CORS response",
                "The response combines wildcard origin with credentials. Browsers reject this combination; evidence alone does not establish data exposure.",
                Severity.low,
                Verification.potential,
                {
                    "allow_origin": origin,
                    "allow_credentials": creds,
                    "request_origin": request_origin,
                },
                "Use an explicit trusted-origin allowlist and enable credentials only when required.",
            )
        )
    elif origin == request_origin and creds:
        result.findings.append(
            _finding(
                endpoint,
                "cors",
                "Untrusted origin reflected with credentials",
                "The response allowed the scanner's synthetic origin and credentials. Verify whether origin reflection is intentional and constrained.",
                Severity.medium,
                Verification.potential,
                {"allow_origin": origin, "allow_credentials": creds},
                "Validate origins against a strict allowlist; do not reflect arbitrary Origin values.",
            )
        )
    return result


def information_exposure_check(
    endpoint: Endpoint, status: int, headers: Mapping[str, str], body: str
) -> CheckResult:
    h = {k.lower(): v for k, v in headers.items()}
    result = CheckResult(tested=1)
    patterns = [
        r"Traceback \(most recent call last\)",
        r" at [\w.$]+\([^\n]*:\d+\)",
        r"(?i)exception in thread",
    ]
    matches = [p for p in patterns if re.search(p, body[:12000])]
    disclosed = {k: h[k] for k in ("server", "x-powered-by") if h.get(k)}
    if matches or (
        status >= 500 and any(k in body.lower() for k in ("traceback", "stack trace", "debugger"))
    ):
        result.findings.append(
            _finding(
                endpoint,
                "information_exposure",
                "Possible diagnostic details in response",
                "A response contained patterns associated with internal diagnostic output. No full response content is retained.",
                Severity.medium,
                Verification.potential,
                {
                    "status": status,
                    "matched_patterns": matches,
                    "body_truncated_for_analysis": len(body) > 12000,
                },
                "Return generic client errors and keep stack traces and debug pages out of externally visible responses.",
            )
        )
    elif disclosed:
        result.findings.append(
            _finding(
                endpoint,
                "information_exposure",
                "Technology identifying response headers",
                "Response headers disclose server or framework identifiers, which may aid fingerprinting.",
                Severity.informational,
                Verification.potential,
                {"disclosed_headers": disclosed},
                "Remove or minimize unnecessary server-identifying headers.",
            )
        )
    return result


def classify_auth(endpoint: Endpoint, status: int, body: str = "") -> CheckResult:
    result = CheckResult(tested=1)
    # Public is explicitly represented by an empty security requirement, including operation overrides.
    declared_public = endpoint.security == [] or endpoint.security is None
    if declared_public:
        result.notes.append(
            "Specification declares the operation public; anonymous response is not a finding."
        )
        return result
    if status in {401, 403}:
        result.notes.append(
            "Authentication/authorization gate appears enforced; status alone does not distinguish the two."
        )
    elif status in {404, 405, 422} or status >= 500:
        result.notes.append("Response is inconclusive for authentication enforcement.")
    else:
        result.findings.append(
            _finding(
                endpoint,
                "authentication",
                "Potential missing authentication enforcement",
                "The specification declares security requirements, but an unauthenticated safe request was not rejected with 401/403. This is a potential finding; compare an authorized test account before confirming.",
                Severity.medium,
                Verification.potential,
                {"status": status, "response_body_saved": False},
                "Enforce the declared authentication scheme and verify with authorized and unauthenticated test identities.",
            )
        )
    return result
