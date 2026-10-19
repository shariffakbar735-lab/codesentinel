from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from app.scanner.checks import classify_auth, cors_check, header_check, information_exposure_check
from app.scanner.models import CheckResult, Endpoint, Finding
from app.scanner.target_validation import TargetRejected, validate_redirect, validate_target


@dataclass
class ScanOutput:
    findings: list[Finding]
    tested_checks: int
    skipped_checks: int
    notes: list[str]


class Scanner:
    def __init__(
        self,
        allowlist: list[str],
        *,
        allow_private: bool = False,
        timeout: float = 5.0,
        max_requests: int = 50,
        delay_seconds: float = 0.1,
    ):
        self.allowlist = allowlist
        self.allow_private = allow_private
        self.timeout = min(max(timeout, 0.5), 15.0)
        self.max_requests = min(max_requests, 200)
        self.delay_seconds = max(delay_seconds, 0.0)

    def scan(self, base_url: str, endpoints: list[Endpoint]) -> ScanOutput:
        base = validate_target(base_url, self.allowlist, allow_private=self.allow_private)
        findings: list[Finding] = []
        notes: list[str] = []
        tested = skipped = requests_sent = 0
        with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
            for endpoint in endpoints:
                if not endpoint.eligible:
                    skipped += 1
                    notes.append(
                        f"{endpoint.method} {endpoint.path}: {endpoint.skip_reason or 'not eligible'}"
                    )
                    continue
                if any(
                    p.get("in") == "path" and p.get("required", True) for p in endpoint.parameters
                ):
                    skipped += 1
                    notes.append(
                        f"{endpoint.method} {endpoint.path}: required path input unavailable; not tested."
                    )
                    continue
                if requests_sent >= self.max_requests:
                    skipped += 1
                    notes.append("Request limit reached; remaining operations skipped.")
                    continue
                url = base.rstrip("/") + "/" + endpoint.path.lstrip("/")
                try:
                    validate_target(url, self.allowlist, allow_private=self.allow_private)
                    if requests_sent and self.delay_seconds:
                        time.sleep(self.delay_seconds)
                    requests_sent += 1
                    with client.stream(
                        endpoint.method, url, headers={"Origin": "https://scanner.invalid"}
                    ) as response:
                        if response.is_redirect:
                            location = response.headers.get("location", "")
                            try:
                                validate_redirect(
                                    url, location, self.allowlist, allow_private=self.allow_private
                                )
                                notes.append(
                                    f"{endpoint.method} {endpoint.path}: redirect not followed (safe by default)."
                                )
                            except TargetRejected as exc:
                                notes.append(
                                    f"{endpoint.method} {endpoint.path}: blocked redirect destination ({exc})."
                                )
                            skipped += 1
                            continue
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            room = 12000 - len(body)
                            if room <= 0:
                                break
                            body.extend(chunk[:room])
                            if len(chunk) > room:
                                break
                        body_text = bytes(body).decode(
                            response.encoding or "utf-8", errors="replace"
                        )
                        results: list[CheckResult] = [
                            header_check(endpoint, response.headers, response.url.scheme),
                            cors_check(endpoint, response.headers),
                            information_exposure_check(
                                endpoint, response.status_code, response.headers, body_text
                            ),
                            classify_auth(endpoint, response.status_code),
                        ]
                    for result in results:
                        findings.extend(result.findings)
                        tested += result.tested
                        notes.extend(result.notes)
                except (httpx.HTTPError, TargetRejected) as exc:
                    skipped += 1
                    notes.append(
                        f"{endpoint.method} {endpoint.path}: request inconclusive ({type(exc).__name__})."
                    )
        return ScanOutput(findings, tested, skipped, notes)
