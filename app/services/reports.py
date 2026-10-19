from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import Any

from app.scanner.models import Finding


def build_report(
    scan_id: str,
    target: str,
    findings: list[Finding],
    *,
    endpoint_count: int,
    tested_checks: int,
    skipped_checks: int,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        data = finding.model_dump(mode="json")
        grouped.setdefault(finding.severity.value, []).append(data)
    return {
        "scan_id": scan_id,
        "target": target,
        "started_at": (started_at or datetime.now(UTC)).isoformat(),
        "finished_at": (finished_at or datetime.now(UTC)).isoformat(),
        "endpoint_count": endpoint_count,
        "tested_checks": tested_checks,
        "skipped_checks": skipped_checks,
        "findings_by_severity": grouped,
        "findings_count": len(findings),
        "notes": notes or [],
        "assessment_complete": skipped_checks == 0,
    }


def json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def html_report(report: dict[str, Any]) -> str:
    # All dynamic strings are escaped; never embed target response bodies.
    title = html.escape(str(report.get("scan_id", "Scan report")))
    target = html.escape(str(report.get("target", "")))
    finding_rows = []
    for severity, findings in report.get("findings_by_severity", {}).items():
        for f in findings:
            finding_rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    html.escape(str(severity)),
                    html.escape(str(f.get("title", ""))),
                    html.escape(str(f.get("endpoint", ""))),
                    html.escape(str(f.get("verification", ""))),
                )
            )
    completeness = (
        "Complete" if report.get("assessment_complete") else "Incomplete — skipped checks exist"
    )
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>CodeSentinel report</title>"
        "<h1>CodeSentinel scan report</h1><p>Scan: " + title + "</p><p>Target: " + target + "</p>"
        "<p>Assessment: " + html.escape(completeness) + "</p><table><thead><tr><th>Severity</th>"
        "<th>Finding</th><th>Endpoint</th><th>Status</th></tr></thead><tbody>"
        + "".join(finding_rows)
        + "</tbody></table></html>"
    )
