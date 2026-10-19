from __future__ import annotations

import json
from datetime import UTC, datetime

from app.core.config import settings
from app.db import SessionLocal
from app.models import Finding as FindingRow
from app.models import Scan
from app.scanner.engine import Scanner
from app.scanner.parser import discover_endpoints
from app.services.reports import build_report, json_report


def run_scan(scan_id: str) -> None:
    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != "Pending":
        db.close()
        return
    try:
        scan.status = "Running"
        scan.started_at = datetime.now(UTC)
        db.commit()
        doc = json.loads(scan.spec_json)
        endpoints = discover_endpoints(doc)
        result = Scanner(
            settings.target_allowlist,
            allow_private=settings.allow_private_targets,
            timeout=settings.scan_timeout_seconds,
            max_requests=settings.scan_max_requests,
            delay_seconds=settings.scan_delay_seconds,
        ).scan(scan.target, endpoints)
        db.refresh(scan)
        if scan.cancel_requested:
            scan.status = "Cancelled"
        else:
            for finding in result.findings:
                db.add(
                    FindingRow(
                        scan_id=scan.id,
                        endpoint=finding.endpoint,
                        method=finding.method,
                        check_name=finding.check_name,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value,
                        verification=finding.verification.value,
                        evidence_json=json.dumps(finding.evidence),
                        remediation=finding.remediation,
                        detected_at=finding.detected_at,
                    )
                )
            scan.endpoint_count = len(endpoints)
            scan.tested_checks = result.tested_checks
            scan.skipped_checks = result.skipped_checks
            finished = datetime.now(UTC)
            report = build_report(
                scan.id,
                scan.target,
                result.findings,
                endpoint_count=len(endpoints),
                tested_checks=result.tested_checks,
                skipped_checks=result.skipped_checks,
                started_at=scan.started_at,
                finished_at=finished,
                notes=result.notes,
            )
            scan.report_json = json_report(report)
            scan.status = "Completed"
        scan.finished_at = datetime.now(UTC)
        db.commit()
    except Exception as exc:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "Failed"
            scan.error_message = type(exc).__name__
            scan.finished_at = datetime.now(UTC)
            db.commit()
    finally:
        db.close()
