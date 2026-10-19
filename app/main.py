from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis import Redis
from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import get_db
from app.models import Finding, Scan, User
from app.scanner.parser import SpecError, load_document
from app.scanner.target_validation import TargetRejected, validate_target
from app.schemas import LoginRequest, ScanCreate, ScanView, TokenResponse, UserCreate, UserView
from app.security import create_access_token, decode_access_token, hash_password, verify_password

app = FastAPI(
    title="CodeSentinel", version="0.1.0", description="Safe, evidence-based API security scanner"
)
bearer_scheme = HTTPBearer(auto_error=False)


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials if credentials else None
    user_id = decode_access_token(token) if token else None
    user = db.get(User, user_id) if user_id else None
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def owned_scan(scan_id: str, user: User, db: Session) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.owner_id == user.id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/auth/register", response_model=UserView, status_code=201)
def register(data: UserCreate, db: Session = Depends(get_db)):
    email = str(data.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email is already registered")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == str(data.email).lower()))
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(access_token=create_access_token(user.id))


@app.get("/auth/me", response_model=UserView)
def me(user: User = Depends(current_user)):
    return user


@app.post("/auth/logout", status_code=204)
def logout(user: User = Depends(current_user)):
    # Stateless access tokens expire naturally; clients must discard the token.
    return Response(status_code=204)


@app.post("/scans", response_model=ScanView, status_code=202)
def create_scan(
    data: ScanCreate, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    try:
        target = validate_target(
            data.target, settings.target_allowlist, allow_private=settings.allow_private_targets
        )
        document = load_document(data.specification)
    except (TargetRejected, SpecError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = Scan(owner_id=user.id, target=target, spec_json=json.dumps(document), status="Pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        queue = Queue(
            "codesentinel", connection=Redis.from_url(settings.redis_url), default_timeout=900
        )
        queue.enqueue("app.worker.run_scan", scan.id, job_timeout=900, result_ttl=0)
    except Exception as exc:
        scan.status = "Failed"
        scan.error_message = "QueueUnavailable"
        scan.finished_at = datetime.now(UTC)
        db.commit()
        raise HTTPException(status_code=503, detail="Background scan queue is unavailable") from exc
    return scan


@app.get("/scans", response_model=list[ScanView])
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.owner_id == user.id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    )


@app.get("/scans/{scan_id}", response_model=ScanView)
def get_scan(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return owned_scan(scan_id, user, db)


@app.post("/scans/{scan_id}/cancel", response_model=ScanView)
def cancel_scan(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = owned_scan(scan_id, user, db)
    if scan.status == "Pending":
        scan.status = "Cancelled"
        scan.finished_at = datetime.now(UTC)
    elif scan.status == "Running":
        scan.cancel_requested = True
    else:
        raise HTTPException(
            status_code=409, detail="Only pending or running scans can be cancelled"
        )
    db.commit()
    db.refresh(scan)
    return scan


@app.get("/scans/{scan_id}/findings")
def list_findings(
    scan_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    owned_scan(scan_id, user, db)
    rows = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.detected_at)
        .limit(limit)
        .offset(offset)
    )
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "endpoint": f.endpoint,
            "method": f.method,
            "check_name": f.check_name,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "verification": f.verification,
            "evidence": json.loads(f.evidence_json),
            "remediation": f.remediation,
            "detected_at": f.detected_at,
        }
        for f in rows
    ]


@app.get("/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|html)$"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    scan = owned_scan(scan_id, user, db)
    if not scan.report_json:
        raise HTTPException(status_code=409, detail="Report is not available until scan finishes")
    if format == "json":
        return Response(scan.report_json, media_type="application/json")
    from app.services.reports import html_report

    return Response(
        html_report(json.loads(scan.report_json)), media_type="text/html; charset=utf-8"
    )


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = db.scalar(
        select(Finding).join(Scan).where(Finding.id == finding_id, Scan.owner_id == user.id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "endpoint": row.endpoint,
        "method": row.method,
        "check_name": row.check_name,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "verification": row.verification,
        "evidence": json.loads(row.evidence_json),
        "remediation": row.remediation,
        "detected_at": row.detected_at,
    }


@app.get("/health/live")
def live():
    return {"status": "alive"}


@app.get("/health/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        Redis.from_url(settings.redis_url).ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Service dependencies are not ready") from exc
    return {"status": "ready"}
