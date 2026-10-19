import pytest

from app.scanner.checks import classify_auth, cors_check, header_check
from app.scanner.models import Endpoint
from app.scanner.parser import SpecError, parse_openapi
from app.scanner.target_validation import TargetRejected, validate_target
from app.services.reports import html_report

SPEC = """openapi: 3.0.3
info: {title: demo, version: "1"}
paths:
  /users:
    parameters: [{name: x, in: query, schema: {type: string}}]
    get: {summary: list, responses: {"200": {description: ok}}}
  /public:
    get: {security: [], responses: {"200": {description: ok}}}
  /write:
    post: {responses: {"200": {description: ok}}}
security: [{BearerAuth: []}]
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
"""


def test_openapi_inheritance_override_and_non_operation_properties():
    _, eps = parse_openapi(SPEC)
    by_path = {e.path: e for e in eps}
    assert by_path["/users"].security == [{"BearerAuth": []}]
    assert by_path["/users"].parameters[0]["name"] == "x"
    assert by_path["/public"].security == []
    assert not by_path["/write"].eligible
    assert len(eps) == 3


def test_invalid_spec_rejected():
    with pytest.raises(SpecError):
        parse_openapi('{"openapi":"2.0","paths":{}}')
    with pytest.raises(SpecError):
        parse_openapi("paths: nope")


def test_public_endpoint_not_flagged_for_anonymous_200():
    endpoint = Endpoint(method="GET", path="/public", security=[])
    assert not classify_auth(endpoint, 200).findings


def test_protected_endpoint_200_is_potential_not_confirmed():
    endpoint = Endpoint(method="GET", path="/private", security=[{"BearerAuth": []}])
    finding = classify_auth(endpoint, 200).findings[0]
    assert finding.verification.value == "Potential"


def test_header_context_and_cors_evidence():
    endpoint = Endpoint(method="GET", path="/x")
    http_headers = header_check(endpoint, {}, "http").findings[0].evidence["missing_headers"]
    assert "strict-transport-security" not in http_headers
    cors = cors_check(
        endpoint, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    )
    assert cors.findings[0].verification.value == "Potential"


def test_target_allowlist_and_loopback_blocking():
    with pytest.raises(TargetRejected):
        validate_target("http://127.0.0.1:9000/", ["127.0.0.1"])
    with pytest.raises(TargetRejected):
        validate_target("https://example.org/", ["safe.test"])
    with pytest.raises(TargetRejected):
        validate_target("http://169.254.169.254/", ["169.254.169.254"], allow_private=True)
    assert validate_target("http://127.0.0.1:9000/", ["127.0.0.1"], allow_private=True).startswith(
        "http://"
    )


def test_report_html_escapes_untrusted_fields():
    report = {
        "scan_id": "<script>x</script>",
        "target": "https://example.test",
        "assessment_complete": False,
        "findings_by_severity": {
            "Low": [{"title": "<img src=x>", "endpoint": "/x", "verification": "Potential"}]
        },
    }
    rendered = html_report(report)
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered and "&lt;img" in rendered


def test_required_parameterized_paths_skip_without_sent_request(monkeypatch):
    from app.scanner import engine

    monkeypatch.setattr(engine, "validate_target", lambda url, *args, **kwargs: url)
    endpoint = Endpoint(
        method="GET",
        path="/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path", "required": True}],
    )
    result = engine.Scanner(["example.test"]).scan("https://example.test", [endpoint])
    assert result.skipped_checks == 1
    assert result.tested_checks == 0
    assert "required path input unavailable" in result.notes[0]
