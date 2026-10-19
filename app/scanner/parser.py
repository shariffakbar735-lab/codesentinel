from __future__ import annotations

import json
from typing import Any

import yaml
from openapi_spec_validator import OpenAPIV30SpecValidator, OpenAPIV31SpecValidator
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError

from app.scanner.models import Endpoint

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class SpecError(ValueError):
    """Invalid, unsupported, or structurally unsafe OpenAPI input."""


def load_document(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw) if raw.lstrip().startswith(("{", "[")) else yaml.safe_load(raw)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SpecError(f"Specification syntax error: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError("Specification root must be an object")
    version = data.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise SpecError("Only OpenAPI 3.x specifications are supported")
    try:
        validator = (
            OpenAPIV31SpecValidator if version.startswith("3.1") else OpenAPIV30SpecValidator
        )
        validator(data).validate()
    except (OpenAPIValidationError, Exception) as exc:
        # Invalid documents are rejected, never quietly reduced to partial operation lists.
        raise SpecError(f"OpenAPI validation failed: {exc}") from exc
    return data


def discover_endpoints(document: dict[str, Any]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    root_security = document.get("security", [])
    if not isinstance(root_security, list):
        raise SpecError("Root security must be an array")
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise SpecError("paths must be an object")
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            raise SpecError(f"Path item {path!r} must be an object")
        path_parameters = path_item.get("parameters", [])
        if not isinstance(path_parameters, list):
            raise SpecError(f"Path parameters for {path!r} must be an array")
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise SpecError(f"Operation {method.upper()} {path} must be an object")
            op_parameters = operation.get("parameters", [])
            if not isinstance(op_parameters, list):
                raise SpecError(
                    f"Operation parameters for {method.upper()} {path} must be an array"
                )
            parameters = path_parameters + op_parameters
            body = operation.get("requestBody", {})
            content = body.get("content", {}) if isinstance(body, dict) else {}
            request_schema = next(
                (
                    v.get("schema")
                    for v in content.values()
                    if isinstance(v, dict) and v.get("schema")
                ),
                None,
            )
            # Operation-level [] explicitly overrides inherited security and means public.
            security = operation["security"] if "security" in operation else root_security
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    summary=operation.get("summary"),
                    parameters=parameters,
                    security=security,
                    request_schema=request_schema,
                    responses=operation.get("responses", {}),
                    eligible=method.lower() in {"get", "head", "options"},
                    skip_reason=None
                    if method.lower() in {"get", "head", "options"}
                    else "Active methods are not executed automatically",
                )
            )
    return endpoints


def parse_openapi(raw: str) -> tuple[dict[str, Any], list[Endpoint]]:
    document = load_document(raw)
    return document, discover_endpoints(document)
