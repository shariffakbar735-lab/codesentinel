import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Scan


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db():
        session = testing_session()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr("app.main.validate_target", lambda url, *args, **kwargs: url.rstrip("/"))
    with TestClient(app) as test_client:
        yield test_client, testing_session
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def register(client, email):
    return client.post("/auth/register", json={"email": email, "password": "Correct-Horse-99!"})


def test_registration_login_and_protected_me(client):
    c, _ = client
    res = register(c, "alice@example.com")
    assert res.status_code == 201
    token = c.post(
        "/auth/login", json={"email": "alice@example.com", "password": "Correct-Horse-99!"}
    ).json()["access_token"]
    assert c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert c.get("/auth/me", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    assert c.get("/auth/me").status_code == 401
    assert (
        c.post("/auth/login", json={"email": "alice@example.com", "password": "wrong"}).status_code
        == 401
    )


def test_owner_cannot_read_another_users_scan(client):
    c, sessions = client
    assert register(c, "alice@example.com").status_code == 201
    assert register(c, "bob@example.com").status_code == 201
    alice_token = c.post(
        "/auth/login", json={"email": "alice@example.com", "password": "Correct-Horse-99!"}
    ).json()["access_token"]
    bob_token = c.post(
        "/auth/login", json={"email": "bob@example.com", "password": "Correct-Horse-99!"}
    ).json()["access_token"]
    alice_id = c.get("/auth/me", headers={"Authorization": f"Bearer {alice_token}"}).json()["id"]
    with sessions() as db:
        scan = Scan(owner_id=alice_id, target="http://test-api", spec_json="{}", status="Completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    response = c.get(f"/scans/{scan_id}", headers={"Authorization": f"Bearer {bob_token}"})
    assert response.status_code == 404
    assert (
        c.get(f"/scans/{scan_id}", headers={"Authorization": f"Bearer {alice_token}"}).status_code
        == 200
    )


def test_invalid_spec_submission_rejected(client):
    c, _ = client
    register(c, "alice@example.com")
    token = c.post(
        "/auth/login", json={"email": "alice@example.com", "password": "Correct-Horse-99!"}
    ).json()["access_token"]
    response = c.post(
        "/scans",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": "http://test-api", "specification": "not a valid spec"},
    )
    assert response.status_code == 422


def test_openapi_uses_http_bearer_with_json_login_contract(client):
    c, _ = client
    spec = c.get("/openapi.json").json()

    scheme = spec["components"]["securitySchemes"]["HTTPBearer"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    assert "flows" not in scheme
    assert spec["paths"]["/auth/me"]["get"]["security"] == [{"HTTPBearer": []}]

    login = spec["paths"]["/auth/login"]["post"]
    assert "security" not in login
    login_body = login["requestBody"]["content"]["application/json"]["schema"]
    assert login_body["$ref"] == "#/components/schemas/LoginRequest"
    assert set(spec["components"]["schemas"]["LoginRequest"]["required"]) == {
        "email",
        "password",
    }
    token_response = login["responses"]["200"]["content"]["application/json"]["schema"]
    assert token_response["$ref"] == "#/components/schemas/TokenResponse"
    assert {"access_token", "token_type"} <= set(
        spec["components"]["schemas"]["TokenResponse"]["properties"]
    )
