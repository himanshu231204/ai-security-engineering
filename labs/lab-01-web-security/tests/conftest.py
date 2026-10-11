import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def vuln():
    return TestClient(create_app(secure=False))


@pytest.fixture()
def sec():
    return TestClient(create_app(secure=True))


def token(client, user, pw):
    r = client.post("/login", json={"username": user, "password": pw})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
