from dataclasses import asdict

from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from flask_azure.entra_exceptions import EntraRequestNoAuthHeaderError


def _assert_entra_error(error: callable, response: TestResponse) -> None:
    assert response.status_code == 401
    assert response.json == asdict(error().problem)


class TestMainUnrestricted:
    """Test unrestricted route."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        response = fx_app_client.post("/unrestricted")
        assert response.status_code == 200
        assert response.text == "Unrestricted route."


class TestMainRestricted:
    """Test basic restricted route."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        token = "xxx"
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.text == "Restricted route."

    def test_no_auth(self, fx_app_client: FlaskClient):
        """Returns no auth header error."""
        response = fx_app_client.post("/restricted")
        _assert_entra_error(EntraRequestNoAuthHeaderError, response)


class TestMainRestrictedScope:
    """Test restricted route with required scope."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        token = "xxx"
        response = fx_app_client.post("/restricted/scope", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.text == "Restricted route with required scope."


class TestMainRestrictedCurrentToken:
    """Test restricted route to get back current token."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        token = "xxx"
        response = fx_app_client.get("/restricted/current-token", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert 'claims' in response.json


class TestMainIntrospectRfc7662:
    """Test token introspection as per RFC7662."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        token = "xxx"
        response = fx_app_client.post("/introspect", data={"token": token})
        assert response.status_code == 200

        data = response.json
        assert data['active']
