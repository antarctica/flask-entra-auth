from dataclasses import asdict

import pytest
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from flask_azure.entra_exceptions import (
    EntraAuthJwksError,
    EntraAuthJwtMissingClaimError,
    EntraAuthRequestInvalidAuthHeaderError,
    EntraAuthRequestNoAuthHeaderError,
)


def _assert_entra_error(error: callable, response: TestResponse, **kwargs) -> None:
    error_ = error(**kwargs)
    assert response.status_code == error_.problem.status
    assert response.json == asdict(error_.problem)


class TestMainUnrestricted:
    """Test unrestricted route."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        response = fx_app_client.post("/unrestricted")
        assert response.status_code == 200
        assert response.text == "Unrestricted route."


class TestMainRestricted:
    """Test basic restricted route."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_ver: str):
        """Request is successful."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_ver}"})
        assert response.status_code == 200
        assert response.text == "Restricted route."

    def test_no_auth(self, fx_app_client: FlaskClient):
        """Returns no auth header error."""
        response = fx_app_client.post("/restricted")
        _assert_entra_error(EntraAuthRequestNoAuthHeaderError, response)

    # parameterise
    @pytest.mark.parametrize('auth_value', ['Bearer', '<token>', 'Invalid <token>'])
    def test_bad_auth(self, fx_app_client: FlaskClient, auth_value: str):
        """Returns invalid auth header error."""
        response = fx_app_client.post("/restricted", headers={'Authorization': auth_value})
        _assert_entra_error(EntraRequestInvalidAuthHeaderError, response)
    def test_bad_jwks(self, fx_app_client: FlaskClient, fx_jwt_empty: str):
        """Returns JWKS error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_empty}"})
        _assert_entra_error(EntraAuthJwksError, response)

    def test_bad_jwk_no_iss(self, fx_app_client: FlaskClient, fx_jwt_kid: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='iss')

    def test_bad_jwk_no_sub(self, fx_app_client: FlaskClient, fx_jwt_iss: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_iss}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='sub')

    def test_bad_jwk_no_aud(self, fx_app_client: FlaskClient, fx_jwt_sub: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_sub}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='aud')

    def test_bad_jwk_no_exp(self, fx_app_client: FlaskClient, fx_jwt_aud: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_aud}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='exp')

    def test_bad_jwk_no_nbf(self, fx_app_client: FlaskClient, fx_jwt_exp: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_exp}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='nbf')

    def test_bad_jwk_no_azp(self, fx_app_client: FlaskClient, fx_jwt_nbf: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_nbf}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='azp')

    def test_bad_jwk_no_ver(self, fx_app_client: FlaskClient, fx_jwt_azp: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_azp}"})
        _assert_entra_error(EntraAuthJwtMissingClaimError, response, claim='ver')


class TestMainRestrictedScope:
    """Test restricted route with required scope."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_ver: str):
        """Request is successful."""
        response = fx_app_client.post("/restricted/scope", headers={"Authorization": f"Bearer {fx_jwt_ver}"})
        assert response.status_code == 200
        assert response.text == "Restricted route with required scope."


class TestMainRestrictedCurrentToken:
    """Test restricted route to get back current token."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_ver: str):
        """Request is successful."""
        response = fx_app_client.get("/restricted/current-token", headers={"Authorization": f"Bearer {fx_jwt_ver}"})
        assert response.status_code == 200
        assert 'claims' in response.json


class TestMainIntrospectRfc7662:
    """Test token introspection as per RFC7662."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_ver: str):
        """Request is successful."""
        response = fx_app_client.post("/introspect", data={"token": fx_jwt_ver})
        assert response.status_code == 200

        data = response.json
        assert data['active']
