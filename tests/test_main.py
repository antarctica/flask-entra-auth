from dataclasses import asdict

import pytest
from _pytest.fixtures import FixtureRequest
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from flask_azure.entra_exceptions import (
    EntraAuthInsufficentScopesError,
    EntraAuthInvalidAppError,
    EntraAuthInvalidAudienceError,
    EntraAuthInvalidExpirationError,
    EntraAuthInvalidIssuerError,
    EntraAuthInvalidSignatureError,
    EntraAuthInvalidSubjectError,
    EntraAuthInvalidTokenError,
    EntraAuthInvalidTokenVersionError,
    EntraAuthKeyError,
    EntraAuthMissingClaimError,
    EntraAuthNotValidBeforeError,
    EntraAuthOidcError,
    EntraAuthRequestInvalidAuthHeaderError,
    EntraAuthRequestNoAuthHeaderError,
)


def _assert_entra_error(error: callable, response: TestResponse, **kwargs: str) -> None:
    error_ = error(**kwargs)
    assert response.json == asdict(error_.problem)
    assert response.status_code == error_.problem.status


class TestMainUnrestricted:
    """Test unrestricted route."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        response = fx_app_client.post("/unrestricted")
        assert response.status_code == 200
        assert response.text == "Unrestricted route."


class TestMainRestricted:
    """Test basic restricted route."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt: str):
        """Request is successful."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt}"})
        assert response.status_code == 200
        assert response.text == "Restricted route."

    def test_no_auth(self, fx_app_client: FlaskClient):
        """Returns no auth header error."""
        response = fx_app_client.post("/restricted")
        _assert_entra_error(EntraAuthRequestNoAuthHeaderError, response)

    # parameterise
    @pytest.mark.parametrize("auth_value", ["Bearer", "<token>", "Invalid <token>"])
    def test_bad_auth(self, fx_app_client: FlaskClient, auth_value: str):
        """Returns invalid auth header error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": auth_value})
        _assert_entra_error(EntraAuthRequestInvalidAuthHeaderError, response)

    def test_bad_oidc_missing(self, fx_app_client_no_oidc: FlaskClient, fx_jwt_kid: str):
        """Returns invalid signing key error when JWKS not available."""
        response = fx_app_client_no_oidc.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthOidcError, response)

    def test_bad_oidc_invalid(self, fx_app_client_bad_oidc: FlaskClient, fx_jwt_kid: str):
        """Returns invalid signing key error when JWKS is invalid."""
        response = fx_app_client_bad_oidc.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthOidcError, response)

    def test_bad_oidc_empty(self, fx_app_client_empty_oidc: FlaskClient, fx_jwt_kid: str):
        """Returns invalid signing key error when JWKS is empty."""
        response = fx_app_client_empty_oidc.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthOidcError, response)

    def test_bad_jwks_missing(self, fx_app_client_no_jwks: FlaskClient, fx_jwt_kid: str):
        """Returns invalid signing key error when JWKS not available."""
        response = fx_app_client_no_jwks.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthKeyError, response)

    def test_bad_jwks_invalid(self, fx_app_client_bad_jwks: FlaskClient, fx_jwt_kid: str):
        """Returns invalid signing key error when JWKS is invalid."""
        response = fx_app_client_bad_jwks.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthKeyError, response)

    def test_bad_jwks_empty(self, fx_app_client_empty_jwks: FlaskClient, fx_jwt_kid: str):
        """Returns invalid signing key error when JWKS is empty."""
        response = fx_app_client_empty_jwks.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthKeyError, response)

    def test_bad_jwt_no_kid(self, fx_app_client: FlaskClient, fx_jwt_empty: str):
        """Returns invalid signing key error when JWT missing 'kid' header parameter."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_empty}"})
        _assert_entra_error(EntraAuthKeyError, response)

    def test_bad_jwt_decode(self, fx_app_client: FlaskClient):
        """Returns invalid token error when JWT can't be parsed."""
        response = fx_app_client.post("/restricted", headers={"Authorization": "Bearer Invalid"})
        _assert_entra_error(EntraAuthInvalidTokenError, response)

    def test_bad_jwt_kid(self, fx_app_client: FlaskClient, fx_jwt_bad_kid: str):
        """Returns invalid signing key error when JWT specifies a signing key not in JWKS."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_kid}"})
        _assert_entra_error(EntraAuthKeyError, response)

    def test_bad_jwt_sig(self, fx_app_client: FlaskClient, fx_jwt_bad_sig: str):
        """Returns invalid signature error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_sig}"})
        _assert_entra_error(EntraAuthInvalidSignatureError, response)

    def test_bad_jwt_no_iss(self, fx_app_client: FlaskClient, fx_jwt_kid: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="iss")

    def test_bad_jwt_no_sub(self, fx_app_client: FlaskClient, fx_jwt_iss: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_iss}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="sub")

    def test_bad_jwt_no_aud(self, fx_app_client: FlaskClient, fx_jwt_sub: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_sub}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="aud")

    def test_bad_jwt_no_exp(self, fx_app_client: FlaskClient, fx_jwt_aud: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_aud}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="exp")

    def test_bad_jwt_no_nbf(self, fx_app_client: FlaskClient, fx_jwt_exp: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_exp}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="nbf")

    def test_bad_jwt_no_azp(self, fx_app_client: FlaskClient, fx_jwt_nbf: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_nbf}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="azp")

    def test_bad_jwt_no_ver(self, fx_app_client: FlaskClient, fx_jwt_azp: str):
        """Returns missing required claim error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_azp}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim="ver")

    def test_bad_jwt_iss(self, fx_app_client: FlaskClient, fx_jwt_bad_iss: str):
        """Returns invalid issuer error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_iss}"})
        _assert_entra_error(EntraAuthInvalidIssuerError, response)

    def test_bad_jwt_aud(self, fx_app_client: FlaskClient, fx_jwt_bad_aud: str):
        """Returns invalid audience error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_aud}"})
        _assert_entra_error(EntraAuthInvalidAudienceError, response)

    def test_bad_jwt_exp(self, fx_app_client: FlaskClient, fx_jwt_bad_exp: str):
        """Returns expired error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_exp}"})
        _assert_entra_error(EntraAuthInvalidExpirationError, response)

    def test_bad_jwt_nbf(self, fx_app_client: FlaskClient, fx_jwt_bad_nbf: str):
        """Returns immature error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_nbf}"})
        _assert_entra_error(EntraAuthNotValidBeforeError, response)

    def test_bad_jwt_sub(self, fx_app_client_bad_subs: FlaskClient, fx_jwt: str):
        """Returns untrusted subject error."""
        response = fx_app_client_bad_subs.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt}"})
        _assert_entra_error(EntraAuthInvalidSubjectError, response)

    def test_bad_jwt_azp(self, fx_app_client_bad_apps: FlaskClient, fx_jwt: str):
        """Returns invalid claim error."""
        response = fx_app_client_bad_apps.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt}"})
        _assert_entra_error(EntraAuthInvalidAppError, response)

    def test_bad_jwt_ver(self, fx_app_client: FlaskClient, fx_jwt_bad_ver: str):
        """Returns invalid token version error."""
        response = fx_app_client.post("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_ver}"})
        _assert_entra_error(EntraAuthInvalidTokenVersionError, response)


class TestMainRestrictedScope:
    """Test restricted route with required scopes."""

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_and(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is successful."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_and")
        url = f"/restricted/scopes/{resource}-and"

        response = fx_app_client.post(url, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.parametrize(
        ("resource", "op"),
        [("scps", "or"), ("roles", "or"), ("scopes", "or"), ("scps", "and"), ("roles", "and"), ("scopes", "and")],
    )
    def test_or(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str, op: str):
        """Request is successful (and should also pass)."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_{op}")
        url = f"/restricted/scopes/{resource}-or"

        response = fx_app_client.post(url, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_and_or(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is successful."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_and_or")
        url = f"/restricted/scopes/{resource}-and-or"

        response = fx_app_client.post(url, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_bad_and(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is unsuccessful (or is not and, special fixture for scopes to be disjoint)."""
        fixture = f"fx_jwt_{resource}_or"
        if resource == "scopes":
            fixture = f"{fixture}_alt"
        token = request.getfixturevalue(fixture)
        url = f"/restricted/scopes/{resource}-and"

        response = fx_app_client.post(url, headers={"Authorization": f"Bearer {token}"})
        _assert_entra_error(EntraAuthInsufficentScopesError, response)

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_bad_or(self, fx_app_client: FlaskClient, fx_jwt: str, resource: str):
        """Request is unsuccessful (either in or)."""
        url = f"/restricted/scopes/{resource}-or"

        response = fx_app_client.post(url, headers={"Authorization": f"Bearer {fx_jwt}"})
        _assert_entra_error(EntraAuthInsufficentScopesError, response)

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_bad_and_or(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is unsuccessful (or is a subset)."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_or")
        url = f"/restricted/scopes/{resource}-and-or"

        response = fx_app_client.post(url, headers={"Authorization": f"Bearer {token}"})
        _assert_entra_error(EntraAuthInsufficentScopesError, response)


class TestMainRestrictedCurrentToken:
    """Test restricted route to get back current token."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt: str):
        """Request is successful."""
        response = fx_app_client.get("/restricted/current-token", headers={"Authorization": f"Bearer {fx_jwt}"})
        assert response.status_code == 200
        assert "claims" in response.json


class TestMainIntrospectRfc7662:
    """Test token introspection as per RFC7662."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt: str):
        """Request is successful."""
        response = fx_app_client.post("/introspect", data={"token": fx_jwt})
        assert response.status_code == 200

        data = response.json
        assert data["active"]
