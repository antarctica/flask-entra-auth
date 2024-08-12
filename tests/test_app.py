from dataclasses import asdict

import pytest
from _pytest.fixtures import FixtureRequest
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from flask_entra_auth.exceptions import (
    EntraAuthInsufficientScopesError,
    EntraAuthInvalidAppError,
    EntraAuthInvalidAudienceError,
    EntraAuthInvalidExpirationError,
    EntraAuthInvalidIssuerError,
    EntraAuthInvalidSignatureError,
    EntraAuthInvalidSubjectError,
    EntraAuthInvalidTokenError,
    EntraAuthInvalidTokenVersionError,
    EntraAuthMissingClaimError,
    EntraAuthNotValidBeforeError,
    EntraAuthOidcError,
    EntraAuthRequestInvalidAuthHeaderError,
    EntraAuthRequestNoAuthHeaderError,
    EntraAuthSigningKeyError,
)
from flask_entra_auth.mocks.jwt import MockClaims


def _assert_entra_error(error: callable, response: TestResponse, **kwargs: str) -> None:
    error_ = error(**kwargs)
    assert response.json == asdict(error_.problem)
    assert response.status_code == error_.problem.status


class TestMainUnrestricted:
    """Test unrestricted route."""

    def test_ok(self, fx_app_client: FlaskClient):
        """Request is successful."""
        response = fx_app_client.get("/unrestricted")
        assert response.status_code == 200
        assert response.text == "Unrestricted route."


class TestMainRestricted:
    """Test basic restricted route."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_no_scopes: str):
        """Request is successful."""
        response = fx_app_client.get("/restricted", headers={"Authorization": f"Bearer {fx_jwt_no_scopes}"})
        assert response.status_code == 200
        assert response.text == "Restricted route."

    def test_no_auth(self, fx_app_client: FlaskClient):
        """Returns no auth header error."""
        response = fx_app_client.get("/restricted")
        _assert_entra_error(EntraAuthRequestNoAuthHeaderError, response)

    # parameterise
    @pytest.mark.parametrize("auth_value", ["Bearer", "<token>", "Invalid <token>"])
    def test_bad_auth(self, fx_app_client: FlaskClient, auth_value: str):
        """Returns invalid auth header error."""
        response = fx_app_client.get("/restricted", headers={"Authorization": auth_value})
        _assert_entra_error(EntraAuthRequestInvalidAuthHeaderError, response)

    @pytest.mark.parametrize("client", ["fx_app_client_no_oidc", "fx_app_client_bad_oidc", "fx_app_client_empty_oidc"])
    def test_bad_oidc(self, request: FixtureRequest, fx_jwt_kid: str, client: str):
        """Returns invalid signing key error when OIDC metadata not available."""
        client_ = request.getfixturevalue(client)
        response = client_.get("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthOidcError, response)

    @pytest.mark.parametrize("client", ["fx_app_client_no_jwks", "fx_app_client_bad_jwks", "fx_app_client_empty_jwks"])
    def test_bad_jwks(self, request: FixtureRequest, fx_jwt_kid: str, client: str):
        """Returns invalid signing key error when JWKS not available."""
        client_ = request.getfixturevalue(client)
        response = client_.get("/restricted", headers={"Authorization": f"Bearer {fx_jwt_kid}"})
        _assert_entra_error(EntraAuthSigningKeyError, response)

    def test_bad_jwt_no_kid(self, fx_app_client: FlaskClient, fx_jwt_empty: str):
        """Returns invalid signing key error when JWT missing 'kid' header parameter."""
        response = fx_app_client.get("/restricted", headers={"Authorization": f"Bearer {fx_jwt_empty}"})
        _assert_entra_error(EntraAuthSigningKeyError, response)

    def test_bad_jwt_decode(self, fx_app_client: FlaskClient):
        """Returns invalid token error when JWT can't be parsed."""
        response = fx_app_client.get("/restricted", headers={"Authorization": "Bearer Invalid"})
        _assert_entra_error(EntraAuthInvalidTokenError, response)

    def test_bad_jwt_kid(self, fx_app_client: FlaskClient, fx_jwt_bad_kid: str):
        """Returns invalid signing key error when JWT specifies a signing key not in JWKS."""
        response = fx_app_client.get("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_kid}"})
        _assert_entra_error(EntraAuthSigningKeyError, response)

    def test_bad_jwt_sig(self, fx_app_client: FlaskClient, fx_jwt_bad_sig: str):
        """Returns invalid signature error."""
        response = fx_app_client.get("/restricted", headers={"Authorization": f"Bearer {fx_jwt_bad_sig}"})
        _assert_entra_error(EntraAuthInvalidSignatureError, response)

    @pytest.mark.parametrize("claim", ["iss", "sub", "aud", "exp", "nbf", "azp", "ver"])
    def test_bad_jwt_no_claim(self, request: FixtureRequest, fx_app_client: FlaskClient, claim: str):
        """Returns missing required claim error."""
        token = request.getfixturevalue(f"fx_jwt_no_{claim}")
        response = fx_app_client.get("/restricted", headers={"Authorization": f"Bearer {token}"})
        _assert_entra_error(EntraAuthMissingClaimError, response, claim=claim)

    @pytest.mark.parametrize(
        ("claim", "exception"),
        [
            ("iss", EntraAuthInvalidIssuerError),
            ("aud", EntraAuthInvalidAudienceError),
            ("exp", EntraAuthInvalidExpirationError),
            ("nbf", EntraAuthNotValidBeforeError),
            ("sub", EntraAuthInvalidSubjectError),
            ("azp", EntraAuthInvalidAppError),
            ("ver", EntraAuthInvalidTokenVersionError),
        ],
    )
    def test_bad_jwt_claim(self, request: FixtureRequest, fx_app_client: FlaskClient, claim: str, exception: callable):
        """Returns relevant invalid claim error."""
        token = request.getfixturevalue(f"fx_jwt_bad_{claim}")

        response = fx_app_client.get("/restricted", headers={"Authorization": f"Bearer {token}"})
        _assert_entra_error(exception, response)


class TestMainRestrictedScope:
    """Test restricted route with required scopes."""

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_and(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is successful."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_and")
        url = f"/restricted/scopes/{resource}-and"

        response = fx_app_client.get(url, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.parametrize(
        ("resource", "op"),
        [("scps", "or"), ("roles", "or"), ("scopes", "or"), ("scps", "and"), ("roles", "and"), ("scopes", "and")],
    )
    def test_or(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str, op: str):
        """Request is successful (and should also pass)."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_{op}")
        url = f"/restricted/scopes/{resource}-or"

        response = fx_app_client.get(url, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_and_or(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is successful."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_and_or")
        url = f"/restricted/scopes/{resource}-and-or"

        response = fx_app_client.get(url, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_bad_and(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is unsuccessful (or is not and, special fixture for scopes to be disjoint)."""
        fixture = f"fx_jwt_{resource}_or"
        if resource == "scopes":
            fixture = f"{fixture}_bad"
        token = request.getfixturevalue(fixture)
        url = f"/restricted/scopes/{resource}-and"

        response = fx_app_client.get(url, headers={"Authorization": f"Bearer {token}"})
        _assert_entra_error(EntraAuthInsufficientScopesError, response)

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_bad_or(self, fx_app_client: FlaskClient, fx_jwt_no_scopes: str, resource: str):
        """Request is unsuccessful (either in or)."""
        url = f"/restricted/scopes/{resource}-or"

        response = fx_app_client.get(url, headers={"Authorization": f"Bearer {fx_jwt_no_scopes}"})
        _assert_entra_error(EntraAuthInsufficientScopesError, response)

    @pytest.mark.parametrize("resource", ["scps", "roles", "scopes"])
    def test_bad_and_or(self, request: FixtureRequest, fx_app_client: FlaskClient, resource: str):
        """Request is unsuccessful (or is a subset)."""
        token = request.getfixturevalue(f"fx_jwt_{resource}_or")
        url = f"/restricted/scopes/{resource}-and-or"

        response = fx_app_client.get(url, headers={"Authorization": f"Bearer {token}"})
        _assert_entra_error(EntraAuthInsufficientScopesError, response)


class TestMainRestrictedCurrentToken:
    """Test restricted route to get back current token."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_no_scopes: str, fx_claims: MockClaims):
        """Request is successful."""
        response = fx_app_client.get(
            "/restricted/current-token", headers={"Authorization": f"Bearer {fx_jwt_no_scopes}"}
        )
        assert response.status_code == 200
        assert "claims" in response.json
        assert response.json["claims"]["sub"] == fx_claims.sub


class TestMainIntrospectRfc7662:
    """Test token introspection as per RFC7662."""

    def test_ok(self, fx_app_client: FlaskClient, fx_jwt_no_scopes: str):
        """Request is successful."""
        response = fx_app_client.post("/introspect", data={"token": fx_jwt_no_scopes})
        assert response.status_code == 200

        data = response.json
        assert data["active"]

    def test_bad(self, fx_app_client: FlaskClient, fx_jwt_bad_exp: str):
        """Request is unsuccessful if token bad."""
        response = fx_app_client.post("/introspect", data={"token": fx_jwt_bad_exp})
        assert response.status_code == 401
