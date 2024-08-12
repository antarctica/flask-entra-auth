import pytest
from flask import Flask
from flask.testing import FlaskClient
from joserfc.jwk import KeySet
from pytest_httpserver import HTTPServer

from flask_entra_auth.mocks.jwks import MockJwks
from flask_entra_auth.mocks.jwt import MockClaims, MockJwtClient
from tests.app import create_app


@pytest.fixture()
def fx_client_id_self() -> str:
    """Client ID for app containing protected resources."""
    return "test_app_1"


@pytest.fixture()
def fx_claims(fx_client_id_self: str) -> MockClaims:
    """MockClaims."""
    return MockClaims(self_app_id=fx_client_id_self)


@pytest.fixture()
def fx_jwks() -> MockJwks:
    """JSON Web Key Set."""
    return MockJwks()


@pytest.fixture()
def fx_jwt(fx_jwks: MockJwks, fx_claims: MockClaims) -> MockJwtClient:
    """JSON Web Tokens client."""
    return MockJwtClient(key=fx_jwks.jwk, claims=fx_claims)


@pytest.fixture()
def fx_jwt_empty(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no claims."""
    return fx_jwt.generate_empty()


@pytest.fixture()
def fx_jwt_kid(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with Key ID (kid) header."""
    return fx_jwt.generate_kid()


@pytest.fixture()
def fx_jwt_no_scopes(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims except scopes."""
    return fx_jwt.generate(scps=False, roles=False)


@pytest.fixture()
def fx_jwt_scps_and(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and all app scopes."""
    return fx_jwt.generate(roles=False)


@pytest.fixture()
def fx_jwt_scps_or(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and a valid choice from a set of required app scopes."""
    return fx_jwt.generate(scps=[fx_claims.scps[0]], roles=False)


@pytest.fixture()
def fx_jwt_scps_and_or(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and a valid subset of required app scopes."""
    return fx_jwt.generate(scps=[fx_claims.scps[0], fx_claims.scps[2]], roles=False)


@pytest.fixture()
def fx_jwt_roles_and(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and all user roles."""
    return fx_jwt.generate(scps=False)


@pytest.fixture()
def fx_jwt_roles_or(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and a valid choice from a set of required user roles."""
    return fx_jwt.generate(scps=False, roles=[fx_claims.roles[0]])


@pytest.fixture()
def fx_jwt_roles_and_or(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and a valid subset of required user roles."""
    return fx_jwt.generate(scps=False, roles=[fx_claims.roles[0], fx_claims.roles[2]])


@pytest.fixture()
def fx_jwt_scopes_and(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and all app and user scopes."""
    return fx_jwt.generate()


@pytest.fixture()
def fx_jwt_scopes_or(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and a valid subset of required app and user scopes."""
    return fx_jwt.generate(scps=[fx_claims.scps[0]], roles=[fx_claims.roles[0]])


@pytest.fixture()
def fx_jwt_scopes_or_bad(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and an invalid subset of required app and user scopes."""
    return fx_jwt.generate(scps=[fx_claims.scps[0]], roles=[fx_claims.roles[1]])  # intentionally don't align


@pytest.fixture()
def fx_jwt_scopes_and_or(fx_claims: MockClaims, fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with all validated claims and a valid subset of required app and user scopes."""
    return fx_jwt.generate(scps=[fx_claims.scps[0], fx_claims.scps[2]], roles=[fx_claims.roles[0], fx_claims.roles[2]])


@pytest.fixture()
def fx_jwt_bad_kid(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with an invalid Key ID (kid) header that is not in JWKS."""
    return fx_jwt.generate(kid="invalid")


@pytest.fixture()
def fx_jwt_bad_sig(fx_jwt_kid: str) -> str:
    """JSON Web Token (JWT) with invalid signature."""
    parts = fx_jwt_kid.split(".")
    return ".".join([parts[0], parts[1], "invalid_sig"])


@pytest.fixture()
def fx_jwt_no_iss(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Issuer (iss) claim."""
    return fx_jwt.generate(iss=False)


@pytest.fixture()
def fx_jwt_no_sub(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Subject (sub) claim."""
    return fx_jwt.generate(sub=False)


@pytest.fixture()
def fx_jwt_no_aud(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Audience (aud) claim."""
    return fx_jwt.generate(aud=False)


@pytest.fixture()
def fx_jwt_no_exp(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Expiry (exp) claim."""
    return fx_jwt.generate(exp=False)


@pytest.fixture()
def fx_jwt_no_nbf(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Not Before (nbf) claim."""
    return fx_jwt.generate(nbf=False)


@pytest.fixture()
def fx_jwt_no_azp(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Azure Client App (azp) claim."""
    return fx_jwt.generate(azp=False)


@pytest.fixture()
def fx_jwt_no_ver(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with no Azure token version (ver) claim."""
    return fx_jwt.generate(ver=False)


@pytest.fixture()
def fx_jwt_bad_iss(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid Issuer (iss) claim."""
    return fx_jwt.generate(iss="invalid")


@pytest.fixture()
def fx_jwt_bad_aud(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid Audience (aud) claim."""
    return fx_jwt.generate(aud="invalid")


@pytest.fixture()
def fx_jwt_bad_exp(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid Expiration (exp) claim."""
    return fx_jwt.generate(exp=1)


@pytest.fixture()
def fx_jwt_bad_nbf(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid Not Before (nbf) claim."""
    return fx_jwt.generate(nbf=4070908800)  # 2099-01-01T00:00:00Z


@pytest.fixture()
def fx_jwt_bad_ver(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid Azure token version (ver) claim."""
    return fx_jwt.generate(ver="invalid")


@pytest.fixture()
def fx_jwt_bad_sub(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid subject (sub) claim."""
    return fx_jwt.generate(sub="invalid")


@pytest.fixture()
def fx_jwt_bad_azp(fx_jwt: MockJwtClient) -> str:
    """JSON Web Token (JWT) with invalid Azure client app (azp) claim."""
    return fx_jwt.generate(azp="invalid")


@pytest.fixture()
def fx_app(httpserver: HTTPServer, fx_jwks: KeySet, fx_client_id_self: str, fx_claims: MockClaims) -> Flask:
    """Application."""
    oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claims.iss}
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
    httpserver.expect_request("/keys").respond_with_json(fx_jwks.as_dict())

    return create_app(
        client_id=fx_client_id_self,
        oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration"),
        allowed_subjects=[fx_claims.sub],
        allowed_apps=[fx_claims.azp],
    )


@pytest.fixture()
def fx_app_client(fx_app: Flask) -> FlaskClient:
    """App test client testing routes."""
    return fx_app.test_client()


@pytest.fixture()
def fx_app_client_no_oidc(httpserver: HTTPServer, fx_client_id_self: str) -> FlaskClient:
    """App test client with an inaccessible OIDC metadata endpoint."""
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_data(
        "Not found", status=404, content_type="text/plain"
    )

    return create_app(
        client_id=fx_client_id_self, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration")
    ).test_client()


@pytest.fixture()
def fx_app_client_bad_oidc(httpserver: HTTPServer, fx_client_id_self: str) -> FlaskClient:
    """App test client with invalid OIDC metadata."""
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_data(
        "Invalid", status=200, content_type="text/plain"
    )

    return create_app(
        client_id=fx_client_id_self, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration")
    ).test_client()


@pytest.fixture()
def fx_app_client_empty_oidc(httpserver: HTTPServer, fx_client_id_self: str) -> FlaskClient:
    """App test client with empty/invalid OIDC metadata."""
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json({})

    return create_app(
        client_id=fx_client_id_self, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration")
    ).test_client()


@pytest.fixture()
def fx_app_client_no_jwks(httpserver: HTTPServer, fx_client_id_self: str, fx_claims: MockClaims) -> FlaskClient:
    """App test client with an inaccessible JWKS endpoint."""
    oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claims.iss}
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
    httpserver.expect_request("/keys").respond_with_data("Not found", status=404, content_type="text/plain")

    return create_app(
        client_id=fx_client_id_self, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration")
    ).test_client()


@pytest.fixture()
def fx_app_client_bad_jwks(httpserver: HTTPServer, fx_client_id_self: str, fx_claims: MockClaims) -> FlaskClient:
    """App test client with an invalid JWKS endpoint."""
    oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claims.iss}
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
    httpserver.expect_request("/keys").respond_with_data("Invalid", status=200, content_type="text/plain")

    return create_app(
        client_id=fx_client_id_self, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration")
    ).test_client()


@pytest.fixture()
def fx_app_client_empty_jwks(httpserver: HTTPServer, fx_client_id_self: str, fx_claims: MockClaims) -> FlaskClient:
    """App test client with an JWKS endpoint that has no keys."""
    oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claims.iss}
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
    httpserver.expect_request("/keys").respond_with_json({"keys": []})

    return create_app(
        client_id=fx_client_id_self, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration")
    ).test_client()
