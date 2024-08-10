import pytest
from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask.testing import FlaskClient
from joserfc.jwk import KeySet
from jwt import encode as jwt_encode
from pytest_httpserver import HTTPServer

from flask_azure.__main__ import app as app_


@pytest.fixture()
def fx_jwks() -> KeySet:
    """JSON Web Key Set for generating local tokens."""
    return KeySet.generate_key_set(key_type="RSA", crv_or_size=2048, count=1)


@pytest.fixture()
def fx_jwk_kid(fx_jwks: KeySet) -> str:
    """Key ID (kid) for JSON Web Key (JWK) in JSON Web Key Set (JWKS)."""
    return fx_jwks.keys[0].kid


@pytest.fixture()
def fx_jwk_private(fx_jwks: KeySet) -> str:
    """Private key for JSON Web Key (JWK) in JSON Web Key Set (JWKS)."""
    return fx_jwks.keys[0].private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture()
def fx_jwt_empty(fx_jwk_private: str) -> str:
    """Jason Web Token (JWT) with no claims."""
    return jwt_encode(payload={}, key=fx_jwk_private, algorithm="RS256")


@pytest.fixture()
def fx_jwt_kid(fx_jwk_private: str, fx_jwk_kid: str) -> str:
    """Jason Web Token (JWT) with Key ID (kid) claim."""
    return jwt_encode(payload={}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_claim_iss() -> str:
    """Issuer claim."""
    return "https://issuer.auth.example.com"


@pytest.fixture()
def fx_app(httpserver: HTTPServer, fx_claim_iss: str, fx_jwks: KeySet) -> Flask:
    """Application."""
    oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claim_iss}
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
    httpserver.expect_request("/keys").respond_with_json(fx_jwks.as_dict(private=False))

    app_.config["TESTING"] = True
    app_.config["ENTRA_AUTH_CLIENT_ID"] = "test-client"
    app_.config["ENTRA_AUTH_OIDC_ENDPOINT"] = httpserver.url_for("/.well-known/openid-configuration")

    return app_


@pytest.fixture()
def fx_app_client(fx_app) -> FlaskClient:
    return fx_app.test_client()
