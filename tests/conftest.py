from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask.testing import FlaskClient
from joserfc.jwk import KeySet
from jwt import encode as jwt_encode
from pytest_httpserver import HTTPServer

from flask_azure.__main__ import app as app_


@pytest.fixture()
def fx_client_id_self() -> str:
    """Client ID for app containing protected resources."""
    return "test_client_1"


@pytest.fixture()
def fx_time_anchor() -> datetime:
    """Temporal reference point for JWT claims."""
    return datetime.now()


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
def fx_claim_iss() -> str:
    """Issuer claim."""
    return "https://issuer.auth.example.com"


@pytest.fixture()
def fx_claim_sub() -> str:
    """Subject claim."""
    return "test_subject"


@pytest.fixture()
def fx_claim_aud(fx_client_id_self: str) -> str:
    """Audience claim."""
    return fx_client_id_self


@pytest.fixture()
def fx_claim_exp(fx_time_anchor: datetime) -> int:
    """Expiration claim."""
    return int(fx_time_anchor.timestamp() + 3600)


@pytest.fixture()
def fx_claim_nbf(fx_time_anchor: datetime) -> int:
    """Not Before claim."""
    return int(fx_time_anchor.timestamp())

@pytest.fixture()
def fx_claim_azp(fx_client_id_self: str) -> str:
    """Azure client application claim."""
    return 'test_client_2'


@pytest.fixture()
def fx_claim_ver() -> str:
    """Azure token Version claim."""
    return '2.0'


@pytest.fixture()
def fx_jwt_empty(fx_jwk_private: str) -> str:
    """Jason Web Token (JWT) with no claims."""
    return jwt_encode(payload={}, key=fx_jwk_private, algorithm="RS256")


@pytest.fixture()
def fx_jwt_kid(fx_jwk_private: str, fx_jwk_kid: str) -> str:
    """Jason Web Token (JWT) with Key ID (kid) header."""
    return jwt_encode(payload={}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_iss(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str) -> str:
    """Jason Web Token (JWT) with Issuer (iss) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_sub(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str, fx_claim_sub: str) -> str:
    """Jason Web Token (JWT) with Subject (sub) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss, 'sub': fx_claim_sub}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_aud(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str, fx_claim_sub: str, fx_claim_aud: str) -> str:
    """Jason Web Token (JWT) with Audience (aud) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss, 'sub': fx_claim_sub, 'aud': fx_claim_aud}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_exp(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str, fx_claim_sub: str, fx_claim_aud: str, fx_claim_exp: int) -> str:
    """Jason Web Token (JWT) with Expiry (exp) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss, 'sub': fx_claim_sub, 'aud': fx_claim_aud, 'exp': fx_claim_exp}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_nbf(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str, fx_claim_sub: str, fx_claim_aud: str, fx_claim_exp: int, fx_claim_nbf: int) -> str:
    """Jason Web Token (JWT) with Not Before (nbf) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss, 'sub': fx_claim_sub, 'aud': fx_claim_aud, 'exp': fx_claim_exp, 'nbf': fx_claim_nbf}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_azp(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str, fx_claim_sub: str, fx_claim_aud: str, fx_claim_exp: int, fx_claim_nbf: int, fx_claim_azp: str) -> str:
    """Jason Web Token (JWT) with Azure Client App (azp) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss, 'sub': fx_claim_sub, 'aud': fx_claim_aud, 'exp': fx_claim_exp, 'nbf': fx_claim_nbf, 'azp': fx_claim_azp}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_jwt_ver(fx_jwk_private: str, fx_jwk_kid: str, fx_claim_iss: str, fx_claim_sub: str, fx_claim_aud: str, fx_claim_exp: int, fx_claim_nbf: int, fx_claim_azp: str, fx_claim_ver: str) -> str:
    """Jason Web Token (JWT) with Azure Token Version (ver) claim."""
    return jwt_encode(payload={'iss': fx_claim_iss, 'sub': fx_claim_sub, 'aud': fx_claim_aud, 'exp': fx_claim_exp, 'nbf': fx_claim_nbf, 'azp': fx_claim_azp, 'ver': fx_claim_ver}, key=fx_jwk_private, algorithm="RS256", headers={"kid": fx_jwk_kid})


@pytest.fixture()
def fx_app(httpserver: HTTPServer, fx_client_id_self: str, fx_claim_iss: str, fx_jwks: KeySet) -> Flask:
    """Application."""
    oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claim_iss}
    httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
    httpserver.expect_request("/keys").respond_with_json(fx_jwks.as_dict(private=False))

    app_.config["TESTING"] = True
    app_.config["ENTRA_AUTH_CLIENT_ID"] = fx_client_id_self
    app_.config["ENTRA_AUTH_OIDC_ENDPOINT"] = httpserver.url_for("/.well-known/openid-configuration")

    return app_


@pytest.fixture()
def fx_app_client(fx_app) -> FlaskClient:
    return fx_app.test_client()
