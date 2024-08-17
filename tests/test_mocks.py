import pytest
from joserfc.jwk import KeySet
from pytest_httpserver import HTTPServer

from flask_entra_auth.mocks.jwt import MockClaims, MockJwtClient
from flask_entra_auth.token import EntraToken


class TestMockJwtClient:
    """Additional tests for MockJwtClient class."""

    @pytest.mark.cov()
    def test_generate_extra_claims(
        self, httpserver: HTTPServer, fx_jwks: KeySet, fx_claims: MockClaims, fx_jwt: MockJwtClient
    ):
        """
        Can generate token with additional claims.

        Using an EntraToken to check the claim is included is overkill but done for completeness and consistency.
        We could base64 & json decode the token string and check, or decode it as a JWT without checking the signature.
        """
        oidc_metadata = {"jwks_uri": httpserver.url_for("/keys"), "issuer": fx_claims.iss}
        httpserver.expect_request("/.well-known/openid-configuration").respond_with_json(oidc_metadata)
        httpserver.expect_request("/keys").respond_with_json(fx_jwks.as_dict())

        claim_ = "foo"
        value_ = "bar"

        token = fx_jwt.generate(additional_claims={claim_: value_})
        claims = EntraToken(
            token=token, oidc_endpoint=httpserver.url_for("/.well-known/openid-configuration"), client_id=fx_claims.aud
        ).claims

        assert claims[claim_] == value_
