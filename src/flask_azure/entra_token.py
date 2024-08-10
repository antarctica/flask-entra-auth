from __future__ import annotations

from typing import TypedDict

import requests
from jwt import (
    DecodeError,
    InvalidSignatureError,
    MissingRequiredClaimError,
    PyJWK,
    PyJWKClient,
    PyJWKClientError,
    PyJWKSetError,
)
from jwt import decode as jwt_decode


class EntraTokenError(Exception):
    pass


class EntraTokenExpiredError(EntraTokenError):
    pass


class EntraTokenSubjectNotAllowedError(EntraTokenError):
    pass


class EntraTokenClientAppNotAllowedError(EntraTokenError):
    pass


class EntraTokenVersionNotAllowedError(EntraTokenError):
    pass
from flask_azure.entra_exceptions import EntraAuthJwksError
from flask_azure.entra_exceptions import EntraAuthJwksError, EntraAuthJwtMissingClaimError
from flask_azure.entra_exceptions import (
    EntraAuthInvalidSignatureError,
    EntraAuthInvalidTokenError,
    EntraAuthKeyError,
    EntraAuthMissingClaimError,
    EntraAuthOidcError,
)


class EntraTokenClaims(TypedDict):
    aud: str
    iss: str
    iat: int
    nbf: int
    exp: int
    aio: str
    azp: str
    azpacr: str
    email: str
    family_name: str
    given_name: str
    name: str
    oid: str
    preferred_username: str
    rh: str
    roles: list[str]
    scp: str
    sub: str
    tid: str
    uti: str
    ver: str


class Rfc7662Members(TypedDict):
    active: bool
    scope: list[str] | None
    client_id: str | None
    username: str | None
    token_type: str | None
    exp: int | None
    iat: int | None
    nbf: int | None
    sub: str | None
    aud: str | None
    iss: str | None
    jti: str | None


class EntraToken:
    @property
    def _required_claims(self) -> list[str]:
        return [
            "iss",  # issuer - who issued the token - checked by default
            "sub",  # subject - who the token was issued to - additionally checked by `allowed_subs` list
            "aud",  # audience - who the token was intended for - checked by default
            "exp",  # expiration - when the token is valid to - checked by default
            "nbf",  # not before - when the token is valid from - ?
            "azp",  # Azure client applications - the client application - additionally checked by `allowed_azps` list
            "ver",  # version - the version of the token - additionally checked, must be '2.0'
        ]

    def __init__(
        self,
        token: str,
        oidc_endpoint: str,
        client_id: str,
        allowed_subs: list | None = None,
        allowed_azps: list | None = None,
    ) -> None:
        self._token = token
        self._oidc_endpoint = oidc_endpoint
        self._client_id = client_id
        self._allowed_subs: list | None = allowed_subs
        self._allowed_azps: list | None = allowed_azps

        self.claims = self.validate()
        self.valid = True

    @property
    def _public_key(self) -> PyJWK:
        oidc_config = self._get_oidc_metadata()
        jwks_client = PyJWKClient(oidc_config["jwks_uri"])
        try:
            return jwks_client.get_signing_key_from_jwt(self._token)
        except PyJWKClientError as e:
            raise EntraAuthKeyError from e
        except JSONDecodeError as e:
            raise EntraAuthKeyError from e
        except PyJWKSetError as e:
            raise EntraAuthKeyError from e

    @property
    def _issuer(self) -> str:
        oidc_config = self._get_oidc_metadata()
        return oidc_config["issuer"]

    def _get_oidc_metadata(self) -> dict:
        try:
            oidc_req = requests.get(self._oidc_endpoint, timeout=10)
            oidc_req.raise_for_status()
            oidc_data = oidc_req.json()
            if "jwks_uri" not in oidc_data or "issuer" not in oidc_data:
                raise EntraAuthOidcError
        except requests.RequestException as e:
            raise EntraAuthOidcError from e
        else:
            return oidc_data

    @staticmethod
    def _validate_ver(ver: str):
        if ver != "2.0":
            raise EntraTokenVersionNotAllowedError(f"Version '{ver}' not allowed")

    def _validate_sub(self, sub: str):
        if self._allowed_subs:
            if sub not in self._allowed_subs:
                raise EntraTokenSubjectNotAllowedError(f"Subject '{sub}' not allowed")

    def _validate_azp(self, azp: str):
        if self._allowed_azps:
            if azp not in self._allowed_azps:
                raise EntraTokenClientAppNotAllowedError(
                    f"Azure client application '{azp}' not allowed"
                )

    def validate(self) -> EntraTokenClaims:
        try:
            claims: EntraTokenClaims = jwt_decode(
                jwt=self._token,
                key=self._public_key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=self._issuer,
                options={"require": self._required_claims},
            )

        self._validate_ver(claims["ver"])
        self._validate_sub(claims["sub"])
        self._validate_azp(claims["azp"])

        return claims
        except MissingRequiredClaimError as e:
            raise EntraAuthJwtMissingClaimError(claim=e.claim) from e

    @property
    def scopes(self) -> list[str]:
        # scps - assigned to applications
        # roles - assigned to users

        scopes = set()

        roles = self.claims.get("roles")
        if isinstance(roles, str):
            scopes.update(set(str(roles).split(" ")))
        elif isinstance(roles, list):
            scopes.update(roles)

        scps = self.claims.get("scp")
        if isinstance(scps, str):
            scopes.update(set(str(scps).split(" ")))
        elif isinstance(scps, list):
            scopes.update(scps)

        return list(scopes)

    @property
    def rfc7662_introspection(self) -> Rfc7662Members:
        return {
            "active": True,
            "scope": self.scopes,
            "client_id": self.claims.get("azp"),
            "username": self.claims.get("email"),
            "token_type": "access_token",
            "exp": self.claims.get("exp"),
            "iat": self.claims.get("iat"),
            "nbf": self.claims.get("nbf"),
            "sub": self.claims.get("sub"),
            "aud": self.claims.get("aud"),
            "iss": self.claims.get("iss"),
        }
