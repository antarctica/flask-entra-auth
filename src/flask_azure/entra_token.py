from __future__ import annotations

from json import JSONDecodeError
from typing import TypedDict

import requests
from jwt import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    MissingRequiredClaimError,
    PyJWK,
    PyJWKClient,
    PyJWKClientError,
    PyJWKSetError,
)
from jwt import decode as jwt_decode

from flask_azure.entra_exceptions import (
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
        allowed_subjects: list | None = None,
        allowed_apps: list | None = None,
    ) -> None:
        self._token = token
        self._oidc_endpoint = oidc_endpoint
        self._client_id = client_id
        self._allowed_subjects: list | None = allowed_subjects
        self._allowed_apps: list | None = allowed_apps

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

    def _validate_sub(self, sub: str) -> None:
        if self._allowed_subjects and sub not in self._allowed_subjects:
            raise EntraAuthInvalidSubjectError() from None

    def _validate_azp(self, azp: str) -> None:
        if self._allowed_apps and azp not in self._allowed_apps:
            raise EntraAuthInvalidAppError() from None

    @staticmethod
    def _validate_ver(ver: str) -> None:
        if ver != "2.0":
            raise EntraAuthInvalidTokenVersionError() from None

    def validate(self) -> EntraTokenClaims:
        try:
            claims: EntraTokenClaims = jwt_decode(
                jwt=self._token,
                key=self._public_key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=self._issuer,
                options={"require": self._required_claims, "verify_iat": False,},
            )
            self._validate_ver(claims["ver"])
            self._validate_sub(claims["sub"])
            self._validate_azp(claims["azp"])
        except InvalidSignatureError as e:
            raise EntraAuthInvalidSignatureError from e
        except DecodeError as e:
            raise EntraAuthInvalidTokenError from e
        except MissingRequiredClaimError as e:
            raise EntraAuthMissingClaimError(claim=e.claim) from e
        except InvalidIssuerError as e:
            raise EntraAuthInvalidIssuerError from e
        except InvalidAudienceError as e:
            raise EntraAuthInvalidAudienceError from e
        except ExpiredSignatureError as e:
            raise EntraAuthInvalidExpirationError from e
        except ImmatureSignatureError as e:
            raise EntraAuthNotValidBeforeError from e
        else:
            return claims

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
