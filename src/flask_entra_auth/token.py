from __future__ import annotations

import time
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

from flask_entra_auth.exceptions import (
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
    EntraAuthSigningKeyError,
)


class EntraTokenClaims(TypedDict):
    """
    Typical claims in an Entra v2.0 access token.

    Note: This list focuses on claims used validation and introspection for typical applications.

    See https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#payload-claims for
    additional claims and their purpose.
    """

    # Standard claims
    aud: str
    iss: str
    sub: str
    iat: int
    nbf: int
    exp: int

    # Entra specific and optional claims
    aio: str
    azp: str  # always present
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
    scps: list[str]
    tid: str
    uti: str
    ver: str  # always present


class Rfc7662Members(TypedDict):
    """
    Properties of a OAuth 2.0 Token Introspection (RFC 7662) payload.

    See https://datatracker.ietf.org/doc/html/rfc7662#section-2.2 for more information.
    """

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
    """
    Entra access token.

    Provides validation, introspection and access methods of and to tokens and their claims.

    Tokens are implicitly validated on init, which will trigger requests to the OIDC and JWKS endpoints. These are then
    cached for upto 60 seconds to speed up subsequent lookups and prevent unnecessary requests.

    If the token is invalid, a relevant EntraAuth exception is raised.

    See https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens for more information.
    """

    @property
    def _required_claims(self) -> list[str]:
        return [
            "iss",  # issuer - who issued the token, checked against expected value, built-in check
            "sub",  # subject - who the token was issued to, checked against `allowed_subs` list, additional check
            "aud",  # audience - who the token was intended for, checked against expected value, built-in check
            "exp",  # expiration - when the token is valid to, must be after now, built-in check
            "nbf",  # not before - when the token is valid from, must be before now, built-in check
            "azp",  # client app - app token is used within, checked against `allowed_azps` list, additional check
            "ver",  # version - token version, must be '2.0', additional check
        ]

    def __init__(
        self,
        token: str,
        oidc_endpoint: str,
        client_id: str,
        allowed_subjects: list | None = None,
        allowed_apps: list | None = None,
        cache_ttl: int = 60,
    ) -> None:
        self._token = token
        self._oidc_endpoint = oidc_endpoint
        self._client_id = client_id
        self._allowed_subjects: list | None = allowed_subjects
        self._allowed_apps: list | None = allowed_apps
        self._cache_ttl = cache_ttl

        self._cached_oidc_metadata: dict | None = None
        self._cached_oidc_metadata_expiry: int = -1

        self.claims = self.validate()
        self.valid = True

    @property
    def _signing_key(self) -> PyJWK:
        """
        Retrieve the signing key for the token from the OIDC metadata.

        The OIDC metadata includes the URI to a JSON Web Key Set (JWKS), which should contain a JWK that can be used to
        verify the token. Keys are matched by the `kid` token header parameter.

        The fetched JWKS is cached to speed up subsequent lookups and prevent unnecessary requests to the JWKS endpoint.
        """
        oidc_config = self._get_oidc_metadata()
        jwks_client = PyJWKClient(oidc_config["jwks_uri"], lifespan=self._cache_ttl)
        try:
            return jwks_client.get_signing_key_from_jwt(self._token)
        except PyJWKClientError as e:
            raise EntraAuthSigningKeyError from e
        except JSONDecodeError as e:
            raise EntraAuthSigningKeyError from e
        except PyJWKSetError as e:
            raise EntraAuthSigningKeyError from e

    @property
    def _issuer(self) -> str:
        """
        Expected token issuer, as defined in OIDC metadata.

        Value used to validate the `iss` claim in the token.
        """
        oidc_config = self._get_oidc_metadata()
        return oidc_config["issuer"]

    def _get_oidc_metadata(self) -> dict:
        """
        Retrieve OIDC metadata from the OIDC endpoint.

        The fetched metadata is cached to speed up subsequent lookups and prevent unnecessary requests to the OIDC
        endpoint.

        See https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#fetch-the-openid-configuration-document
        for more information.
        """
        if self._cached_oidc_metadata and time.monotonic() < self._cached_oidc_metadata_expiry:
            return self._cached_oidc_metadata

        try:
            oidc_req = requests.get(self._oidc_endpoint, timeout=10)
            oidc_req.raise_for_status()
            oidc_data = oidc_req.json()
            if "jwks_uri" not in oidc_data or "issuer" not in oidc_data:
                raise EntraAuthOidcError
        except requests.RequestException as e:
            raise EntraAuthOidcError from e
        else:
            self._cached_oidc_metadata = oidc_data
            self._cached_oidc_metadata_expiry = time.monotonic() + self._cache_ttl
            return oidc_data

    def _validate_sub(self, sub: str) -> None:
        """
        Validate the subject (sub) claim against allowed subjects if configured.

        Entra Docs:

        > The principal associated with the token. For example, the user of an application.
        > The subject is a pairwise identifier that's unique to a particular application ID. If a single user signs
        > into two different applications using two different client IDs, those applications receive two different
        > values for the subject claim.

        If not configured, all subjects are allowed.
        """
        if self._allowed_subjects and sub not in self._allowed_subjects:
            raise EntraAuthInvalidSubjectError() from None

    def _validate_azp(self, azp: str) -> None:
        """
        Validate the client application (azp) Entra claim against allowed clients if configured.

        Entra Docs:

        > The application ID of the client using the token. The application can act as itself or on behalf of a user.
        > The application ID typically represents an application object, but it can also represent a service principal
        > object in Microsoft Entra ID.

        If not configured, all clients are allowed.
        """
        if self._allowed_apps and azp not in self._allowed_apps:
            raise EntraAuthInvalidAppError() from None

    @staticmethod
    def _validate_ver(ver: str) -> None:
        """
        Validate the token version (ver) Entra claim.

        Must be a '2.0' token.
        """
        if ver != "2.0":
            raise EntraAuthInvalidTokenVersionError() from None

    def validate(self) -> EntraTokenClaims:
        """
        Validate the token and set claims.

        The `iat` claim is not checked as it can't be tested, and it's implementation is controversial.

        See the 'Token validation' section of the README for more information.
        """
        try:
            claims: EntraTokenClaims = jwt_decode(
                jwt=self._token,
                key=self._signing_key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=self._issuer,
                options={
                    "require": self._required_claims,
                    "verify_iat": False,
                },
            )
            self._validate_ver(claims["ver"])
            self._validate_sub(claims["sub"])
            self._validate_azp(claims["azp"])
        except InvalidSignatureError as e:
            raise EntraAuthInvalidSignatureError() from e
        except DecodeError as e:
            raise EntraAuthInvalidTokenError() from e
        except MissingRequiredClaimError as e:
            raise EntraAuthMissingClaimError(claim=e.claim) from e
        except InvalidIssuerError as e:
            raise EntraAuthInvalidIssuerError() from e
        except InvalidAudienceError as e:
            raise EntraAuthInvalidAudienceError() from e
        except ExpiredSignatureError as e:
            raise EntraAuthInvalidExpirationError() from e
        except ImmatureSignatureError as e:
            raise EntraAuthNotValidBeforeError() from e
        else:
            return claims

    @property
    def scopes(self) -> list[str]:
        """
        Get any scopes included in the token.

        Combines scopes from the `roles` and `scps` claims, which are assigned to users and client apps respectively.
        Roles are assigned to users, and delegated to client apps. 'Scps' are assigned to client apps directly.

        To simplify authorisation checks, these are combined into a generic list of scopes.
        """
        scopes = set()

        roles = self.claims.get("roles", [])
        scopes.update(roles)

        scps = self.claims.get("scps", [])
        scopes.update(scps)

        return list(scopes)

    @property
    def rfc7662_introspection(self) -> Rfc7662Members:
        """
        Response payload for a OAuth 2.0 Token Introspection (RFC 7662) request.

        As tokens are validated implicitly on init, and will raise an exception if invalid, this method assumes the
        token is active at the time of introspection.
        """
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
