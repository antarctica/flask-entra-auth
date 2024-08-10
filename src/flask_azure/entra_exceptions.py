from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus


@dataclass
class HttpProblem:
    """HTTP Problem Details for RFC 7807."""

    type: str | None
    title: str | None
    status: int | None
    detail: str | None


class EntraAuthError(Exception):
    """Base class for EntraToken exceptions."""

    def __init__(
        self,
        status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR,
        type_: str = "unknown",
        title: str = "Unknown",
        detail: str = "An unknown authentication error has occurred. Please try again later or report this error.",
    ):
        self._status = status
        self._type = f"#auth_{type_}"

        self.problem = HttpProblem(
            type=self._type,
            title=title,
            status=self._status.value,
            detail=detail,
        )
        super().__init__(title)


class EntraAuthOidcError(EntraAuthError):
    """Raised when the OIDC metadata endpoint is unavailable or invalid."""

    def __init__(self):
        super().__init__(
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            type_="auth_oidc_error",
            title="OIDC metadata error",
            detail="The OIDC metadata endpoint used to get trusted signing keys and other setting is unavailable or "
                   "invalid. This is an atypical server error, please try again later, or report this error if it "
                   "persists.",
        )


class EntraAuthRequestNoAuthHeaderError(EntraAuthError):
    """Raised when no auth header is in request."""

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="header_missing",
            title="Missing authorization header",
            detail="Ensure your request includes an 'Authorization' header and try again.",
        )


class EntraAuthRequestInvalidAuthHeaderError(EntraAuthError):
    """Raised when the auth header has a missing/unsupported auth scheme or missing credential."""

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="header_invalid",
            title="Invalid authorization header",
            detail="Ensure the 'Authorization' header scheme is 'Bearer' with a valid credential and try again. \n "
                   "E.g. 'Authorization: Bearer <token>'",
        )


class EntraAuthKeyError(EntraAuthError):
    """
    Raised when the JWT signing key is unavailable or invalid.

    Covers a few situations:
    - JWKS endpoint is unavailable, malformed or empty
    - JWT does not contain a key ID (kid) header parameter
    - JWKS does not contain the key specified by the JWT
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="auth_token_key_error",
            title="Token signing key error",
            detail="The key used to sign the auth token could not be loaded. This is an atypical error. Please check "
                   "the token includes a valid 'kid' header parameter and try again later, or report this error if it "
                   "persists. https://jwt.ms can be used to check a token.",
        )


class EntraAuthJwtMissingClaimError(EntraAuthError):
    """Raised when a required claim is missing from the JSON Web Token (JWT)."""

    def __init__(self, claim: str):
        self.claim = claim

        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="jwt_claim_missing",
            title="Missing required claim",
            detail=f"Required claim '{self.claim}' is missing from the token. Please try again with a new token "
                   "or report this error if it persists. https://jwt.ms can be used to check claims in a token.",


class EntraAuthInvalidTokenError(EntraAuthError):
    """
    Raised when the JWT can't be decoded.

    Corresponds to https://pyjwt.readthedocs.io/en/latest/api.html#jwt.exceptions.DecodeError
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="auth_token_invalid",
            title="Auth token invalid",
            detail="Auth token could not be decoded. This an atypical error, please check the token is a JWT "
                   "(JSON Web Token) and try again, or report this error if it persists. https://jwt.ms can be used to "
                   "check a token.",
        )


class EntraAuthInvalidSignatureError(EntraAuthError):
    """
    Raised when the JWT signature cannot be verified against it's signing key.

    Corresponds to https://pyjwt.readthedocs.io/en/latest/api.html#jwt.exceptions.InvalidSignatureError
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="jwt_invalid_signature",
            title="Invalid token signature",
            detail="The auth token's signature cannot be verified using the signing key specified by the token, and "
                   "cannot therefore be trusted. This is an atypical error, please try again with a new token "
                   "or report this error if it persists. https://jwt.ms can be used to check a token.",


class EntraAuthInvalidIssuerError(EntraAuthError):
    """
    Raised when the JWT issuer is invalid.

    Corresponds to https://pyjwt.readthedocs.io/en/latest/api.html#jwt.exceptions.InvalidIssuerError
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="auth_token_issuer_untrusted",
            title="Auth token untrusted issuer",
            detail="The auth token's issuer is not trusted. This is an uncommon error, please try again with a new "
                   "token or report this error if it persists. https://jwt.ms can be used to check a token.",
        )


class EntraAuthInvalidAudienceError(EntraAuthError):
    """
    Raised when the JWT audience is invalid.

    Corresponds to https://pyjwt.readthedocs.io/en/latest/api.html#jwt.exceptions.InvalidAudienceError
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="auth_token_audience_invalid",
            title="Auth token audience invalid",
            detail="The auth token's audience does not correspond to this application. This is an uncommon error, "
                   "please try again with a new token or report this error if it persists. "
                   "https://jwt.ms can be used to check a token.",
        )


class EntraAuthInvalidExpirationError(EntraAuthError):
    """
    Raised when the JWT has expired.

    Corresponds to https://pyjwt.readthedocs.io/en/latest/api.html#jwt.exceptions.ExpiredSignatureError
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="auth_token_expired",
            title="Auth token expired",
            detail="The auth token has expired. This is a common error, please try again with a new token or report "
                   "this error if it persists. https://jwt.ms can be used to check a token.",
        )


class EntraAuthNotValidBeforeError(EntraAuthError):
    """
    Raised when the JWT is not valid yet.

    Corresponds to https://pyjwt.readthedocs.io/en/latest/api.html#jwt.exceptions.ImmatureSignatureError
    """

    def __init__(self):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="auth_token_immature",
            title="Auth token not yet valid",
            detail="The auth token is not valid yet. This is an uncommon error, please try again with a new token or "
                   "report this error if it persists. https://jwt.ms can be used to check a token.",
        )
