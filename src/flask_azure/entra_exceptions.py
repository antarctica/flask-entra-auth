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


class EntraAuthJwksError(EntraAuthError):
    """Raised when the JSON Web Key Set (JWKS) containing the token signing key is unavailable or invalid."""

    def __init__(self):
        super().__init__(
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            type_="jwks_error",
            title="Error processing JWKS",
            detail="The token signing key could not be loaded. Please try again later or report this error.",
        )


class EntraAuthJwtMissingClaimError(EntraAuthError):
    """Raised when a required claim is missing from the JSON Web Token (JWT)."""

    def __init__(self, claim: str):
        super().__init__(
            status=HTTPStatus.UNAUTHORIZED,
            type_="jwt_claim_missing",
            title="Missing required claim",
            detail="A required claim is missing from the token. Please try again with a new token "
                   "or report this error if it persists.",
        )

        self.claim = claim
