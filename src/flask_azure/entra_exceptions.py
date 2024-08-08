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

    def __init__(self, type_: str = "unknown", title: str = "Unknown", detail: str = "-"):
        self._status = HTTPStatus.UNAUTHORIZED
        self._type = f"#auth_{type_}"

        self.problem = HttpProblem(
            type=self._type,
            title=title,
            status=self._status.value,
            detail=detail,
        )
        super().__init__(title)


class EntraRequestNoAuthHeaderError(EntraAuthError):
    """Raised when no auth header is in request."""

    def __init__(self):
        super().__init__(
            type_="header_missing",
            title="Missing authorization header",
            detail="Ensure your request includes an 'Authorization' header and try again.",
        )


class EntraRequestInvalidAuthHeaderError(EntraAuthError):
    """Raise when the auth header has a missing/unsupported auth scheme or missing credential."""

    def __init__(self):
        super().__init__(
            type_="header_invalid",
            title="Invalid authorization header",
            detail="Ensure the 'Authorization' header scheme is 'Bearer' with a valid credential and try again. \n "
                   "E.g. 'Authorization: Bearer <token>'",
        )
