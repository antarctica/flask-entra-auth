from __future__ import annotations

import json
from dataclasses import asdict

from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.integrations.flask_oauth2.errors import raise_http_exception
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator
from flask import Flask, Request, current_app

from flask_azure.exceptions import (
    EntraAuthError,
    EntraAuthInsufficentScopesError,
    EntraAuthRequestInvalidAuthHeaderError,
    EntraAuthRequestNoAuthHeaderError,
)
from flask_azure.token import EntraToken


def _raise_exception_response(error: EntraAuthError) -> None:
    """
    Override of the AuthLib exception response handler to work with EntraAuthError exceptions.

    These exceptions use the problem details response format (RFC 7807) encoded as JSON.
    """
    raise_http_exception(
        status=error.problem.status,
        body=json.dumps(asdict(error.problem)),
        headers={"content-type": "application/json"},
    )


class EntraBearerTokenValidator(BearerTokenValidator):
    """
    Bearer token validator for Entra identity platform.

    As tokens are issued by Entra, and not by this application, this class is not used as it's typically intended by
    looking up a token in a store. Instead, the token is implicitly authenticated by validating it as a JWT.

    The `validate_token` method is overridden to only check the scopes of the token (authorisation), as the expiration
    will have already been checked by the `authenticate_token` method, revoking tokens does not apply in this case.
    """

    def authenticate_token(self, token_str: str) -> EntraToken:
        """
        Authenticate a token by parsing it and validating its claims.

        Creating a EntraToken instance implicitly validates it and will raise an exception as a response if needed.
        """
        try:
            return EntraToken(
                token=token_str,
                oidc_endpoint=current_app.config["ENTRA_AUTH_OIDC_ENDPOINT"],
                client_id=current_app.config["ENTRA_AUTH_CLIENT_ID"],
                allowed_subjects=current_app.config.get("ENTRA_AUTH_ALLOWED_SUBJECTS", []),
                allowed_apps=current_app.config.get("ENTRA_AUTH_ALLOWED_APPS", []),
            )
        except EntraAuthError as e:
            _raise_exception_response(e)

    def validate_token(self, token: EntraToken, required_scopes: list[str], request: Request) -> None:
        """
        Validate the token by checking its scopes against the required scopes.

        Typically, this method would also check the token's expiration and revocation status, however the former will
        have already been checked by the `authenticate_token` method and revoking tokens does not apply to Entra tokens.
        """
        if self.scope_insufficient(token_scopes=token.scopes, required_scopes=required_scopes):
            _raise_exception_response(EntraAuthInsufficentScopesError())


class EntraResourceProtector(ResourceProtector):
    """
    Resource protector for Entra identity platform.

    This class:
    - registers a bearer token validator for Entra access tokens
    - provides a shortcut to the access token as an EntraToken in routes (i.e. to get the current user)
    - overrides the error handler to provide consistent error responses
    """

    def __init__(self):
        super().__init__()
        self.current_token: EntraToken = current_token

        self.register_token_validator(EntraBearerTokenValidator())

    def raise_error_response(self, error: OAuth2Error) -> None:
        """Override of the default error handler to provide consistent error responses."""
        if error.error == "missing_authorization":
            # the request has no `authorization` header
            _raise_exception_response(EntraAuthRequestNoAuthHeaderError())
        if error.error == "unsupported_token_type":
            # the auth scheme or credential was not specified or the scheme is not 'bearer'
            _raise_exception_response(EntraAuthRequestInvalidAuthHeaderError())

        super().raise_error_response(error)  # pragma: no cover


class FlaskEntraAuth:
    """Flask extension for authenticating and authorising requests using Entra identity platform."""

    def __init__(self, app: Flask | None = None) -> None:
        """Conventional extension init method."""
        if app is not None:  # pragma: no branch
            self.init_app(app)  # pragma: no cover

    @staticmethod
    def init_app(app: Flask) -> None:
        """Initialise extension for an application."""
        auth = EntraResourceProtector()
        app.auth = auth
