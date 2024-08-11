from __future__ import annotations

import json
from dataclasses import asdict

from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.integrations.flask_oauth2.errors import raise_http_exception
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator
from flask import Flask, Request, current_app

from flask_azure.entra_exceptions import (
    EntraAuthError,
    EntraAuthInsufficentScopesError,
    EntraAuthRequestInvalidAuthHeaderError,
    EntraAuthRequestNoAuthHeaderError,
)
from flask_azure.entra_token import EntraToken


def _raise_exception_response(error: EntraAuthError) -> None:
    raise_http_exception(
        status=error.problem.status,
        body=json.dumps(asdict(error.problem)),
        headers={"content-type": "application/json"},
    )


class EntraBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_str: str) -> EntraToken:
        # initialising token implicitly validates it
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
        # token authenticated so only need to check authorisation via scopes
        if self.scope_insufficient(token_scopes=token.scopes, required_scopes=required_scopes):
            _raise_exception_response(EntraAuthInsufficentScopesError())


class EntraResourceProtector(ResourceProtector):
    def __init__(self):
        super().__init__()
        self.current_token = current_token

        self.register_token_validator(EntraBearerTokenValidator())

    def raise_error_response(self, error: OAuth2Error) -> None:
        error_ = EntraAuthError()
        if error.error == "missing_authorization":
            error_ = EntraAuthRequestNoAuthHeaderError()
        elif error.error == "unsupported_token_type":
            error_ = EntraAuthRequestInvalidAuthHeaderError()

        raise_http_exception(
            status=error_.problem.status,
            body=json.dumps(asdict(error_.problem)),
            headers={"content-type": "application/json"},
        )


class FlaskEntraAuth:
    def __init__(self, app: Flask | None = None) -> None:
        if app is not None:
            self.init_app(app)

    @staticmethod
    def init_app(app: Flask) -> None:
        auth = EntraResourceProtector()
        app.auth = auth
