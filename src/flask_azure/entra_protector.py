import json
from dataclasses import asdict

from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.integrations.flask_oauth2.errors import raise_http_exception
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator, InsufficientScopeError
from flask import Flask, Request

from flask_azure.entra_exceptions import (
    EntraAuthError,
    EntraRequestInvalidAuthHeaderError,
    EntraRequestNoAuthHeaderError,
)
from flask_azure.entra_token import EntraToken


class EntraBearerTokenValidator(BearerTokenValidator):
    def __init__(self, oidc_endpoint: str, client_id: str):
        super().__init__()
        self._oidc_endpoint = oidc_endpoint
        self._client_id = client_id

    def authenticate_token(self, token_str: str) -> EntraToken:
        # initialising token implicitly validates it
        return EntraToken(
            token=token_str,
            oidc_endpoint=self._oidc_endpoint,
            client_id=self._client_id,
        )

    def validate_token(self, token: EntraToken, required_scopes: list[str], request: Request) -> None:
        # token authenticated so only need to check authorisation via scopes
        if self.scope_insufficient(token_scopes=token.scopes, required_scopes=required_scopes):
            raise InsufficientScopeError()


class EntraResourceProtector(ResourceProtector):
    def __init__(self, oidc_endpoint: str, client_id: str):
        super().__init__()

        self.current_token = current_token
        self.register_token_validator(
            EntraBearerTokenValidator(
                oidc_endpoint=oidc_endpoint,
                client_id=client_id,
            )
        )

    def raise_error_response(self, error: OAuth2Error) -> None:
        error_ = EntraAuthError()
        if error.error == "missing_authorization":
            error_ = EntraRequestNoAuthHeaderError()
        elif error.error == "unsupported_token_type":
            error_ = EntraRequestInvalidAuthHeaderError()

        raise_http_exception(
            status=error_.problem.status,
            body=json.dumps(asdict(error_.problem)),
            headers={"content-type": "application/json"},
        )

        # # temp
        # super().raise_error_response(error)


class FlaskEntraAuth:
    def __init__(self, app: Flask = None) -> None:
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        auth = EntraResourceProtector(
            oidc_endpoint=app.config["auth_oidc_endpoint"],
            client_id=app.config["auth_client_id"],
        )
        app.auth = auth
