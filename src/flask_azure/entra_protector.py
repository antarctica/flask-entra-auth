from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.oauth2.rfc6750 import BearerTokenValidator, InsufficientScopeError
from flask import Request, Flask

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

    def validate_token(
        self, token: EntraToken, required_scopes, request: Request
    ) -> None:
        # token authenticated so only need to check authorisation via scopes
        if self.scope_insufficient(
            token_scopes=token.scopes, required_scopes=required_scopes
        ):
            raise InsufficientScopeError()


class EntraProtector:
    def __init__(self, app: Flask = None) -> None:
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        auth = ResourceProtector()
        auth.register_token_validator(
            EntraBearerTokenValidator(
                oidc_endpoint=app.config["auth_oidc_endpoint"],
                client_id=app.config["auth_client_id"],
            )
        )
        auth.current_token = current_token

        app.auth = auth
