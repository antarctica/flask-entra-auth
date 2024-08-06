from authlib.oauth2.rfc6750 import BearerTokenValidator

from flask_azure.entra_token import EntraToken


class EntraTokenAuthlib(EntraToken):
    def __init__(self, token: str, oidc_endpoint: str, client_id: str):
        super().__init__(token, oidc_endpoint, client_id)

    def is_expired(self) -> bool:
        return not self.valid

    @staticmethod
    def is_revoked() -> bool:
        # This doesn't apply to Entra tokens
        return False

    def get_scope(self) -> list[str]:
        return self.scopes


class EntraBearerTokenValidator(BearerTokenValidator):
    def __init__(self, oidc_endpoint: str, client_id: str):
        super().__init__()
        self._oidc_endpoint = oidc_endpoint
        self._client_id = client_id

    def authenticate_token(self, token_string) -> None:
        EntraTokenAuthlib(
            token=token_string,
            oidc_endpoint=self._oidc_endpoint,
            client_id=self._client_id,
        )
