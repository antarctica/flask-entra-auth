from http import HTTPStatus

from flask_azure_oauth.errors import ApiAuthTokenScopesInsufficient
from tests.test_base import FlaskOAuthProviderBaseTestCase


class FlaskOAuthProviderJWTScopesTestCase(FlaskOAuthProviderBaseTestCase):
    def test_auth_insufficient_token_scopes(self):
        error = ApiAuthTokenScopesInsufficient(
            meta={
                'required_scopes': ['unobtainable-scope'],
                'scopes_in_token': []
            }
        )
        expected_payload = self._prepare_expected_error_payload(error)
        token = self._create_auth_token()

        response = self.client.get('/meta/auth/insufficient-scopes', headers={'authorization': f"Bearer { token }"})
        json_response = response.get_json()

        self._check_error_response(
            response=response,
            json_response=json_response,
            expected_status=HTTPStatus.FORBIDDEN
        )
        self.assertDictEqual(json_response, expected_payload)
