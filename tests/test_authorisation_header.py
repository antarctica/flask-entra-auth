from http import HTTPStatus

from tests.test_base import FlaskOAuthProviderBaseTestCase
from flask_azure_oauth.errors import ApiAuthAuthorizationMissingError, \
    ApiAuthTokenTypeUnsupportedError


class FlaskOAuthProviderAuthorisationHeaderTestCase(FlaskOAuthProviderBaseTestCase):
    def test_auth_missing_authorization_header(self):
        error = ApiAuthAuthorizationMissingError()
        expected_payload = self._prepare_expected_error_payload(error)

        # Auth introspection used as a stable test endpoint
        response = self.client.get('/meta/auth/introspection')
        json_response = response.get_json()

        self._check_error_response(
            response=response,
            json_response=json_response,
            expected_status=HTTPStatus.UNAUTHORIZED
        )
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_unsupported_token_type(self):
        error = ApiAuthTokenTypeUnsupportedError()
        expected_payload = self._prepare_expected_error_payload(error)

        # Auth introspection used as a stable test endpoint
        response = self.client.get('/meta/auth/introspection', headers={'authorization': 'invalid-token-type'})
        json_response = response.get_json()

        self._check_error_response(
            response=response,
            json_response=json_response,
            expected_status=HTTPStatus.UNAUTHORIZED
        )
        self.assertDictEqual(json_response, expected_payload)
