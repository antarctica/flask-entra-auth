import unittest

from tests.test_base import FlaskOAuthProviderBaseTestCase
from flask_azure_oauth.errors import ApiAuthTokenDecodeError, ApiAuthTokenHeaderKidMissingError, \
    ApiAuthTokenKeyUntrustedError, ApiAuthTokenKeyDecodeError, ApiAuthTokenSignatureInvalidError


class FlaskOAuthProviderJWKTestCase(FlaskOAuthProviderBaseTestCase):
    def test_auth_token_decode_error(self):
        error = ApiAuthTokenDecodeError()
        expected_payload = self._prepare_expected_error_payload(error)
        # Exempting Bandit security issue (possible hard-coded password)
        #
        # This is intentional as part of testing
        token = 'invalid-token'  # nosec

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_missing_token_kid_header_field(self):
        error = ApiAuthTokenHeaderKidMissingError()
        expected_payload = self._prepare_expected_error_payload(error)
        token = self._create_auth_token(header={'alg': 'RS256'})

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_untrusted_token_jwk(self):
        error = ApiAuthTokenKeyUntrustedError()
        expected_payload = self._prepare_expected_error_payload(error)
        token = self._create_auth_token()

        # Change the application to remove the trusted JSON Web Key Set and so make any tokens untrusted
        self._change_application_auth('null-jwks')

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_token_signing_key_decode_error(self):
        error = ApiAuthTokenKeyDecodeError()
        expected_payload = self._prepare_expected_error_payload(error)
        token = self._create_auth_token()

        # Change the application to break the trusted JSON Web Key Set and so prevent validating any tokens
        self._change_application_auth('broken-jwks')

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_token_signature_invalid(self):
        error = ApiAuthTokenSignatureInvalidError()
        expected_payload = self._prepare_expected_error_payload(error)
        token = self._create_auth_token()

        # Change the application to replace the JSON Web Key Set and so prevent validating any tokens
        self._change_application_auth('replaced-jwks')

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_restore_jwks(self):
        # Change the application to restore the JSON Web Key Set to a normal state
        self._change_application_auth('restored-jwks')
