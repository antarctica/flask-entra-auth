import time
from http import HTTPStatus

from tests.test_base import FlaskOAuthProviderBaseTestCase
from flask_azure_oauth.errors import ApiAuthTokenClaimUntrustedIssuerError, ApiAuthTokenClaimMissingError, \
    ApiAuthTokenClaimInvalidIssuedAt, ApiAuthTokenClaimInvalidNotBefore, ApiAuthTokenClaimInvalidExpiry, \
    ApiAuthTokenClaimInvalidClientApplication, ApiAuthTokenClaimInvalidAudience


class FlaskOAuthProviderJWTTestCase(FlaskOAuthProviderBaseTestCase):
    def test_auth_token_missing_essential_claim(self):
        claims = {
            'aud': {
                'claim': 'aud',
                'name': 'Audience',
                'type': 'standard'
            },
            'exp': {
                'claim': 'exp',
                'name': 'Expires at',
                'type': 'standard'
            },
            'iat': {
                'claim': 'iat',
                'name': 'Issued at',
                'type': 'standard'
            },
            'iss': {
                'claim': 'iss',
                'name': 'Issuer',
                'type': 'standard'
            },
            'nbf': {
                'claim': 'nbf',
                'name': 'Not before',
                'type': 'standard'
            },
            'sub': {
                'claim': 'sub',
                'name': 'Subject',
                'type': 'standard'
            },
            'azp': {
                'claim': 'azp',
                'name': 'Azure client application ID',
                'type': 'custom'
            }
        }

        for claim in claims.values():
            with self.subTest(claim=claim):
                error = ApiAuthTokenClaimMissingError(
                    detail=f"The token payload is missing a required claim: '{ claim['name'] }' ({ claim['claim'] }). "
                    f"Ensure you are using the correct token and try again, or contact support.",
                    meta={
                        'missing_claim': claim
                    }
                )
                expected_payload = self._prepare_expected_error_payload(error)

                # Generate JWT with essential claim removed
                token_payload = {}
                for _claim in claims.keys():
                    if _claim != claim['claim']:
                        token_payload[_claim] = None
                token = self._create_auth_token(payload=token_payload)

                json_response = self._check_token_error_response(token)
                self.assertDictEqual(json_response, expected_payload)

    def test_auth_untrusted_token_issuer(self):
        error = ApiAuthTokenClaimUntrustedIssuerError()
        expected_payload = self._prepare_expected_error_payload(error)

        # Generate JWT
        token_payload = {
            'aud': None,
            'exp': None,
            'iat': None,
            'iss': 'invalid',
            'nbf': None,
            'sub': None,
            'azp': None
        }
        token = self._create_auth_token(payload=token_payload)

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_invalid_token_audience(self):
        error = ApiAuthTokenClaimInvalidAudience()
        expected_payload = self._prepare_expected_error_payload(error)

        # Generate JWT
        token_payload = {
            'aud': 'invalid',
            'exp': None,
            'iat': None,
            'iss': 'https://login.microsoftonline.com/test/v2.0',
            'nbf': None,
            'sub': None,
            'azp': None
        }
        token = self._create_auth_token(payload=token_payload)

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_token_not_yet_issued(self):
        error = ApiAuthTokenClaimInvalidIssuedAt()
        expected_payload = self._prepare_expected_error_payload(error)

        # Generate JWT
        token_payload = {
            'aud': 'test',
            'exp': None,
            'iat': int(time.time() + 10000),
            'iss': 'https://login.microsoftonline.com/test/v2.0',
            'nbf': None,
            'sub': None,
            'azp': None
        }
        token = self._create_auth_token(payload=token_payload)

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_token_not_yet_valid(self):
        error = ApiAuthTokenClaimInvalidNotBefore()
        expected_payload = self._prepare_expected_error_payload(error)

        # Generate JWT
        token_payload = {
            'aud': 'test',
            'exp': None,
            'iat': int(time.time()),
            'iss': 'https://login.microsoftonline.com/test/v2.0',
            'nbf': int(time.time() + 10000),
            'sub': None,
            'azp': None
        }
        token = self._create_auth_token(payload=token_payload)

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_expired_token(self):
        error = ApiAuthTokenClaimInvalidExpiry()
        expected_payload = self._prepare_expected_error_payload(error)

        # Generate JWT
        token_payload = {
            'aud': 'test',
            'exp': int(time.time() - 10000),
            'iat': int(time.time()),
            'iss': 'https://login.microsoftonline.com/test/v2.0',
            'nbf': int(time.time()),
            'sub': None,
            'azp': None
        }
        token = self._create_auth_token(payload=token_payload)

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_untrusted_token_client_application(self):
        error = ApiAuthTokenClaimInvalidClientApplication()
        expected_payload = self._prepare_expected_error_payload(error)

        # Generate JWT
        token_payload = {
            'aud': 'test',
            'exp': int(time.time() + 10000),
            'iat': int(time.time()),
            'iss': 'https://login.microsoftonline.com/test/v2.0',
            'nbf': int(time.time()),
            'sub': None,
            'azp': 'invalid'
        }
        token = self._create_auth_token(payload=token_payload)

        json_response = self._check_token_error_response(token)
        self.assertDictEqual(json_response, expected_payload)

    def test_auth_successful_token(self):
        # Generate JWT
        token_payload = {
            'aud': 'test',
            'exp': int(time.time() + 10000),
            'iat': int(time.time()),
            'iss': 'https://login.microsoftonline.com/test/v2.0',
            'nbf': int(time.time()),
            'sub': None,
            'azp': 'test'
        }
        token = self._create_auth_token(payload=token_payload)

        # Auth introspection used as a stable test endpoint
        response = self.client.get('/meta/auth/introspection', headers={'authorization': f"Bearer {token}"})
        self.assertEqual(HTTPStatus.OK, response.status_code)

    def test_auth_multiple_token_client_applications(self):
        azps = ['test', 'test2']

        for azp in azps:
            with self.subTest(azp=azp):
                # Generate JWT
                token_payload = {
                    'aud': 'test',
                    'exp': int(time.time() + 10000),
                    'iat': int(time.time()),
                    'iss': 'https://login.microsoftonline.com/test/v2.0',
                    'nbf': int(time.time()),
                    'sub': None,
                    'azp': azp
                }
                token = self._create_auth_token(payload=token_payload)

                # Auth introspection used as a stable test endpoint
                response = self.client.get('/meta/auth/introspection', headers={'authorization': f"Bearer {token}"})
                self.assertEqual(response.status_code, HTTPStatus.OK)
