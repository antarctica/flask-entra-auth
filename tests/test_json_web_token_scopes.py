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

    def test_auth_sufficient_token_scope_single_role(self):
        token = self._create_auth_token(roles=["scope"])

        response = self.client.get("/meta/auth/sufficient-scope", headers={"authorization": f"Bearer { token }"})

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)

    def test_auth_sufficient_token_scope_single_scps(self):
        token = self._create_auth_token(scps=["scope"])

        response = self.client.get("/meta/auth/sufficient-scope", headers={"authorization": f"Bearer { token }"})

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)

    def test_auth_sufficient_token_scopes_multiple_scps(self):
        token = self._create_auth_token(scps=["scope1", "scope2"])

        response = self.client.get("/meta/auth/sufficient-scopes", headers={"authorization": f"Bearer { token }"})

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)

    def test_auth_sufficient_token_scopes_mixed_roles_scps(self):
        token = self._create_auth_token(roles=["scope1"], scps=["scope2"])

        response = self.client.get("/meta/auth/sufficient-scopes", headers={"authorization": f"Bearer { token }"})

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
