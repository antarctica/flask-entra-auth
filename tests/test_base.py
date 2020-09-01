import unittest

from http import HTTPStatus

# noinspection PyPackageRequirements
from werkzeug.wrappers import Response

from flask import Response

from tests.utils import TestJwt, create_app
from flask_azure_oauth.errors import ApiAuthError


class FlaskOAuthProviderBaseTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

        self.maxDiff = None

    def tearDown(self):
        self.app_context.pop()

    @staticmethod
    def _prepare_expected_error_payload(error: ApiAuthError):
        error = error.dict()
        # Overwrite dynamic error ID with static value to allow comparision
        error["id"] = "a611b89f-f1bb-43c5-8efa-913c83c9109e"

        return {"errors": [error]}

    def _check_error_response(self, *, response: Response, json_response: dict, expected_status: HTTPStatus):
        self.assertEqual(response.status_code, expected_status)
        self.assertIn("errors", json_response.keys())
        self.assertEqual(len(json_response["errors"]), 1)

        # Overwrite dynamic error ID with static value to allow comparision
        if "id" in json_response["errors"][0].keys():
            json_response["errors"][0]["id"] = "a611b89f-f1bb-43c5-8efa-913c83c9109e"

    def _check_token_error_response(self, token: str):
        # Auth introspection used as a stable test endpoint
        response = self.client.get("/meta/auth/introspection", headers={"authorization": f"Bearer { token }"})
        json_response = response.get_json()

        self._check_error_response(
            response=response, json_response=json_response, expected_status=HTTPStatus.UNAUTHORIZED
        )

        return json_response

    def _create_auth_token(self, header: dict = None, payload: dict = None, roles: list = None, scps: list = None):
        jwt = TestJwt(
            app=self.app,
            header=header,
            payload=payload,
            roles=roles,
            scps=scps,
            signing_key=self.app.config["TEST_JWKS"],
        )
        return jwt.dumps()

    def _change_application_auth(self, **kwargs):
        self.app_context.pop()

        self.app = create_app(**kwargs)

        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
