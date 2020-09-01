import unittest

from http import HTTPStatus
from unittest.mock import patch

from flask_azure_oauth import FlaskAzureOauth
from flask_azure_oauth.mocks.keys import TestJwk
from flask_azure_oauth.mocks.tokens import TestJwt

from examples import create_app


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.test_jwks = TestJwk()

        with patch.object(FlaskAzureOauth, "_get_jwks") as mocked_get_jwks:
            mocked_get_jwks.return_value = self.test_jwks.jwks()

            # `self.app` should be set to a Flask application, either by direct import, or by calling an app factory
            self.app = create_app()

            self.app.config["TEST_JWKS"] = self.test_jwks
            self.app_context = self.app.app_context()
            self.app_context.push()
            self.client = self.app.test_client()

    def test_protected_route_with_multiple_scopes_authorised(self):
        # Generate token with required roles
        token = TestJwt(
            app=self.app, roles=["BAS.MAGIC.ADD.Records.Publish.All", "BAS.MAGIC.ADD.Records.ReadWrite.All"]
        )

        # Make request to protected route with token
        response = self.client.get(
            "/protected-with-multiple-scopes", headers={"authorization": f"bearer { token.dumps() }"}
        )
        self.assertEqual(HTTPStatus.OK, response.status_code)
        self.app_context.pop()

    def test_protected_route_with_multiple_scopes_unauthorised(self):
        # Generate token with no scopes
        token = TestJwt(app=self.app)

        # Make request to protected route with token
        response = self.client.get(
            "/protected-with-multiple-scopes", headers={"authorization": f"bearer { token.dumps() }"}
        )
        self.assertEqual(HTTPStatus.FORBIDDEN, response.status_code)
        self.app_context.pop()
