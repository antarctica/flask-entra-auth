from http import HTTPStatus

from flask import Flask, request, jsonify

from flask_azure_oauth import FlaskAzureOauth
from tests.utils import TestJwk, TestFlaskAzureOauth

config = {
    "AZURE_OAUTH_TENANCY": "test",
    "AZURE_OAUTH_APPLICATION_ID": "test",
    "AZURE_OAUTH_CLIENT_APPLICATION_IDS": ["test", "test2"],
    "TEST_JWKS": TestJwk(),
}

auth = FlaskAzureOauth()


def create_app():
    app = Flask(__name__)

    # Configure and load provider
    app.config["AZURE_OAUTH_TENANCY"] = config["AZURE_OAUTH_TENANCY"]
    app.config["AZURE_OAUTH_APPLICATION_ID"] = config["AZURE_OAUTH_APPLICATION_ID"]
    app.config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"] = config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"]
    auth.init_app(app)

    @app.route("/meta/auth/introspection")
    @auth()
    def meta_auth_introspection():
        authorization_header = request.headers.get("authorization")
        token_string = authorization_header.split("Bearer ")[1]

        payload = {"data": {"token": auth.introspect_token(token_string=token_string), "token-string": token_string}}

        return jsonify(payload)

    return app


def create_test_app(**kwargs):
    app = Flask(__name__)
    app.config["AZURE_OAUTH_TENANCY"] = config["AZURE_OAUTH_TENANCY"]
    app.config["AZURE_OAUTH_APPLICATION_ID"] = config["AZURE_OAUTH_APPLICATION_ID"]
    app.config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"] = config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"]
    app.config["TEST_JWKS"] = config["TEST_JWKS"]

    app.auth = TestFlaskAzureOauth(
        azure_tenancy_id=app.config["AZURE_OAUTH_TENANCY"],
        azure_application_id=app.config["AZURE_OAUTH_APPLICATION_ID"],
        azure_client_application_ids=app.config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"],
        azure_jwks=app.config["TEST_JWKS"].jwks(),
    )

    # Support invalid ways of setting up the auth provider when testing
    if "AUTH_MODE" in kwargs:
        if kwargs["AUTH_MODE"] == "null-jwks":
            app.auth.use_null_jwks()
        elif kwargs["AUTH_MODE"] == "broken-jwks":
            app.auth.use_broken_jwks()
        elif kwargs["AUTH_MODE"] == "replaced-jwks":
            app.auth.use_replaced_jwks()
        elif kwargs["AUTH_MODE"] == "restored-jwks":
            app.auth.use_restored_jwks()

    @app.route("/meta/auth/introspection")
    @app.auth()
    def meta_auth_introspection():
        authorization_header = request.headers.get("authorization")
        token_string = authorization_header.split("Bearer ")[1]

        payload = {
            "data": {
                "token": app.auth.introspect_token(token_string=token_string),
                "token-rfc7662": app.auth.introspect_token_rfc7662(token_string=token_string),
                "token-string": token_string,
            }
        }

        return jsonify(payload)

    @app.route("/meta/auth/insufficient-scopes")
    @app.auth("unobtainable-scope")
    def meta_auth_insufficient_scopes():
        """
        Simulates a resource a client doesn't have access to due to not having the correct scopes.

        In practice it is impossible to access this resource.
        """
        return "", HTTPStatus.NO_CONTENT

    @app.route("/meta/auth/sufficient-scope")
    @app.auth("scope")
    def meta_auth_sufficient_scope():
        """
        Simulates a resource a client has access to by having the correct scope.
        """
        return "", HTTPStatus.NO_CONTENT

    @app.route("/meta/auth/sufficient-scopes")
    @app.auth("scope1 scope2")
    def meta_auth_sufficient_scopes():
        """
        Simulates a resource a client has access to by having the correct scopes.
        """
        return "", HTTPStatus.NO_CONTENT

    return app
