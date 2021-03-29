from uuid import uuid4

import click
from authlib.integrations.flask_oauth2 import current_token

from flask import Flask, current_app, session, request
from msal import PublicClientApplication, ConfidentialClientApplication

from flask_azure_oauth import FlaskAzureOauth


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "TPZHP2Ljw82CSXR5BjjfoQ"

    ## Note: If changing between config sets, make sure to update required scopes in routes as well

    ## Config options for 'Flask Azure OAuth Provider - Example App 1' (version 1.0 tokens)
    # app.config["AZURE_OAUTH_TENANCY"] = "d14c529b-5558-4a80-93b6-7655681e55d6"
    # app.config["AZURE_OAUTH_APPLICATION_ID"] = "be76d0cc-26ab-4c07-8bae-ed544224078f"
    # app.config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"] = ["da553d65-9dca-4393-a604-875addd10f13"]
    # app.config["AUTH_CLIENT_ID"] = "da553d65-9dca-4393-a604-875addd10f13"
    # app.config["AUTH_CLIENT_TENANCY"] = "https://login.microsoftonline.com/d14c529b-5558-4a80-93b6-7655681e55d6"
    # app.config["AUTH_CLIENT_SCOPES"] = [
    #     "api://be76d0cc-26ab-4c07-8bae-ed544224078f/BAS.WSF.FlaskOAuthProvider.Examples.Example1.Access"
    # ]

    ## Config options for 'Flask Azure OAuth Provider - Example App 2' (version 2.0 tokens)
    app.config["AZURE_OAUTH_TENANCY"] = "d14c529b-5558-4a80-93b6-7655681e55d6"
    app.config["AZURE_OAUTH_APPLICATION_ID"] = "de40e653-e63b-46e3-80f6-52a39f055bf3"
    app.config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"] = ["c5134fdc-f69a-4b80-ad55-66c4d6e5a2b0"]
    app.config["AUTH_CLIENT_ID"] = "c5134fdc-f69a-4b80-ad55-66c4d6e5a2b0"
    app.config["AUTH_CLIENT_SECRET"] = "yq__4pGnY4RQ.Z3w~g_~ZFBF09S_07ergR"
    app.config["AUTH_CLIENT_TENANCY"] = "https://login.microsoftonline.com/d14c529b-5558-4a80-93b6-7655681e55d6"
    app.config["AUTH_CLIENT_SCOPES"] = [
        "api://de40e653-e63b-46e3-80f6-52a39f055bf3/BAS.WSF.FlaskOAuthProvider.Examples.Example2.Access"
    ]

    app.auth = FlaskAzureOauth()
    app.auth.init_app(app)

    @app.route("/auth/sign-in")
    def auth_sign_in():
        session["state"] = str(uuid4())
        auth_url = ConfidentialClientApplication(
            app.config["AUTH_CLIENT_ID"],
            authority=current_app.config["AUTH_CLIENT_TENANCY"],
            client_credential=app.config["AUTH_CLIENT_SECRET"],
        ).get_authorization_request_url(
            scopes=current_app.config["AUTH_CLIENT_SCOPES"],
            state=session.get("state"),
            redirect_uri="http://localhost:9000/auth/callback",
        )
        return f'<a href="{auth_url}">Click to Login</a>.'

    @app.route("/auth/callback")
    def auth_callback():
        if request.args.get("state") != session.get("state"):
            return "Sign-in failed, state doesn't match.", 403
        if request.args.get("error"):
            return request.args.get("error"), 403
        if not request.args.get("code"):
            return "Sign-in failed, no auth code.", 403

        result = ConfidentialClientApplication(
            app.config["AUTH_CLIENT_ID"],
            authority=current_app.config["AUTH_CLIENT_TENANCY"],
            client_credential=app.config["AUTH_CLIENT_SECRET"],
        ).acquire_token_by_authorization_code(
            code=request.args.get("code"),
            scopes=current_app.config["AUTH_CLIENT_SCOPES"],
            redirect_uri="http://localhost:9000/auth/callback",
        )
        if result.get("error"):
            return "Sign-in failed.", 403
        if not result.get("access_token"):
            return "Sign-in failed, no access token.", 403

        session["access_token"] = result.get("access_token")
        return "Signed-in"

    @app.route("/unprotected")
    def unprotected():
        return "Unprotected resource."

    @app.route("/protected")
    @app.auth()
    def protected():
        return "Protected resource."

    @app.route("/protected-with-single-scope")
    # @app.auth("BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope1")
    @app.auth("BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope1")
    def protected_with_scope():
        return "Protected resource requiring single scope."

    @app.route("/protected-with-multiple-scopes")
    # @app.auth("BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope1 BAS.WSF.FlaskOAuthProvider.Examples.Example1.Scope2")
    @app.auth("BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope1 BAS.WSF.FlaskOAuthProvider.Examples.Example2.Scope2")
    def protected_with_multiple_scopes():
        return "Protected resource requiring multiple scopes."

    @app.route("/introspection")
    @app.auth()
    def introspection():
        return current_token.introspect()

    @app.route("/claims")
    @app.auth()
    def claims():
        return current_token.claims

    @app.cli.command("access-resource")
    @click.argument(
        "resource",
        type=click.Choice(
            [
                "unprotected",
                "protected",
                "protected-with-single-scope",
                "protected-with-multiple-scopes",
                "introspection",
                "claims",
            ]
        ),
    )
    @click.option("-t", "--access-token")
    def access_resource(resource, access_token):
        """Simulates a user requesting a resource"""
        if access_token is not None:
            current_app.config["AUTH_TOKEN"] = access_token
        if resource != "unprotected" and "AUTH_TOKEN" not in current_app.config:
            _get_token()

        client_headers = {}
        if "AUTH_TOKEN" in current_app.config:
            client_headers["Authorization"] = f"Bearer {current_app.config['AUTH_TOKEN']}"
        client = current_app.test_client()

        response = client.get(f"/{resource}", headers=client_headers)
        click.echo(f"Response status code: {response.status_code}")
        click.echo(f"Response data: {response.data.decode()}")

    def _get_token():
        auth_client = PublicClientApplication(
            client_id=current_app.config["AUTH_CLIENT_ID"], authority=current_app.config["AUTH_CLIENT_TENANCY"]
        )
        auth_flow = auth_client.initiate_device_flow(scopes=current_app.config["AUTH_CLIENT_SCOPES"])
        click.pause(
            f"To sign-in, visit 'https://microsoft.com/devicelogin', enter this code '{auth_flow['user_code']}' and then press any key..."
        )
        auth_payload = auth_client.acquire_token_by_device_flow(auth_flow)
        current_app.config["AUTH_TOKEN"] = auth_payload["access_token"]
        click.echo(current_app.config["AUTH_TOKEN"])
        click.echo(f"Ok. Access token set.")

    return app
