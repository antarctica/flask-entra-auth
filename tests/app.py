from __future__ import annotations

from flask import Flask, request

from flask_entra_auth.exceptions import EntraAuthError
from flask_entra_auth.resource_protector import FlaskEntraAuth
from flask_entra_auth.token import EntraToken

auth = FlaskEntraAuth()


def create_app(  # noqa: C901
    client_id: str, oidc_endpoint: str, allowed_subjects: list[str] | None = None, allowed_apps: list[str] | None = None
) -> Flask:
    """Create Flask app."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["ENTRA_AUTH_CLIENT_ID"] = client_id
    app.config["ENTRA_AUTH_OIDC_ENDPOINT"] = oidc_endpoint
    app.config["ENTRA_AUTH_ALLOWED_SUBJECTS"] = allowed_subjects or []
    app.config["ENTRA_AUTH_ALLOWED_APPS"] = allowed_apps or []
    auth.init_app(app)

    @app.route("/unrestricted")
    def unrestricted() -> str:
        """Open route."""
        return "Unrestricted route."

    @app.route("/restricted")
    @app.auth()
    def restricted() -> str:
        """Closed route (authenticated)."""
        return "Restricted route."

    @app.route("/restricted/scopes/scps-and")
    @app.auth(["SCOPE_A SCOPE_B"])
    def restricted_scps_and() -> str:
        """Closed route (authenticated and authorised with multiple required scps, logical AND)."""
        return "Restricted route, you have (SCOPE_A && SCOPE_B)."

    @app.route("/restricted/scopes/scps-or")
    @app.auth(["SCOPE_A", "SCOPE_B"])
    def restricted_scps_or() -> str:
        """Closed route (authenticated and authorised with multiple required scps, logical OR)."""
        return "Restricted route, you have (SCOPE_A || SCOPE_B)."

    @app.route("/restricted/scopes/scps-and-or")
    @app.auth(["SCOPE_A SCOPE_C", "SCOPE_B SCOPE_C"])
    def restricted_scps_and_or() -> str:
        """Closed route (authenticated and authorised with multiple required scps, logical OR & AND)."""
        return "Restricted route, you have ((SCOPE_A && SCOPE_C) || (SCOPE_B && SCOPE_C))."

    @app.route("/restricted/scopes/roles-and")
    @app.auth(["ROLE_1 ROLE_2"])
    def restricted_routes_and() -> str:
        """Closed route (authenticated and authorised with multiple required roles, logical AND)."""
        return "Restricted route, you have (ROLE_1 && ROLE_2)."

    @app.route("/restricted/scopes/roles-or")
    @app.auth(["ROLE_1", "ROLE_2"])
    def restricted_routes_or() -> str:
        """Closed route (authenticated and authorised with multiple required roles, logical OR)."""
        return "Restricted route, you have (ROLE_1 || ROLE_2)."

    @app.route("/restricted/scopes/roles-and-or")
    @app.auth(["ROLE_1 ROLE_3", "ROLE_2 ROLE_3"])
    def restricted_routes_and_or() -> str:
        """Closed route (authenticated and authorised with multiple required roles, logical OR & AND)."""
        return "Restricted route, you have ((ROLE_1 && ROLE_3) || (ROLE_2 && ROLE_3))."

    @app.route("/restricted/scopes/scopes-and")
    @app.auth(["SCOPE_A ROLE_1"])
    def restricted_scopes_and() -> str:
        """Closed route (authenticated and authorised with multiple required scopes, logical AND)."""
        return "Restricted route, you have (SCOPE_A && ROLE_1)."

    @app.route("/restricted/scopes/scopes-or")
    @app.auth(["SCOPE_A", "ROLE_1"])
    def restricted_scopes_or() -> str:
        """Closed route (authenticated and authorised with multiple required scopes, logical OR)."""
        return "Restricted route, you have (SCOPE_A || ROLE_1)."

    @app.route("/restricted/scopes/scopes-and-or")
    @app.auth(["SCOPE_A SCOPE_C ROLE_1 ROLE_3", "SCOPE_B SCOPE_C ROLE_2 ROLE_3"])
    def restricted_scopes_and_or() -> str:
        """Closed route (authenticated and authorised with multiple required scopes, logical OR & AND)."""
        return (
            "Restricted route, you have "
            "((SCOPE_A && SCOPE_C && ROLE_1 && ROLE_3) || (SCOPE_B && SCOPE_C && ROLE_2 && ROLE_3))."
        )

    @app.route("/restricted/current-token", methods=["GET"])
    @app.auth()
    def restricted_current_token() -> dict:
        """Closed route (authenticated)."""
        token: EntraToken = app.auth.current_token
        return {"claims": token.claims}

    @app.route("/introspect", methods=["POST"])
    def introspect_rfc7662() -> dict | tuple:
        """
        Token introspection as per RFC7662.

        See https://tools.ietf.org/html/rfc7662 for details of required request and response.

        Note that:
        - the RFC requires the introspection endpoint is authenticated
            - this isn't implemented as it doesn't make sense to have another authentication method
        - the optional `jti` response property isn't included as Entra doesn't include this claim in tokens
        """
        try:
            token = EntraToken(
                token=request.form.get("token"),
                oidc_endpoint=app.config["ENTRA_AUTH_OIDC_ENDPOINT"],
                client_id=app.config["ENTRA_AUTH_CLIENT_ID"],
            )
            return token.rfc7662_introspection  # noqa: TRY300
        except EntraAuthError as e:
            return {"error": str(e)}, e.problem.status

    return app
