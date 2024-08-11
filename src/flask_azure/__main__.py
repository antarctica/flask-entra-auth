from __future__ import annotations

from flask import Flask, request

from flask_azure.entra_exceptions import EntraAuthError
from flask_azure.entra_protector import FlaskEntraAuth
from flask_azure.entra_token import EntraToken

auth = FlaskEntraAuth()

app = Flask(__name__)
app.json.sort_keys = False
app.config["ENTRA_AUTH_CLIENT_ID"] = "8b45581e-1b2e-4b8c-b667-e5a1360b6906"
app.config["ENTRA_AUTH_OIDC_ENDPOINT"] = (
    "https://login.microsoftonline.com/b311db95-32ad-438f-a101-7ba061712a4e/v2.0/.well-known/openid-configuration"
)
app.config["ENTRA_AUTH_ALLOWED_SUBJECTS"] = []
app.config["ENTRA_AUTH_ALLOWED_APPS"] = []
auth.init_app(app)


@app.route("/unrestricted", methods=["POST"])
def unrestricted() -> str:
    """Open route."""
    return "Unrestricted route."


@app.route("/restricted", methods=["POST"])
@app.auth()
def restricted() -> str:
    """Closed route (authenticated)."""
    return "Restricted route."


@app.route("/restricted/scopes/scps-and", methods=["POST"])
@app.auth(["SCOPE_A SCOPE_B"])
def restricted_scps_and() -> str:
    """Closed route (authenticated and authorised with multiple required scps, logical AND)."""
    return "Restricted route, you have (SCOPE_A && SCOPE_B)."


@app.route("/restricted/scopes/scps-or", methods=["POST"])
@app.auth(["SCOPE_A", "SCOPE_B"])
def restricted_scps_or() -> str:
    """Closed route (authenticated and authorised with multiple required scps, logical OR)."""
    return "Restricted route, you have (SCOPE_A || SCOPE_B)."


@app.route("/restricted/scopes/scps-and-or", methods=["POST"])
@app.auth(["SCOPE_A SCOPE_C", "SCOPE_B SCOPE_C"])
def restricted_scps_and_or() -> str:
    """Closed route (authenticated and authorised with multiple required scps, logical OR & AND)."""
    return "Restricted route, you have ((SCOPE_A && SCOPE_C) || (SCOPE_B && SCOPE_C))."


@app.route("/restricted/scopes/roles-and", methods=["POST"])
@app.auth(["ROLE_1 ROLE_2"])
def restricted_routes_and() -> str:
    """Closed route (authenticated and authorised with multiple required roles, logical AND)."""
    return "Restricted route, you have (ROLE_1 && ROLE_2)."


@app.route("/restricted/scopes/roles-or", methods=["POST"])
@app.auth(["ROLE_1", "ROLE_2"])
def restricted_routes_or() -> str:
    """Closed route (authenticated and authorised with multiple required roles, logical OR)."""
    return "Restricted route, you have (ROLE_1 || ROLE_2)."


@app.route("/restricted/scopes/roles-and-or", methods=["POST"])
@app.auth(["ROLE_1 ROLE_3", "ROLE_2 ROLE_3"])
def restricted_routes_and_or() -> str:
    """Closed route (authenticated and authorised with multiple required roles, logical OR & AND)."""
    return "Restricted route, you have ((ROLE_1 && ROLE_3) || (ROLE_2 && ROLE_3))."


@app.route("/restricted/scopes/scopes-and", methods=["POST"])
@app.auth(["SCOPE_A ROLE_1"])
def restricted_scopes_and() -> str:
    """Closed route (authenticated and authorised with multiple required scopes, logical AND)."""
    return "Restricted route, you have (SCOPE_A && ROLE_1)."


@app.route("/restricted/scopes/scopes-or", methods=["POST"])
@app.auth(["SCOPE_A", "ROLE_1"])
def restricted_scopes_or() -> str:
    """Closed route (authenticated and authorised with multiple required scopes, logical OR)."""
    return "Restricted route, you have (SCOPE_A || ROLE_1)."


@app.route("/restricted/scopes/scopes-and-or", methods=["POST"])
@app.auth(["SCOPE_A SCOPE_C ROLE_1 ROLE_3", "SCOPE_B SCOPE_C ROLE_2 ROLE_3"])
def restricted_scopes_and_or() -> str:
    """Closed route (authenticated and authorised with multiple required scopes, logical OR & AND)."""
    return "Restricted route, you have ((SCOPE_A && SCOPE_C && ROLE_1 && ROLE_3) || (SCOPE_B && SCOPE_C && ROLE_2 && ROLE_3))."


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
            oidc_endpoint=app.config['ENTRA_AUTH_OIDC_ENDPOINT'],
            client_id=app.config['ENTRA_AUTH_CLIENT_ID'],
        )
        return token.rfc7662_introspection  # noqa: TRY300
    except EntraAuthError as e:
        return {"error": str(e)}, 400
