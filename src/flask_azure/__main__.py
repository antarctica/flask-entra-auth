from __future__ import annotations

from flask import Flask, request

from flask_azure.entra_exceptions import EntraAuthError
from flask_azure.entra_protector import FlaskEntraAuth
from flask_azure.entra_token import EntraToken

auth = FlaskEntraAuth()

app = Flask(__name__)
app.json.sort_keys = False
app.config["auth_client_id"] = "8b45581e-1b2e-4b8c-b667-e5a1360b6906"
app.config["auth_oidc_endpoint"] = (
    "https://login.microsoftonline.com/b311db95-32ad-438f-a101-7ba061712a4e/v2.0/.well-known/openid-configuration"
)
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


@app.route("/restricted/scope", methods=["POST"])
@app.auth(["BAS.MAGIC.ADD.Access"])
def restricted_scope() -> str:
    """Closed route (authenticated and authorised with single required scope)."""
    return "Restricted route with required scope."


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
            oidc_endpoint=app.config["auth_oidc_endpoint"],
            client_id=app.config["auth_client_id"],
        )
        return token.rfc7662_introspection  # noqa: TRY300
    except EntraAuthError as e:
        return {"error": str(e)}, 400
