from flask import Flask, request

from flask_azure.entra_token import EntraToken, EntraTokenError

app = Flask(__name__)
app.json.sort_keys = False

app.config["client_id"] = "8b45581e-1b2e-4b8c-b667-e5a1360b6906"
app.config["oidc_endpoint"] = (
    "https://login.microsoftonline.com/b311db95-32ad-438f-a101-7ba061712a4e/v2.0/.well-known/openid-configuration"
)


def get_token(token: str) -> EntraToken:
    return EntraToken(token, app.config["oidc_endpoint"], app.config["client_id"])


@app.route("/unrestricted", methods=["POST"])
def unrestricted():
    return "Unrestricted route"


@app.route("/restricted", methods=["POST"])
def restricted():
    # return 403 error if no Authorization header is present
    return "", 403


@app.route("/introspect")
def introspect_rfc7662():
    # required introspection method authentication is ignored
    # optional `jti` introspection member is ignored as Entra doesn't support this so can't be provided

    try:
        token = get_token(token=request.form.get("token"))
        return token.rfc7662_introspection
    except EntraTokenError as e:
        return {"error": str(e)}, 400
