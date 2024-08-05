import jwt
import requests
from flask import Flask, request

app = Flask(__name__)
app.json.sort_keys = False

app.config["client_id"] = "8b45581e-1b2e-4b8c-b667-e5a1360b6906"
app.config["oidc_endpoint"] = (
    "https://login.microsoftonline.com/b311db95-32ad-438f-a101-7ba061712a4e/v2.0/.well-known/openid-configuration"
)


def validate_token(token: str):
    oidc_req = requests.get(app.config["oidc_endpoint"])
    oidc_req.raise_for_status()
    oidc_config = oidc_req.json()

    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])
    public_key = jwks_client.get_signing_key_from_jwt(token)

    return jwt.decode(
        jwt=token,
        key=public_key,
        algorithms=["RS256"],
        audience=app.config["client_id"],
    )


@app.route("/unrestricted", methods=["POST"])
def unrestricted():
    return "Unrestricted route"


@app.route("/restricted", methods=["POST"])
def restricted():
    # return 403 error if no Authorization header is present
    return "", 403


@app.route("/introspect")
def introspect():
    if "Authorization" not in request.headers:
        return {"headers": dict(request.headers)}
    if "Bearer" not in request.headers.get("Authorization"):
        return {"auth": request.headers.get("Authorization")}

    payload = {
        "token": request.headers.get("Authorization").split(" ")[1],
        "token_decoded": {},
        "token_valid": False,
        "token_error": "unknown",
    }
    try:
        payload["token_decoded"] = validate_token(payload["token"])
        payload["token_valid"] = True
        payload["token_error"] = "-"
    except jwt.exceptions.ExpiredSignatureError:
        payload["token_error"] = "expired"
    except jwt.exceptions.InvalidAudienceError:
        payload["token_error"] = "invalid audience"

    if not payload["token_valid"]:
        payload["token_decoded_invalid"] = jwt.decode(
            payload["token_raw"], options={"verify_signature": False}
        )

    selected_claims = ["email", "family_name", "given_name", "name", "roles"]
    claims = (
        payload["token_decoded"]
        if payload["token_valid"]
        else payload["token_decoded_invalid"]
    )
    payload["selected_claims"] = {claim: claims.get(claim) for claim in selected_claims}

    if "selected-only" in request.args:
        return {
            "token_valid": payload["token_valid"],
            "selected_claims": payload["selected_claims"],
        }

    return payload
