import jwt
from flask import Flask, request

app = Flask(__name__)
app.json.sort_keys = False


@app.route("/unrestricted", methods=["POST"])
def unrestricted():
    return "Unrestricted route"


@app.route("/restricted", methods=["POST"])
def restricted():
    # return 403 error if no Authorization header is present
    return "", 403


@app.route("/introspect")
def introspect():
    payload = {"headers": dict(request.headers)}

    if "Authorization" not in request.headers:
        return payload

    payload["auth"] = request.headers.get("Authorization")

    if "Bearer" not in request.headers.get("Authorization"):
        return payload

    payload["token_raw"] = request.headers.get("Authorization").split(" ")[1]
    payload["token_decoded"] = jwt.decode(
        payload["token_raw"], options={"verify_signature": False}
    )

    selected_claims = ["email", "family_name", "given_name", "name", "roles"]
    payload["selected_claims"] = {
        claim: payload["token_decoded"].get(claim) for claim in selected_claims
    }

    if "selected-only" in request.args:
        return {"selected_claims": payload["selected_claims"]}

    return payload
