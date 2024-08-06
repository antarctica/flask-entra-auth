from __future__ import annotations

from typing import TypedDict, Union

import jwt
import requests
from flask import Flask, request

app = Flask(__name__)
app.json.sort_keys = False

app.config["client_id"] = "8b45581e-1b2e-4b8c-b667-e5a1360b6906"
app.config["oidc_endpoint"] = (
    "https://login.microsoftonline.com/b311db95-32ad-438f-a101-7ba061712a4e/v2.0/.well-known/openid-configuration"
)


class EntraTokenSubjectNotAllowedError(Exception):
    pass


class EntraTokenClientAppNotAllowedError(Exception):
    pass


class EntraTokenVersionNotAllowedError(Exception):
    pass


class EntraTokenClaims(TypedDict):
    aud: str
    iss: str
    iat: int
    nbf: int
    exp: int
    aio: str
    azp: str
    azpacr: str
    email: str
    family_name: str
    given_name: str
    name: str
    oid: str
    preferred_username: str
    rh: str
    roles: list[str]
    scp: str
    sub: str
    tid: str
    uti: str
    ver: str


def validate_token(
    token: str,
    leeway: float = 0,
    allowed_subs: list | None = None,
    allowed_azps: list | None = None,
) -> EntraTokenClaims:
    required_claims = [
        "iss",  # issuer - who issued the token - checked by default
        "sub",  # subject - who the token was issued to - additionally checked by `allowed_subs` list
        "aud",  # audience - who the token was intended for - checked by default
        "exp",  # expiration - when the token is valid to - checked by default
        "nbf",  # not before - when the token is valid from - ?
        "azp",  # Azure client applications - the client application - additionally checked by `allowed_azps` list
        "ver",  # version - the version of the token - additionally checked, must be '2.0'
    ]

    oidc_req = requests.get(app.config["oidc_endpoint"])
    oidc_req.raise_for_status()
    oidc_config = oidc_req.json()

    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])
    public_key = jwks_client.get_signing_key_from_jwt(token)
    issuer = oidc_config["issuer"]

    claims: EntraTokenClaims = jwt.decode(
        jwt=token,
        key=public_key,
        algorithms=["RS256"],
        audience=app.config["client_id"],
        issuer=issuer,
        leeway=leeway,
        options={"require": required_claims},
    )

    if claims["ver"] != "2.0":
        raise EntraTokenVersionNotAllowedError(f"Version '{claims['ver']}' not allowed")

    if allowed_subs:
        if claims["sub"] not in allowed_subs:
            raise EntraTokenSubjectNotAllowedError(
                f"Subject '{claims['sub']}' not allowed"
            )

    if allowed_azps:
        if claims["azp"] not in allowed_azps:
            raise EntraTokenClientAppNotAllowedError(
                f"Azure client app '{claims['azp']}' not allowed"
            )

    return claims


@app.route("/unrestricted", methods=["POST"])
def unrestricted():
    return "Unrestricted route"


@app.route("/restricted", methods=["POST"])
def restricted():
    # return 403 error if no Authorization header is present
    return "", 403


@app.route("/introspect")
def introspect():
    payload = {"token_valid": False}
    status = 401

    if "Authorization" not in request.headers:
        return {**payload, "headers": dict(request.headers)}
    if "Bearer" not in request.headers.get("Authorization"):
        return {**payload, "auth": request.headers.get("Authorization")}

    payload["token"] = request.headers.get("Authorization").split(" ")[1]
    token_decoded: Union[EntraTokenClaims, dict] = {}
    payload["token_decoded"]: token_decoded
    payload["token_valid"] = False
    payload["token_error"] = "unknown"

    try:
        payload["token_decoded"] = validate_token(payload["token"])
        payload["token_valid"] = True
        payload["token_error"] = "-"
        status = 200
    except jwt.exceptions.ExpiredSignatureError:
        payload["token_error"] = "expired"
    except jwt.exceptions.InvalidAudienceError:
        payload["token_error"] = "invalid audience"

    if not payload["token_valid"]:
        payload["token_decoded_invalid"] = jwt.decode(
            payload["token"], options={"verify_signature": False}
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
            **payload,
            "selected_claims": payload["selected_claims"],
        }

    return payload, status
