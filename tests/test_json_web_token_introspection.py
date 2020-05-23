from http import HTTPStatus

from flask_azure_oauth.tokens import TestJwt
from tests.test_base import FlaskOAuthProviderBaseTestCase


class FlaskOAuthProviderJWTIntrospectionTestCase(FlaskOAuthProviderBaseTestCase):
    def test_auth_token_introspection(self):
        token = TestJwt(app=self.app, roles=["scope1"], scps=["scope2"])
        token_string = token.dumps()

        expected_payload = {
            "data": {
                "token": {
                    "header": {"alg": "RS256", "kid": "test-GquI77x", "typ": "JWT"},
                    "payload": {
                        "aud": {"claim": "aud", "name": "Audience", "type": "standard", "value": "test"},
                        "azp": {
                            "claim": "azp",
                            "name": "Azure client application ID",
                            "type": "custom",
                            "value": "test",
                        },
                        "exp": {
                            "claim": "exp",
                            "name": "Expires at",
                            "type": "standard",
                            "value": 1587383954,
                            "value_iso_8601": "2020-04-20T11:59:14",
                        },
                        "iat": {
                            "claim": "iat",
                            "name": "Issued at",
                            "type": "standard",
                            "value": 1587373954,
                            "value_iso_8601": "2020-04-20T09:12:34",
                        },
                        "iss": {
                            "claim": "iss",
                            "name": "Issuer",
                            "type": "standard",
                            "value": "https://login.microsoftonline.com/test/v2.0",
                        },
                        "nbf": {
                            "claim": "nbf",
                            "name": "Not before",
                            "type": "standard",
                            "value": 1587373954,
                            "value_iso_8601": "2020-04-20T09:12:34",
                        },
                        "sub": {"claim": "sub", "name": "Subject", "type": "standard", "value": None},
                    },
                    "scopes": ["scope1", "scope2"],
                },
                "token-rfc7662": {
                    "active": True,
                    "aud": "test",
                    "client_id": "test",
                    "exp": 1587383954,
                    "iat": 1587373954,
                    "iss": "https://login.microsoftonline.com/test/v2.0",
                    "nbf": 1587373954,
                    "scope": "scope1 scope2",
                    "sub": None,
                    "token_type": "JWT",
                },
                "token-string": token_string,
            }
        }

        response = self.client.get("/meta/auth/introspection", headers={"authorization": f"Bearer {token_string}"})
        json_response = response.get_json()

        # Overwrite dynamic properties with static value to allow comparision
        if "data" in json_response:
            if "token" in json_response["data"]:
                if "header" in json_response["data"]["token"]:
                    if "kid" in json_response["data"]["token"]["header"]:
                        json_response["data"]["token"]["header"]["kid"] = expected_payload["data"]["token"]["header"][
                            "kid"
                        ]
                if "payload" in json_response["data"]["token"]:
                    if "exp" in json_response["data"]["token"]["payload"]:
                        if "value" in json_response["data"]["token"]["payload"]["exp"]:
                            json_response["data"]["token"]["payload"]["exp"]["value"] = expected_payload["data"][
                                "token"
                            ]["payload"]["exp"]["value"]
                        if "value_iso_8601" in json_response["data"]["token"]["payload"]["exp"]:
                            json_response["data"]["token"]["payload"]["exp"]["value_iso_8601"] = expected_payload[
                                "data"
                            ]["token"]["payload"]["exp"]["value_iso_8601"]
                    if "iat" in json_response["data"]["token"]["payload"]:
                        if "value" in json_response["data"]["token"]["payload"]["iat"]:
                            json_response["data"]["token"]["payload"]["iat"]["value"] = expected_payload["data"][
                                "token"
                            ]["payload"]["iat"]["value"]
                        if "value_iso_8601" in json_response["data"]["token"]["payload"]["iat"]:
                            json_response["data"]["token"]["payload"]["iat"]["value_iso_8601"] = expected_payload[
                                "data"
                            ]["token"]["payload"]["iat"]["value_iso_8601"]
                    if "nbf" in json_response["data"]["token"]["payload"]:
                        if "value" in json_response["data"]["token"]["payload"]["nbf"]:
                            json_response["data"]["token"]["payload"]["nbf"]["value"] = expected_payload["data"][
                                "token"
                            ]["payload"]["nbf"]["value"]
                        if "value_iso_8601" in json_response["data"]["token"]["payload"]["iat"]:
                            json_response["data"]["token"]["payload"]["nbf"]["value_iso_8601"] = expected_payload[
                                "data"
                            ]["token"]["payload"]["nbf"]["value_iso_8601"]
            if "token-rfc7662" in json_response["data"]:
                if "exp" in json_response["data"]["token-rfc7662"]:
                    json_response["data"]["token-rfc7662"]["exp"] = expected_payload["data"]["token-rfc7662"]["exp"]
                if "iat" in json_response["data"]["token-rfc7662"]:
                    json_response["data"]["token-rfc7662"]["iat"] = expected_payload["data"]["token-rfc7662"]["iat"]
                if "nbf" in json_response["data"]["token-rfc7662"]:
                    json_response["data"]["token-rfc7662"]["nbf"] = expected_payload["data"]["token-rfc7662"]["nbf"]

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertDictEqual(json_response, expected_payload)
