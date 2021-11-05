import requests

from flask import Flask as App
from typing import List, Union

from flask_azure_oauth.resource_protector import ResourceProtector
from flask_azure_oauth.tokens import AzureTokenValidator, AzureToken


class FlaskAzureOauth(ResourceProtector):
    def __init__(self):
        super().__init__()

        self.validator = None

        self.azure_tenancy_id = None
        self.azure_application_id = None
        self.azure_client_application_ids = []
        self.jwks = {}

        self._b2c_openid_config: Union[dict, None] = None

    def init_app(self, app: App):
        """
        Initialises extension using settings from the Flask application

        :type app: App
        :param app: Flask application
        """
        self.azure_tenancy_id = app.config["AZURE_OAUTH_TENANCY"]
        self.azure_application_id = app.config["AZURE_OAUTH_APPLICATION_ID"]

        self.azure_b2c_tenant_mode = app.config.get("AZURE_B2C_TENANT_MODE", False)
        self.azure_tenant_name = app.config.get("AZURE_TENANT_NAME", None)
        self.azure_b2c_registerlogin_userflow_name = app.config.get("AZURE_B2C_REGISTERLOGIN_USERFLOW_NAME", None)
        assert (self.azure_b2c_tenant_mode and self.azure_tenant_name and self.azure_b2c_registerlogin_userflow_name) \
            or not self.azure_b2c_tenant_mode, \
            "If B2C mode is enabled " \
            "configuration options 'AZURE_TENANT_NAME' and 'AZURE_B2C_REGISTERLOGIN_USERFLOW_NAME' are required!"

        self.azure_client_application_ids = None
        if self.azure_b2c_tenant_mode:
            self.jwks = self._get_b2c_jwks()
        else:
            self.jwks = self._get_jwks()

        try:
            self.azure_client_application_ids = app.config["AZURE_OAUTH_CLIENT_APPLICATION_IDS"]
            if isinstance(self.azure_client_application_ids, list):
                if len(self.azure_client_application_ids) == 0:
                    self.azure_client_application_ids = None
        except KeyError:
            pass

        self.validator = AzureTokenValidator(
            azure_tenancy_id=self.azure_tenancy_id,
            azure_b2c_tenant_mode=self.azure_b2c_tenant_mode,
            azure_b2c_issuer=self._get_b2c_issuer(),
            azure_application_id=self.azure_application_id,
            azure_client_application_ids=self.azure_client_application_ids,
            azure_jwks=self.jwks,
        )

        self.register_token_validator(self.validator)

    def _get_jwks(self, jwks_uri: str = None) -> dict:
        """
        Retrieves a JSON Web Key Set (JWKS)

        JWKS allow token providers to advertise the keys that will be used to sign JSON Web Tokens (JWTs) in a dynamic
        and machine readable way. Normally keys are fetched from the configured Azure tenancy, and will change
        periodically.

        :rtype dict
        :return: JSON Web Key Set
        """
        if jwks_uri is None:
            # Default URI for standard AAD tenants
            jwks_uri = f"https://login.microsoftonline.com/{self.azure_tenancy_id}/discovery/v2.0/keys"

        jwks_request = requests.get(
            jwks_uri,
            params={"appid": self.azure_application_id},
        )
        jwks_request.raise_for_status()
        return jwks_request.json()

    def _get_b2c_jwks(self) -> Union[dict, None]:
        """
        Get the valid JSON Web Key Set (JWKS) source URI from B2C userflow configuration and then acquire the
        current JWKS from there
        """
        if self.azure_b2c_tenant_mode:
            return self._get_jwks(self._get_b2c_openid_config()["jwks_uri"])
        return None

    def _get_b2c_issuer(self) -> Union[str, None]:
        """
        Get the valid issuer value from B2C userflow configuration
        """
        if self.azure_b2c_tenant_mode:
            return self._get_b2c_openid_config()["issuer"]
        return None

    def _get_b2c_openid_config(self) -> Union[dict, None]:
        """
        Query the configured Azure AD B2C userflow openid configuration
        see https://docs.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#validate-signature
        """
        if not self.azure_b2c_tenant_mode:
            return None

        if self._b2c_openid_config:
            return self._b2c_openid_config

        openid_config_request = requests.get(
            f"https://{self.azure_tenant_name}.b2clogin.com/{self.azure_tenant_name}.onmicrosoft.com/{self.azure_b2c_registerlogin_userflow_name}/v2.0/.well-known/openid-configuration"
        )
        openid_config_request.raise_for_status()
        self._b2c_openid_config = openid_config_request.json()
        return self._b2c_openid_config

    def introspect_token(self, *, token_string: str) -> dict:
        """
        Returns details about the current (Azure) JSON Web Token for reference/debugging

        Includes support for RFC 7662 https://tools.ietf.org/html/rfc7662

        :param token_string: str
        :return: (Azure) JWT as a base64 encoded string (i.e. the value of the Authorization header)

        :rtype dict
        :return: Token properties, including formatted scopes and meta information for claims
        """
        token = AzureToken(
            token_string=token_string,
            azure_tenancy_id=self.azure_tenancy_id,
            azure_application_id=self.azure_application_id,
            azure_client_application_ids=self.azure_client_application_ids,
            azure_jwks=self.jwks,
        )
        return token.introspect()

    def introspect_token_rfc7662(self, *, token_string: str) -> dict:
        """
        Returns details about the current token for reference/debugging

        Implements RFC 7662 https://tools.ietf.org/html/rfc7662

        :rtype dict
        :return: Token properties, formatted as per RFC 7662
        """
        token = AzureToken(
            token_string=token_string,
            azure_tenancy_id=self.azure_tenancy_id,
            azure_application_id=self.azure_application_id,
            azure_client_application_ids=self.azure_client_application_ids,
            azure_jwks=self.jwks,
        )
        return token.introspect_rfc7662()
