import time

from datetime import datetime
from typing import List, Union, Callable

# noinspection PyPackageRequirements
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from flask import Request, Flask as App

from authlib.jose import JWTClaims, JWK, JWK_ALGORITHMS, jwt, JWT
from authlib.jose.errors import MissingClaimError, InvalidClaimError, InvalidTokenError, ExpiredTokenError, \
    DecodeError, BadSignatureError, InvalidHeaderParameterName
from authlib.jose.util import extract_header
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc6750 import BearerTokenValidator, InsufficientScopeError

from flask_azure_oauth.errors import auth_error_token_decode, auth_error_token_missing_kid, \
    auth_error_token_untrusted_jwk, auth_error_token_key_decode, auth_error_token_signature_invalid, \
    auth_error_token_missing_claim, auth_error_token_untrusted_claim_issuer, auth_error_token_invalid_claim_audience, \
    auth_error_token_invalid_claim_expiry, auth_error_token_invalid_claim_client_application, \
    auth_error_token_invalid_claim_issued_at, auth_error_token_invalid_claim_not_before, \
    auth_error_token_scopes_insufficient


class AzureJWTClaims(JWTClaims):
    """
    Custom implementation of the AuthLib default 'JWTClaims' class.

    Differences include:
    - adding additional registered claims, specific to tokens issued by Microsoft Azure's Active Directory OAuth
      endpoints ('azp', 'roles')
    - adding default claim validation options, including essential claims and in some cases specific values
    - overloading the 'issued at' validator, by requiring that the token has been issued (i.e. now is after issued at)
    - overloading the 'expires at' validator, by setting default values for the 'now' and 'leeway' parameters
    - adding a custom 'Azure client application' claim validator, allowing client applications to be whitelisted
    - removal of the 'JWT ID' claim validator, as this optional claim is not implemented in tokens issued by Azure AD
    - when validating claims, exceptions are caught as API errors, which will be returned to the client

    Note: Ensuring the 'issued at' claim is after now is not required by RFC 7519 [1], but it makes logical sense with
    the way our OAuth provider (Azure) works.

    Note: The 'JWT ID' claim is an optional claim according to RFC 7519 [2]. As Azure issued tokens don't include this
    claim, we loose no benefits by requiring this claim.

    [1] https://tools.ietf.org/html/rfc7519#section-4.1.6
    [2] https://tools.ietf.org/html/rfc7519#section-4.1.7
    """
    REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'azp', 'roles']

    claim_details = {
        'aud': {
            'claim': 'aud',
            'name': 'Audience',
            'type': 'standard'
        },
        'exp': {
            'claim': 'exp',
            'name': 'Expires at',
            'type': 'standard'
        },
        'iat': {
            'claim': 'iat',
            'name': 'Issued at',
            'type': 'standard'
        },
        'iss': {
            'claim': 'iss',
            'name': 'Issuer',
            'type': 'standard'
        },
        'nbf': {
            'claim': 'nbf',
            'name': 'Not before',
            'type': 'standard'
        },
        'sub': {
            'claim': 'sub',
            'name': 'Subject',
            'type': 'standard'
        },
        'azp': {
            'claim': 'azp',
            'name': 'Azure client application ID',
            'type': 'custom'
        }
    }

    def __init__(self, *, payload: dict, header: dict, tenancy_id: str, service_app_id: str, client_app_ids: List[str]):
        """
        :type payload: dict
        :param payload: Payload of an (Azure) JSON Web Token
        :type header: dict
        :param header: Header of an (Azure) JSON Web Token
        :type tenancy_id: str
        :param tenancy_id: Azure Active Directory tenancy ID, used for validating 'issuer' claim
        :type service_app_id: str
        :param service_app_id: ID of the Azure Active Directory application registration representing this service/API,
        used for validating the 'audience' claim
        :type client_app_ids: List[str]
        :param client_app_ids: IDs of Azure Active Directory application registrations representing clients of this
        service/API, used for validating the 'Azure client applications' (azp) custom claim
        """
        options = {
            "iss": {
                "essential": True,
                "values": [f"https://login.microsoftonline.com/{ tenancy_id }/v2.0"]
            },
            "sub": {
                "essential": True
            },
            "aud": {
                "essential": True,
                "value": service_app_id
            },
            "exp": {
                "essential": True
            },
            "nbf": {
                "essential": True
            },
            "iat": {
                "essential": True
            },
            "azp": {
                "essential": True,
                "values": client_app_ids
            }
        }
        params = None

        super().__init__(payload, header, options=options, params=params)

    def validate(self, now: float = None, leeway: float = 0) -> None:
        """
        Overloaded implementation of the 'validate' method in the AuthLib default 'JWTClaims' class.

        Differences include:
        - removing the default 'JWT ID' claim validator (see class comments)
        - adding the custom 'Azure client application' claim validator (see class comments)
        - wrapping calls to validator methods to catch exceptions as API errors, which will be returned to the client

        When validating, options defined __init__ will be used, i.e. allowed audience claim values etc.

        :type now: float
        :param now: current time, in the form of seconds past the Unix Epoch
        :type leeway: float
        :param leeway: a time delta in seconds to allow for clock skew between servers (i.e. a margin of error)
        """
        try:
            self._validate_essential_claims()
        except MissingClaimError as e:
            auth_error_token_missing_claim(exception=e, claims=self.claim_details)

        if now is None:
            now = int(time.time())

        try:
            self.validate_iss()
        except InvalidClaimError:
            auth_error_token_untrusted_claim_issuer()
        try:
            self.validate_aud()
        except InvalidClaimError:
            auth_error_token_invalid_claim_audience()
        try:
            self.validate_sub()
        except InvalidClaimError:
            raise NotImplementedError()
        try:
            self.validate_iat(now, leeway)
        except (InvalidClaimError, InvalidTokenError):
            auth_error_token_invalid_claim_issued_at()
        try:
            self.validate_nbf(now, leeway)
        except (InvalidClaimError, InvalidTokenError):
            auth_error_token_invalid_claim_not_before()
        try:
            self.validate_exp(now, leeway)
        except (InvalidClaimError, ExpiredTokenError):
            auth_error_token_invalid_claim_expiry()
        try:
            self.validate_azp()
        except InvalidClaimError:
            auth_error_token_invalid_claim_client_application()

    def validate_iat(self, now, leeway) -> None:
        """
        Overloaded implementation of the 'validate_iat' method in the AuthLib default 'JWTClaims' class.

        Differences include:
        - checking the claim value is after now, to ensure a token has been issued and is 'in force'

        Note: Validating the 'issued at' claim in this way is not required when validating a token, according to
        RFC7519, the JWT RFC. We do so because it makes logical sense with the way our OAuth provider (Azure) works.

        :type now: float
        :param now: current time, in the form of seconds past the Unix Epoch
        :type leeway: float
        :param leeway: a time delta in seconds to allow for clock skew between servers (i.e. a margin of error)
        """
        iat = self.get('iat')
        if iat and not isinstance(iat, int):
            raise InvalidClaimError('iat')
        if iat > (now + leeway):
            raise InvalidTokenError()

    def validate_exp(self, now: float = None, leeway: float = 0) -> None:
        """
        Overloaded implementation of the 'validate_exp' method in the AuthLib default 'JWTClaims' class.

        Differences include:
        - providing default parameter values for 'now' and 'leeway' to make it easier to call this method directly

        :type now: float
        :param now: current time, in the form of seconds past the Unix Epoch
        :type leeway: float
        :param leeway: a time delta in seconds to allow for clock skew between servers (i.e. a margin of error)
        """
        if now is None:
            now = int(time.time())

        exp = self.get('exp')
        if exp:
            if not isinstance(exp, int):
                raise InvalidClaimError('exp')
            if exp < (now - leeway):
                raise ExpiredTokenError()

    def validate_azp(self) -> None:
        """
        Custom validation for the proprietary 'Azure client application' (azp) claim, which is included in tokens
        issued by Microsoft Azure's Active Directory OAuth endpoints.

        This claim contains the ID of the Azure AD application registration that requested the token (i.e. the client).

        This claim can be used to control which applications can use a service, rather than (in user facing services)
        the identity of the current user and any permissions/scopes that may have been assigned or delegated to either.

        I.e. A client application may be partially untrusted (i.e. entirely client side or 3rd party) and should not
        have access to some functionality or information, as it would be unsafe (e.g. logs visible to 3rd party staff).

        This claim is different to the 'Subject' (sub) standard claim, as this claim always returns the ID of the
        client application, whereas the subject claim will return either the ID of the current user (in user facing
        services) or the ID of the client application (in service to service contexts).

        Note: Checking this claim authorises a request in a very broad sense. Further checks *MUST* be made using scopes
        and other logic as relevant.

        For more information see:
        https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#claims-in-access-tokens
        """
        self._validate_claim_value('azp')


class AzureToken:
    """
    Custom class representing a JSON Web Token (JWT) issued by Microsoft Azure AD

    This class is intended to represent and interact with an existing JWT, it cannot create or issue them itself.
    Specifically, this class is intended for JWTs issued by Microsoft Azure's Active Directory OAuth endpoints.

    On instantiation, this class will validate a token against a set of trusted JSON Web Keys (JWKs) provided by Azure,
    and validate its claims. Some of these claims, such as 'roles' can then be used be used as scopes to determine
    whether a client has permission to interact with a resource.

    Where an error arises validating or decoding a token, exceptions and errors are caught API errors and returned to
    the client.
    """
    _jwk_lib = JWK(algorithms=JWK_ALGORITHMS)

    def __init__(
        self,
        *,
        token_string: str,
        azure_tenancy_id: str,
        azure_application_id: str,
        azure_client_application_ids: List[str],
        azure_jwks: dict
    ):
        """
        :type token_string: str
        :param token_string: (Azure) JWT as a base64 encoded string (i.e. the value of the Authorization header)
        :type azure_tenancy_id: str
        :param azure_tenancy_id: Azure Active Directory tenancy ID
        :type azure_application_id: str
        :param azure_application_id: ID of the Azure Active Directory application registration representing this app
        :type azure_client_application_ids: List[str]
        :param azure_client_application_ids: IDs of Azure Active Directory application registrations representing
        clients of this app
        :type azure_jwks: dict
        :param azure_jwks: trusted JWKs formatted as a JSON Web Key Set
        """
        self._token_string = token_string
        self.jwks = azure_jwks
        self._payload = self._get_payload()
        self.claims = AzureJWTClaims(
            payload=self._payload,
            header=self._header,
            tenancy_id=azure_tenancy_id,
            service_app_id=azure_application_id,
            client_app_ids=azure_client_application_ids
        )
        self.scopes = self._get_scopes()

    def _get_header(self) -> dict:
        """
        Returns the header of the JSON Web Token

        :rtype dict
        :return: token header
        """
        token_header = self._token_string.split('.')[0].encode()
        try:
            return extract_header(token_header, DecodeError)
        except DecodeError:
            auth_error_token_decode()

    def _get_payload(self) -> AzureJWTClaims:
        """
        Returns the payload of the JSON Web Token

        The returned JWTClaims object can be used to validate and retrieve claims defined in the token payload.

        :rtype AzureJWTClaims
        :return: An object containing the claims of the JSON Web Token
        """
        try:
            self._jwk_public_key = self._get_jwk_public_key()
            return jwt.decode(self._token_string, self._jwk_public_key)
        except DecodeError:
            auth_error_token_decode()
        except BadSignatureError:
            auth_error_token_signature_invalid()

    def _get_kid(self) -> str:
        """
        Returns the 'Key ID' (kid) field of the JSON Web Token header

        :rtype str
        :return: Key ID claim
        """
        try:
            self._header = self._get_header()
            if 'kid' not in self._header.keys():
                raise InvalidHeaderParameterName('kid')
        except InvalidHeaderParameterName:
            auth_error_token_missing_kid()

        return self._header['kid']

    def _get_jwk(self, jwks: dict) -> dict:
        """
        Returns the JSON Web Key (JWT) from the JSON Web Key Set (JWKS) for the JSON Web Token, as indicated by the
        'Key ID' field in the header of the token. If a matching JWK is not found an API error is returned to the
        client.

        This JWK can be used to verify the authenticity of the token by checking that it's signature is signed by the
        key specified, providing that this key is trusted by this application.

        :type jwks: dict
        :param jwks: trusted JWKs formatted as a JSON Web Key Set

        :rtype: dict
        :return: JWK used to sign the JWT
        """

        jwk = None
        self._kid = self._get_kid()

        for key in jwks['keys']:
            if key['kid'] == self._kid:
                jwk = key
        if jwk is None:
            auth_error_token_untrusted_jwk()

        return jwk

    def _get_jwk_public_key(self) -> str:
        """
        Returns the public key from the JSON Web Key (JWK) used to sign the JSON Web Token.

        Requires an 'RSA' JWK.

        :rtype str
        :return: Public key for an RSA key pair, encoded using 'SubjectPublicKeyInfo', formatted as a PEM certificate.
        """
        try:
            self._jwk = self._get_jwk(self.jwks)
            jwk = self._jwk_lib.loads(self._jwk)

            return jwk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        except ValueError:
            auth_error_token_key_decode()

    def _get_scopes(self) -> set:
        """
        Returns a set of scopes present in the JSON Web Token

        Scopes can be used for authorise whether the token bearer (application or user) can interact with a resource.

        Scopes must be space separated. Where no scopes are present in the token, an empty set is returned. Currently
        this method supports loading 'application' permissions contained in a 'roles' claim.

        :rtype set
        :return: set of scopes present in the token
        """
        scopes = self.claims.get('roles')

        if scopes is None:
            return set()
        if scopes == '':
            return set()
        if isinstance(scopes, list):
            return set(scopes)

        scopes = set(str(scopes).split(' '))
        return scopes

    def introspect(self) -> dict:
        """
        Returns details about the current token for reference/debugging

        :rtype dict
        :return: Token properties, including formatted scopes and meta information for claims
        """
        claims = {}

        for claim in self.claims.claim_details:
            claims[claim] = {
                'claim': self.claims.claim_details[claim]['claim'],
                'name': self.claims.claim_details[claim]['name'],
                'type': self.claims.claim_details[claim]['type'],
                'value': self.claims[claim]
            }

            if claim == 'iat' or claim == 'nbf' or claim == 'exp':
                claims[claim]['value_iso_8601'] = datetime.utcfromtimestamp(int(claims[claim]['value'])).isoformat()

        return {
            'header': self._header,
            'payload': claims,
            'scopes': list(self._get_scopes()),
        }


class AzureTokenValidator(BearerTokenValidator):
    """
    Custom implementation of the AuthLib default 'BearerTokenValidator' class.

    Differences include:
    - overloading abstract methods ('authenticate_token', 'request_invalid' and 'token_revoked') with concrete
      implementations
    - overloading the '__init__' method to pass configuration options
    - overloading the '__call__' method to catch exceptions as API errors returned to the client
    - overloading the 'token_expired' and 'scope_insufficient' methods to make compatible with our AzureToken class
    """

    def __init__(
        self,
        *,
        azure_tenancy_id: str,
        azure_application_id: str,
        azure_client_application_ids: List[str],
        azure_jwks: dict
    ):
        """
        :type azure_tenancy_id: str
        :param azure_tenancy_id: Azure Active Directory tenancy ID
        :type azure_application_id: str
        :param azure_application_id: ID of the Azure Active Directory application registration representing this app
        :type azure_client_application_ids: List[str]
        :param azure_client_application_ids: IDs of Azure Active Directory application registrations representing
        clients of this app
        :type azure_jwks: dict
        :param azure_jwks: trusted JWKs formatted as a JSON Web Key Set
        """
        self.tenancy_id = azure_tenancy_id
        self.application_id = azure_application_id
        self.client_application_ids = azure_client_application_ids
        self.jwks = azure_jwks

        super().__init__(realm=None)

    def __call__(self, token_string: str, scope: str, request: Request, scope_operator: str = 'AND'):
        """
        Overloaded method to catch exceptions as API errors returned to the client

        :type token_string: str
        :param token_string: JWT as a base64 encoded string (i.e. the value of the Authorization header)
        :type scope: str
        :param scope: space concatenated list of scopes required to interact with the current resource
        :type request: Request
        :param request: current Flask request
        :type scope_operator: str
        :param scope_operator: Strategy of validating whether token scopes meet resource scopes (i.e. all represent, at
        least one present)
        """
        try:
            return super().__call__(token_string, scope, request, scope_operator)
        except InsufficientScopeError:
            token = AzureToken(
                token_string=token_string,
                azure_tenancy_id=self.tenancy_id,
                azure_application_id=self.application_id,
                azure_client_application_ids=self.client_application_ids,
                azure_jwks=self.jwks
            )
            auth_error_token_scopes_insufficient(resource_scopes=scope, token_scopes=list(token.scopes))

    def authenticate_token(self, token_string: str) -> AzureToken:
        """
        Create and validate an Azure Token object from an (Azure) JSON Web Token

        This method implements an abstract method in the 'BearerTokenValidator' class.

        :type token_string: str
        :param token_string: JWT as a base64 encoded string (i.e. the value of the Authorization header)

        :rtype AzureToken
        :return: Custom representation of an (Azure) JSON Web Token as an object
        """
        token = AzureToken(
            token_string=token_string,
            azure_tenancy_id=self.tenancy_id,
            azure_application_id=self.application_id,
            azure_client_application_ids=self.client_application_ids,
            azure_jwks=self.jwks
        )
        token.claims.validate()

        return token

    def request_invalid(self, request: Request) -> bool:
        """
        Determines whether a request is suitable for authentication purposes

        I.e. whether the request has an authorization header with a bearer token.

        This method implements an abstract method in the 'BearerTokenValidator' class and is intentionally a stub as
        a bearer token is already checked for by the `flask_azure_oauth.resource_protector.ResourceProtector` class.

        :type request: Request
        :param request: Current Flask request

        :rtype bool
        :return: True if the request is invalid, False if ok
        """
        return False

    def token_revoked(self, token: AzureToken) -> bool:
        """
        Determines whether a token is still trusted for authentication purposes

        I.e. whether the token has been tainted and no longer valid.

        This method implements an abstract method in the 'BearerTokenValidator' class and is intentionally a stub as
        our token provider (Azure AD) has no mechanism to revoke an access token (as opposed to a refresh token).

        :type token: AzureToken
        :param token: JSON Web Token as an Azure Token object

        :rtype bool
        :return: True if the token has been revoked, False if ok
        """
        return False

    def token_expired(self, token: AzureToken) -> bool:
        """
        Determines whether a token is still valid for authentication purposes

        I.e. whether the token has expired and no longer valid.

        This method overloads the default method in the 'BearerTokenValidator' class to make it compatible with our
        custom Token class, and to catch exceptions as API errors returned to the client.

        :type token: AzureToken
        :param token: JSON Web Token as an Azure Token object

        :rtype bool
        :return: True if the token has expired, False if ok
        """
        try:
            token.claims.validate_exp()
            return False
        except (InvalidClaimError, ExpiredTokenError):
            auth_error_token_invalid_claim_expiry()

    def scope_insufficient(self, token: AzureToken, scope: str, operator: Union[str, Callable] = 'AND') -> bool:
        """
        Determines whether a token has sufficient scopes to interact with a resource

        I.e. whether the token bearer has suitable permissions to perform their intended action.

        This method overloads the default method in the 'BearerTokenValidator' class to make it compatible with our
        AzureToken class.

        :type token: AzureToken
        :param token: JSON Web Token as an Azure Token object
        :type scope: str
        :param scope: space concatenated list of scopes required to interact with the current resource
        :type operator: str or Callable
        :param operator: Strategy of validating whether token scopes meet resource scopes (i.e. all represent, at
        least one present)

        :rtype bool
        :return: True if the token has insufficient scopes, False if ok
        """
        if not scope:
            return False

        token_scopes = token.scopes
        resource_scopes = set(scope_to_list(scope))

        if operator == 'AND':
            return not token_scopes.issuperset(resource_scopes)
        if operator == 'OR':
            for resource_scope in resource_scopes:
                if resource_scope in token_scopes:
                    return False
        if callable(operator):
            return not operator(token_scopes, resource_scopes)
        raise ValueError(f"Invalid operator value [{ operator }], valid options are 'AND', 'OR' or <callable>")


class TestJwt:
    """
    Class to create JSON Web Tokens (JWTs) for testing purposes

    Supports generating tokens with a set of requested scopes using a testing signing key generated by the TestJwk
    class. Values for the `aud`, `iss` and `azp` claims in the payment will values from the current Flask application.
    """
    _jwt = JWT()

    def __init__(self, *, app: App, scopes: list = None):
        """
        :type app: App
        :type app: Flask application
        :type scopes: list
        :param scopes: Optional scopes to include in the token (as a 'roles' claim) for testing authorisation
        """
        self.signing_key = app.config['TEST_JWKS']

        self.header = {
            'alg': self.signing_key.algorithm,
            'kid': self.signing_key.kid()
        }
        self.payload = {
            'aud': app.config['AZURE_OAUTH_APPLICATION_ID'] or 'testing',
            'exp': int(time.time() + 10000),
            'iat': int(time.time()),
            'iss': f"https://login.microsoftonline.com/{ app.config['AZURE_OAUTH_TENANCY'] or 'testing' }/v2.0",
            'nbf': int(time.time()),
            'sub': None,
            'azp': app.config['AZURE_OAUTH_CLIENT_APPLICATION_IDS'][0] or 'testing'
        }
        if scopes is not None:
            self.payload['roles'] = ' '.join(scopes)

    def dumps(self) -> str:
        """
        Returns a signed/issued JWT encoded as a string for exchange

        :rtype str
        :return: Signed JWT
        """
        return self._jwt.encode(self.header, self.payload, self.signing_key.private_key_pem()).decode()
