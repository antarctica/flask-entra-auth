import json
from http import HTTPStatus
from uuid import uuid4

from flask import make_response, jsonify, Response
from authlib.common.errors import AuthlibHTTPError
from authlib.flask.error import raise_http_exception
from authlib.specs.rfc7519 import MissingClaimError


class ApiException(Exception):
    """
    Base API Exception class for representing API errors returned to clients

    All errors in this application should inherit from this class. Errors are structured according to the JSON API
    specification, https://jsonapi.org/format/#error-objects.

    In most cases error specifics can be specified when creating each class instance and the 'response()' method called
    to return the error as a Flask response. Where further processing or handling of the error is needed the 'json()'
    method can be used to return the error as a dict.
    """
    status = HTTPStatus.INTERNAL_SERVER_ERROR
    code = None
    title = 'API Error'
    detail = None
    meta = {}
    links = {}

    def __init__(
        self,
        *,
        status: HTTPStatus = None,
        code: str = None,
        title: str = None,
        detail: str = None,
        meta: dict = None,
        about_link: str = None
    ):
        """
        :type status: HTTPStatus
        :param status: HTTP Status, as specified by members of the http.HTTPStatus enum
        :type code: str
        :param code: Application specific identifier for the error that SHOULD NOT change between instances
        :type title: str
        :param title: short, human-readable summary of the error that SHOULD NOT change between instances
        :type detail: str
        :param detail: more detailed, or instance specific, human readable information about the error
        :type meta: dict
        :param meta: additional, free-form information about the error, possibly machine readable
        :param about_link: a URI that leads to more information about the error, either generally or instance specific
        """
        self.id = uuid4()

        if status is not None:
            self.status = status
        if code is not None:
            self.code = code
        if title is not None:
            self.title = title
        if detail is not None:
            self.detail = detail
        if meta is not None:
            self.meta = meta
        if about_link is not None:
            self.links = {
                'about': about_link
            }

    def dict(self) -> dict:
        """
        Formats the error as a dictionary

        :rtype dict
        :return: Error as dict
        """
        error = {
            'id': str(self.id),
            'status': self.status.value,
            'title': self.title
        }

        if self.code is not None:
            error['code'] = self.code
        if self.detail is not None:
            error['detail'] = self.detail
        if self.meta:
            error['meta'] = self.meta
        if 'about' in self.links.keys():
            error['links'] = {'about': self.links['about']}

        return error

    def json(self) -> str:
        """
        Formats the error as a JSON serialised string

        :rtype str
        :return: JSON serialised error
        """

        return json.dumps(self.dict())

    def response(self) -> Response:
        """
        Returns the error as a JSON formatted response

        :rtype Response
        :return: Flask response containing the error, formatted as JSON
        """
        payload = {
            'errors': [self.dict()]
        }
        return make_response(jsonify(payload), self.status.value)


class ApiAuthError(ApiException):
    """
    Base exception for authentication/authorisation related API errors

    This class adapts the ApiException class to be compatible with the AuthLib library and acts as a base for more
    specific auth related errors.

    Instances of this exception are returned where their isn't a more specific exception type.
    """
    status = HTTPStatus.UNAUTHORIZED

    def response(self):
        """
        This method overloads the default method in the 'ApiException' class to make it compatible with the AuthLib
        library.
        """
        payload = {'errors': [self.dict()]}

        raise_http_exception(self.status, json.dumps(payload), {'content-type': 'application/json'})


class ApiAuthAuthorizationMissingError(ApiAuthError):
    """
    Returned where a request doesn't have an Authorization header
    """
    title = 'Missing authorization header'
    detail = 'Ensure your request includes an \'Authorization\' header and try again'


class ApiAuthTokenTypeUnsupportedError(ApiAuthError):
    """
    Returned where a request's Authorization header doesn't have an Bearer token
    """
    title = 'Unsupported token type'
    detail = 'Ensure your request uses a \'Bearer\' token type and try again'


class ApiAuthTokenDecodeError(ApiAuthError):
    """
    Returned where a request's token cannot be decoded as a JSON Web Token
    """
    title = 'Token could not be decoded'
    detail = 'The JSON Web Token (JWT) used as a token could not be decoded. Ensure you are using the correct token ' \
             'and try again, or contact support'


class ApiAuthTokenHeaderKidMissingError(ApiAuthError):
    """
    Returned where a request's token's header does not contain a Key ID field
    """
    title = '\'kid\' header field missing in token'
    detail = 'Ensure your request includes a \'kid\' (Key ID) field in the token header and try again'


class ApiAuthTokenKeyUntrustedError(ApiAuthError):
    """
    Returned where the signing key identified in the request's token isn't trusted by the API
    """
    title = 'Untrusted token JWK'
    detail = 'The JSON Web Key (JWK) identified by the \'kid\' (Key ID) field in the token header, does not ' \
             'correspond to one of the JWKs in the JSON Web Key Set (JWKS) trusted by this API. Ensure you are ' \
             'using the correct \'kid\' and try again, or contact support.'


class ApiAuthTokenKeyDecodeError(ApiAuthError):
    """
    Returned where the signing key identified in the request's token cannot be decoded as a JSON Web Key
    """
    title = 'Token JWK could not be decoded'
    detail = 'The JSON Web Key (JWK) in the JSON Web Key Set (JWKS) identified by the \'kid\' (Key ID) field in the ' \
             'token header cannot be decoded. Ensure you are using the correct Key ID and try again, or contact ' \
             'support.'


class ApiAuthTokenSignatureInvalidError(ApiAuthError):
    """
    Returned where the request's token's signature cannot be verified against it's signing key
    """
    title = 'Invalid token signature'
    detail = 'The JSON Web Token (JWT) used as a token could be verified as authentic. Ensure you are using the ' \
             'correct token and try again, or contact support.'


class ApiAuthTokenClaimMissingError(ApiAuthError):
    """
    Returned where a request's token's payload does not contain a required claim

    Instances of this exception must overload the 'detail' class variable with human readable, and the meta variable
    with machine readable, information about the missing claim.
    """
    title = 'Missing required claim in token'


class ApiAuthTokenClaimUntrustedIssuerError(ApiAuthError):
    """
    Returned where a request's token's issuer claim isn't trusted by the API
    """
    title = 'Untrusted issuer claim in token'
    detail = 'The JSON Web Token (JWT) used as a token was not issued by a trusted issuer. Ensure you are using the ' \
             'correct token and try again, or contact support.'


class ApiAuthTokenClaimInvalidAudience(ApiAuthError):
    """
    Returned where a request's token's audience claim doesn't match the application identifier of the API

    I.e. it is meant for a different audience.
    """
    title = 'Invalid audience claim in token'
    detail = 'The JSON Web Token (JWT) used as a token does not have the correct audience. Ensure you are using the ' \
             'correct token and try again, or contact support.'


class ApiAuthTokenClaimInvalidIssuedAt(ApiAuthError):
    """
    Returned where a request's token has not been issued yet
    """
    title = 'Invalid issued at claim in token'
    detail = 'The JSON Web Token (JWT) used as a token has not been issued yet. Ensure you are using the correct ' \
             'token and try again, or contact support.'


class ApiAuthTokenClaimInvalidNotBefore(ApiAuthError):
    """
    Returned where a request's token is not valid yet
    """
    title = 'Invalid not before claim in token'
    detail = 'The JSON Web Token (JWT) used as a token is not valid yet. Ensure you are using the correct token and ' \
             'try again, or contact support.'


class ApiAuthTokenClaimInvalidExpiry(ApiAuthError):
    """
    Returned where a request's token has expired
    """
    title = 'Invalid expiry claim in token'
    detail = 'The JSON Web Token (JWT) used as a token has expired. Ensure you are using the correct token and try ' \
             'again, or contact support.'


class ApiAuthTokenClaimInvalidClientApplication(ApiAuthError):
    """
    Returned where a request's token's Azure client application ID isn't trusted by the API
    """
    title = 'Invalid client application claim in token'
    detail = 'The JSON Web Token (JWT) used as a token uses an invalid client application (azp). Ensure you are ' \
             'using the correct token & client credentials and try again, or contact support.'


class ApiAuthTokenScopesInsufficient(ApiAuthError):
    """
    Returned where a request's token's scopes (permissions) don't meet the scopes required to interact with the
    requested resource
    """
    status = HTTPStatus.FORBIDDEN
    title = 'Insufficient scopes in token'
    detail = 'The JSON Web Token (JWT) used as a token does not contain scopes required to access this resource. '
    'Ensure you are using the correct token and have the correct permissions assigned or delegated to '
    'your client and try again, or contact support.'


def auth_error_fallback(e: AuthlibHTTPError):
    """
    Auth error handler for any AuthLib exception/error

    This method sets error details dynamically, and is intended as a fallback where a more specific exception isn't
    available. It adapts an AuthLib error into the structure used by errors in this API.

    :type e: AuthlibHTTPError
    :param e: Auth exception
    """
    error = ApiAuthError(
        status=HTTPStatus(e.status_code),
        title=e.error,
        detail=e.get_error_description()
    )
    error.response()


def auth_error_missing_authorization():
    """
    Auth error handler for 'ApiAuthAuthorizationMissingError' errors
    """
    error = ApiAuthAuthorizationMissingError()
    error.response()


def auth_error_token_type_unsupported():
    """
    Auth error handler for 'ApiAuthTokenTypeUnsupportedError' errors
    """
    error = ApiAuthTokenTypeUnsupportedError()
    error.response()


def auth_error_token_decode():
    """
    Auth error handler for 'ApiAuthTokenDecodeError' errors
    """
    error = ApiAuthTokenDecodeError()
    error.response()


def auth_error_token_missing_kid():
    """
    Auth error handler for 'ApiAuthTokenHeaderKidMissingError' errors
    """
    error = ApiAuthTokenHeaderKidMissingError()
    error.response()


def auth_error_token_untrusted_jwk():
    """
    Auth error handler for 'ApiAuthTokenKeyUntrustedError' errors
    """
    error = ApiAuthTokenKeyUntrustedError()
    error.response()


def auth_error_token_key_decode():
    """
    Auth error handler for 'ApiAuthTokenKeyDecodeError' errors
    """
    error = ApiAuthTokenKeyDecodeError()
    error.response()


def auth_error_token_signature_invalid():
    """
    Auth error handler for 'ApiAuthTokenSignatureInvalidError' errors
    """
    error = ApiAuthTokenSignatureInvalidError()
    error.response()


def auth_error_token_missing_claim(*, exception: MissingClaimError, claims: dict):
    """
    Auth error handler for 'ApiAuthTokenClaimMissingError' errors

    This handler sets the missing token claim dynamically.

    :type exception: MissingClaimError
    :param exception: Missing claim exception instance
    :type claims: dict
    :param claims: details of the possible claims within a token payload
    """
    claim = str(exception).split('"')[1]

    error = ApiAuthTokenClaimMissingError(
        detail=f"The token payload is missing a required claim: '{ claims[claim]['name'] }' ({ claim }). Ensure you "
        f"are using the correct token and try again, or contact support.",
        meta={
            'missing_claim': claims[claim]
        }
    )
    error.response()


def auth_error_token_untrusted_claim_issuer():
    """
    Auth error handler for 'ApiAuthTokenClaimUntrustedIssuerError' errors
    """
    error = ApiAuthTokenClaimUntrustedIssuerError()
    error.response()


def auth_error_token_invalid_claim_audience():
    """
    Auth error handler for 'ApiAuthTokenClaimInvalidAudience' errors
    """
    error = ApiAuthTokenClaimInvalidAudience()
    error.response()


def auth_error_token_invalid_claim_issued_at():
    """
    Auth error handler for 'ApiAuthTokenClaimInvalidIssuedAt' errors
    """
    error = ApiAuthTokenClaimInvalidIssuedAt()
    error.response()


def auth_error_token_invalid_claim_not_before():
    """
    Auth error handler for 'ApiAuthTokenClaimInvalidNotBefore' errors
    """
    error = ApiAuthTokenClaimInvalidNotBefore()
    error.response()


def auth_error_token_invalid_claim_expiry():
    """
    Auth error handler for 'ApiAuthTokenClaimInvalidExpiry' errors
    """
    error = ApiAuthTokenClaimInvalidExpiry()
    error.response()


def auth_error_token_invalid_claim_client_application():
    """
    Auth error handler for 'ApiAuthTokenClaimInvalidClientApplication' errors
    """
    error = ApiAuthTokenClaimInvalidClientApplication()
    error.response()


def auth_error_token_scopes_insufficient(*, resource_scopes: str, token_scopes: list):
    """
    Auth error handler for 'ApiAuthTokenScopesInsufficient' errors

    This handler dynamically sets the scopes required to interact with the resource, and the scopes available in the
    current token.

    :type resource_scopes: str
    :param resource_scopes: space concatenated list of scopes required to interact with the current resource
    :type token_scopes: set
    :param token_scopes: list of scopes within the current token
    """
    resource_scopes = resource_scopes.split(' ')

    error = ApiAuthTokenScopesInsufficient(
        meta={
            'required_scopes': resource_scopes,
            'scopes_in_token': token_scopes
        }
    )
    error.response()
