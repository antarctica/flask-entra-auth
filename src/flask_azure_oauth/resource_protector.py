from typing import Optional, Union

from authlib.common.errors import AuthlibHTTPError
from authlib.integrations.flask_oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import HttpRequest, MissingAuthorizationError, UnsupportedTokenTypeError
from authlib.oauth2.rfc6750 import BearerTokenValidator
from flask import session

from flask_azure_oauth.errors import (
    auth_error_fallback,
    auth_error_missing_authorization,
    auth_error_token_type_unsupported,
)


class ResourceProtector(_ResourceProtector):
    """
    Custom implementation of the AuthLib default 'ResourceProtector' class

    Differences include:
    - overloading the `raise_error_response` method to catch exceptions as API errors and return them to the client
    - overloading the `validate_request` method to support access tokens stored in the current flask session
    """

    def deregister_token_validator(self, token_validator: BearerTokenValidator) -> None:
        """
        This method adds a counterpart to the 'register_token_validator' in the 'ResourceProtector' class to allow a
        previously registered token validator type to be removed

        :type token_validator: BearerTokenValidator
        :param token_validator: Previously registered token validator
        """
        del self._token_validators[token_validator.TOKEN_TYPE]

    def raise_error_response(self, error: AuthlibHTTPError):
        """
        This method overloads the `raise_error_response` method in the `ResourceProtector` class to catch exceptions as
        API errors returned to the client

        Some errors are caught specifically to return targeted errors, otherwise the AuthLib error is formatted as an
        error generically.

        :type error AuthlibHTTPError
        :param error: Error exception
        :return:
        """
        if isinstance(error, MissingAuthorizationError):
            auth_error_missing_authorization()
        elif isinstance(error, UnsupportedTokenTypeError):
            auth_error_token_type_unsupported()
        else:
            auth_error_fallback(error)

    def validate_request(self, scope: Optional[Union[list, str]], request: HttpRequest, scope_operator: str = "AND"):
        """
        This method overloads the `validate_request` method in the base `authlib.oauth2.ResourceProtector` class to
        support cases where an access token may not be set directly in the request as an authorisation header but within
        a user session.

        This usually occurs when applications support stateful sessions via a web browser, in addition or instead of an
        stateless API.

        If a session is active, contains an 'access_token' value, and there is no Authorization header already set, this
        method will add one for compatibility with the Resource Protector class.
        """
        if session.get("access_token") and "Authorization" not in request.headers.keys():
            headers = {header: value for header, value in request.headers.items()}
            headers["Authorization"] = f"Bearer {session.get('access_token')}"
            request = HttpRequest(method=request.method, uri=request.uri, data=request.data, headers=headers)

        return super().validate_request(scope, request, scope_operator)
