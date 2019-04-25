from authlib.flask.oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError, UnsupportedTokenTypeError
from authlib.oauth2.rfc6750 import BearerTokenValidator

from flask_azure_oauth.errors import auth_error_missing_authorization, auth_error_token_type_unsupported, \
    auth_error_fallback


class ResourceProtector(_ResourceProtector):
    """
    Custom implementation of the AuthLib default 'ResourceProtector' class

    Differences include:
    - overloading the 'raise_error_response' method to catch exceptions as API errors and return them to the client
    """

    @classmethod
    def deregister_token_validator(cls, token_validator: BearerTokenValidator) -> None:
        """
        This method adds a counterpart to the 'register_token_validator' in the 'ResourceProtector' class to allow a
        previously registered token validator type to be removed

        :type token_validator: BearerTokenValidator
        :param token_validator: Previously registered token validator
        """
        del cls.TOKEN_VALIDATORS[token_validator.TOKEN_TYPE]

    # noinspection PyMethodMayBeStatic
    def raise_error_response(self, error):
        """
        This method overloads the default method in the 'ResourceProtector' class to catch exceptions as API errors
        returned to the client

        Some errors are caught specifically to to return targeted errors, otherwise a generic error is returned by
        transforming an AuthLib error into the form used for API errors.

        :param error:
        :return:
        """
        if isinstance(error, MissingAuthorizationError):
            auth_error_missing_authorization()
        elif isinstance(error, UnsupportedTokenTypeError):
            auth_error_token_type_unsupported()
        else:
            auth_error_fallback(error)
