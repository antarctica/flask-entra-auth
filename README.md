# Flask Azure Auth Experiments

Experiment to update how access to a Flask app can be controlled using Azure/Entra ID.

See https://gitlab.data.bas.ac.uk/MAGIC/add-metadata-toolbox/-/issues/384 for background.

**Note:** This README is in the process of being re-written to become a proper package.

## Roadmap

v0.1.0

- [x] what else did my app do to check a token?
- [x] logically we should ensure `ver` claim is '2.0'
- [x] resource protector v1
- [x] get current token
- [x] refactor validator to skip auth method and overload validator to prevent needing derived token
- [x] refactored into an extension (resource protector v2)
- [x] minimal tests

Then:

- [x] fake token auth for tests
- reimplement error handling as exceptions to be handled by the app
  - generic:
    - [x] missing authorisation header
    - [x] authentication scheme not bearer
    - [x] missing credentials
  - internal:
    - [x] oidc metadata
    - [x] jwks (missing, invalid and empty)
  - https://pyjwt.readthedocs.io/en/latest/api.html#exceptions:
    - [x] missing required claim (iss)
    - [ ] (invalid token base)
    - [x] decode error
    - [x] invalid signature
    - [x] expired
    - [x] invalid audience
    - [x] invalid issuer
    - [x] not issued (nbf)
    - ~~invalid issued-at~~ easy not testable
    - ~~invalid key~~ not easy testable and unlikely
    - ~~invalid alg~~ not easy testable and unlikely
  - additional:
    - [x] no 'kid' header parameter
    - [x] 'kid' header parameter value not in JWKS
    - [x] sub
    - [x] azp
    - [x] ver
    - [x] roles/scopes
- [x] does `pyjwt` validate `nbf` claim? - Yes
- [x] change tests for subjects/apps to change the value in the token, rather than the app config
- [x] refactor how missing required tokens are tested
- [x] additional scopes tests
- [x] refactor app directly into tests, eliminating `__main__.py`
- [x] expose allows subs/azp's as config options

- Later:

- [x] change POST to GET in routes
- [ ] note Token class implicitly validates for safety (currently)
- [ ] warn that initialising an EntraToken will fetch OIDC metadata and the JWKS
- [ ] doc blocks
- [ ] test for current token?
- [ ] contact in errors (url, mailto)
- [ ] document config options
- [ ] caching for `_get_oidc_metadata`
  - `JWKSclient` already caches the fetching of the key
- [ ] support invalid tokens?
  - `jwt.decode(payload["token"], options={"verify_signature": False})`

Later:

- [ ] CI
- [ ] Safety
- [ ] publish under existing package name?

Other:

- [ ] using MSAL cache written to user's home directory

# Flask Entra Auth

Flask extension for authenticating and authorising requests using Entra identity platform.

## Purpose

Allows routes in a [Flask](https://flask.palletsprojects.com) application to be restricted using the 
[Microsoft Entra](https://learn.microsoft.com/en-us/entra/) identity platform.

...

## Install

```
$ pip install flask-entra-auth
```

## Usage

After creating an [App Registration](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) 
in Entra, [Configure](#configuration) your Flask app:

```python
from flask import Flask
from flask_entra_auth.resource_protector import FlaskEntraAuth

auth = FlaskEntraAuth()

def create_app() -> Flask:
    """Create Flask app."""
    app = Flask(__name__)
    app.config["ENTRA_AUTH_CLIENT_ID"] = 'xxx'
    app.config["ENTRA_AUTH_OIDC_ENDPOINT"] = 'xxx'
    app.config["ENTRA_AUTH_ALLOWED_SUBJECTS"] = ['xxx']  # optional, allows all subjects if empty or not set
    app.config["ENTRA_AUTH_ALLOWED_APPS"] = ['xxx']  # optional, allows all applications if empty or not set
    auth.init_app(app)

    @app.route("/restricted/foo")
    @app.auth()
    def authenticated() -> str:
        """Closed route (requires authentication)."""
        return "Authenticated route."

    @app.route("/restricted/bar")
    @app.auth(['APP_SCOPE'])
    def authorised() -> str:
        """Closed route (requires authentication and authorisation)."""
        return "Authorised route."
```

(add route example for using current token)

...

## Configuration

Config options are read from the [Flask config](https://flask.palletsprojects.com/en/3.0.x/config/) object.

| Option                        | Required | Description                            |
|-------------------------------|----------|----------------------------------------|
| `ENTRA_AUTH_CLIENT_ID`        | Yes      | Entra Application (Client) ID          |
| `ENTRA_AUTH_OIDC_ENDPOINT`    | Yes      | OpenID configuration document URI      |
| `ENTRA_AUTH_ALLOWED_SUBJECTS` | No       | An allowed list of end-users           |
| `ENTRA_AUTH_ALLOWED_APPS`     | No       | An allowed list of client applications |

See the Entra documentation for how to get the 
[Client ID](https://learn.microsoft.com/en-us/azure/healthcare-apis/register-application#application-id-client-id)
and [OIDC Endpoint](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri)
for your application.

## Implementation

### Resource protector

This library uses the [AuthLib Flask](https://docs.authlib.org/en/latest/flask/2/resource-server.html) resource 
protector to secure access to routes within an application. This requires a valid user (authentication) and optionally
ensures the user has one or more required [Scopes](#scopes) (authorisation).

The resource protector uses validators for a given token type. In this case a
[BearerTokenValidator](https://github.com/lepture/authlib/blob/master/authlib/oauth2/rfc6750/validator.py#L15) is used
to [Validate](#token-validation) a bearer JSON Web Token (JWT) specified in the `Authorization` request header. 
If validation fails, an [Error](#error-handling) is returned as the request response.

The AuthLib resource protector assumes the application is running its own OAuth server, and so has a record of tokens 
it has issued and can determine their validity (not revoked, expired or having insufficient scopes). This assumption
doesn't hold for Entra tokens and instead we validate the token using `pyjwt` and some additional checks statelessly.

## Entra Tokens

...

...creating an `EntraToken` class automatically and implicitly [Validates](#token-validation) it...

...

## Token validation

### Validation sequence

Summary:

- get signing keys (JWKS) from Entra Open ID Connect (OIDC) endpoint to avoid hard-coding keys that Entra may rotate
- validate standard claims using `pyjwt.decode()`
- additionally validate the (Entra) `ver` claim is '2.0' so we know which claims we should expect
- the `sub` and/or (Entra) `azp` claim values are validated against an allow list if set (otherwise all allowed)

Detail:

1. load OIDC metadata to get expected issuer and location to JWKS
1. load JWKS
1. parse token (base64 decode, JSON parse into header, payload and signature parts)
1. match `kid` token header parameter to key in JWKS
1. validate token signature using signing key
1. validate issuer
1. validate audience
1. validate expiration
1. validate not before
1. validate issued at (omitted)
1. validatetoken schema version
1. validate subject (if configured)
1. validate client (if configured)
1. validate scopes (if configured)

### Sources

- initially https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa
  - which checks signing key and audience (`aud`) claim
- then https://github.com/Intility/fastapi-azure-auth/blob/main/fastapi_azure_auth/auth.py#L189
  - which additionally checks `iss` claim
- then from various parts of https://github.com/AzureAD/microsoft-authentication-library-for-python/issues/147:
  - which includes clock skew (not been a problem for us inclined to omit for now)
- then from https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth/-/blob/main/src/flask_azure_oauth/tokens.py:
  - which additionally required the `sub` and `azp` claim for optionally filtering the security principle and application
  - which also exposed a leeway value with a default of 0
  - it also checked the `iat` claim but given we didn't do anything with its value, I don't think this adds anything


### Resource protector 2

As an evolved version of the resource protector:

- overloads `validate()` method of bearer token validator as much of its validation checks are done implicitly by
  initialising an `EntraToken` (such as expiry), now only checks for required scopes
- means we can remove the derived `EntraTokenAuthlib` class
- means we essentially have an authenticate and authorise method (but with the latter called 'validate')
- refactors into a Flask extension

## Token introspection

...

## Scopes

...

## Error handling

Errors encountered when accessing or validating the access token are raised as exceptions inheriting from a base
`EntraAuthError` exception. Exceptions are based on [RFC7807](https://datatracker.ietf.org/doc/html/rfc7807), returned
as a JSON response.

### Limitations

#### Authentication header

The resource protector checks for a missing authorisation header but doesn't raise a specific error for a missing
auth scheme, or auth credential (i.e. either parts of the authorisation header). Instead, both errors are interpreted
as requesting an unknown token type (meaning scheme (basic/digest/bearer/etc.) not OAuth type (access/refresh/etc.)) by
`authlib.oauth2.rfc6749.resource_protector.ResourceProtector.parse_request_authorization()`.

This is technically true but not as granular as we'd ideally like. We could work around that by overloading that parse
request method, but I don't think it's worth it. We can add detail to our exception to explain it may be invalid for 
one of three reasons instead (no scheme, no credential or unsupported scheme).

#### `iat` claim

The optional `iat` claim is included in Entra tokens but is not validated because it can't be tested.

Currently, there is no combination of `exp`, `nbf` and `iat` claim values that mean only the `iat` claim is invalid,
which is necessary to write an isolated test for it. Without a test we can't ensure this works correctly and is 
therefore disabled.

#### `jit` claim

The optional `jit` claim is not validated as this isn't included in Entra tokens.

## Tests

To run tests:

```
$ poetry run pytest
```

To run coverage:

```
$ poetry run pytest --cov --cov-report=html
```

## Licence

Copyright (c) 2024 UK Research and Innovation (UKRI), British Antarctic Survey (BAS).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

