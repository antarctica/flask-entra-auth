# Flask Azure Auth Experiments

Experiment to update how access to a Flask app can be controlled using Azure/Entra ID.

See https://gitlab.data.bas.ac.uk/MAGIC/add-metadata-toolbox/-/issues/384 for background.

**Note:** This README is in the process of being re-written to become a proper package.

## Roadmap

v0.1.0:

- [x] what else did my app do to check a token?
- [x] logically we should ensure `ver` claim is '2.0'
- [x] resource protector v1
- [x] get current token
- [x] refactor validator to skip auth method and overload validator to prevent needing derived token
- [x] refactored into an extension (resource protector v2)
- [x] minimal tests

v0.2.0:

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

v0.3.0:

- [x] change POST to GET in routes
- [x] doc blocks
- [x] document config options
- [x] note Token class implicitly validates for safety (currently)
- [x] warn that initialising an EntraToken will fetch OIDC metadata and the JWKS
- [x] test for current token?
- [x] link to https://jwt.ms as useful resource (introspection section)
- [x] link to MSAL for generating access tokens
- [x] introspection
- [x] explain custom scopes and how these can be used for authz
- [x] explain that other Entra features can control access to applications (user placement)
- [x] review existing README
- [x] rename package to `flask_entra_auth` (`flask-entra-auth`)

Then:

- [ ] testing support (move mock JWKS and JWT into main package?)
- [ ] contact in errors (url, mailto)
- [ ] caching for `_get_oidc_metadata`
  - `JWKSclient` already caches the fetching of the key

Later:

- [ ] CI
- [ ] Safety
- [ ] publish under existing package name?
- [ ] support invalid tokens?
  - `jwt.decode(payload["token"], options={"verify_signature": False})`
- [ ] re-support sessions

Other:

- [ ] using MSAL cache written to user's home directory

## Dropped features

For change log:

- session support
- version 1.0 tokens

# Flask Entra Auth

Flask extension for authenticating and authorising requests using Entra identity platform.

## Overview

**Note:** This project is focused on needs within the British Antarctic Survey. It has been open-sourced in case it is
of interest to others. Some resources, indicated with a '🛡' or '🔒' symbol, can only be accessed by BAS staff or
project members respectively. Contact the [Project Maintainer](#project-maintainer) to request access.

## Purpose

Allows routes in a [Flask](https://flask.palletsprojects.com) application to be restricted using the 
[Microsoft Entra](https://learn.microsoft.com/en-us/entra/) identity platform.

Use this if you use Entra ID and want to authenticate and optionally authorise users or clients of your Flask app.

## Install

The extension can be installed using Pip from [PyPi](https://pypi.org/project/flask-entra-auth):

```
$ pip install flask-entra-auth
```

**Note:** Since version 0.6.0, this package requires Flask 2.0 or greater.

## Usage

After creating an [App Registration](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) 
in Entra, [Configure](#configuration) your Flask app:

```python
from flask import Flask, current_app
from flask_entra_auth.resource_protector import FlaskEntraAuth
from flask_entra_auth.token import EntraToken

app = Flask(__name__)
app.config["ENTRA_AUTH_CLIENT_ID"] = 'xxx'
app.config["ENTRA_AUTH_OIDC_ENDPOINT"] = 'xxx'
app.config["ENTRA_AUTH_ALLOWED_SUBJECTS"] = ['xxx']  # optional, allows all subjects if empty or not set
app.config["ENTRA_AUTH_ALLOWED_APPS"] = ['xxx']  # optional, allows all applications if empty or not set

auth = FlaskEntraAuth()
auth.init_app(app)

@app.route("/restricted/red")
@app.auth()
def authenticated():
    """Route requires authenticated user."""
    return "Authenticated route."

@app.route("/restricted/blue")
@app.auth(['APP_SCOPE_1'])
def authorised():
    """Route requires authenticated and authorised user, specifically having the 'APP_SCOPE_1' scope."""
    return "Authorised route."

@app.route("/restricted/green")
@app.auth(['APP_SCOPE_1 APP_SCOPE_2'])
def authorised_and():
    """Route requires authenticated and authorised user, specifically having both the 'APP_SCOPE_1' and 'APP_SCOPE_2' scopes."""
    return "Authorised route."

@app.route("/restricted/yellow")
@app.auth(['APP_SCOPE_1', 'APP_SCOPE_2'])
def authorised_either():
    """Route requires authenticated and authorised user, specifically having either the 'APP_SCOPE_1' or 'APP_SCOPE_2' scopes."""
    return "Authorised route."

@app.route("/restricted/purple")
@app.auth()
def current_token():
    """Get a claim from the current token"""
    token: EntraToken = current_app.auth.current_token
    return f"Hello {token.claims['name']}"
```

### Generating access tokens

Generating access tokens is out of scope for this project as there is an official Microsoft library 
[MSAL](http://msal-python.readthedocs.io/en/latest/) to do that. This library can also be used to validate ID tokens.

### Inspecting access tokens

The [jwt.ms](https://jwt.ms) tool from Microsoft provides an easy way to debug an access token, including descriptions 
for claims it contains.

### Using scopes to control access

See the [Token Scopes](#token-scopes) section.

## Configuration

Config options are read from the [Flask config](https://flask.palletsprojects.com/en/3.0.x/config/) object.

| Option                        | Required | Description                            |
|-------------------------------|----------|----------------------------------------|
| `ENTRA_AUTH_CLIENT_ID`        | Yes      | Entra Application (Client) ID          |
| `ENTRA_AUTH_OIDC_ENDPOINT`    | Yes      | OpenID configuration document URI      |
| `ENTRA_AUTH_ALLOWED_SUBJECTS` | No       | An allowed list of end-users           |
| `ENTRA_AUTH_ALLOWED_APPS`     | No       | An allowed list of client applications |

The `CLIENT_ID` represents the Flask application being secured (and a client of Entra ID).

The `ALLOWED_APPS` list of clients represents clients of the Flask application (but which are also Entra ID clients).

See the Entra documentation for how to get the 
[Client ID](https://learn.microsoft.com/en-us/azure/healthcare-apis/register-application#application-id-client-id)
and [OIDC Endpoint](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri)
for your application.

## Resource protector

This library uses the [AuthLib Flask](https://docs.authlib.org/en/latest/flask/2/resource-server.html) resource 
protector, [`EntraResourceProtector`](src/flask_entra_auth/resource_protector.py), to secure access to routes within an 
application. This requires a valid user (authentication) and optionally ensures the user has one or more required 
[Scopes](#token-scopes) (authorisation).

The resource protector uses validators for a given token type. In this case a
[BearerTokenValidator](https://github.com/lepture/authlib/blob/master/authlib/oauth2/rfc6750/validator.py#L15), 
[`EntraBearerTokenValidator`](src/flask_entra_auth/resource_protector.py), is used to [Validate](#token-validation) a 
bearer JSON Web Token (JWT) specified in the `Authorization` request header. If validation fails, an 
[Error](#error-handling) is returned as the request response.

The AuthLib resource protector assumes the application is running its own OAuth server, and so has a record of tokens 
it has issued and can determine their validity (not revoked, expired or having insufficient scopes). This assumption
doesn't hold for Entra tokens, so instead we validate the token using PyJWT and some additional checks statelessly.

For convenience the resource protector is exposed as a Flask extension, including a `current_token` property that gives
access to the access token taken from the request as an [EntraToken](#entra-tokens) instance.

## Entra Tokens

This library uses a custom [`EntraToken`](src/flask_entra_auth/token.py) class to represent Entra 
[Access Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens) (not ID tokens which can be 
validated with the official [MSAL](http://msal-python.readthedocs.io) library).

This class provides token [Validation](#token-validation), [Introspection](#token-introspection) and access methods of 
and to tokens and their claims.

**Note:** Creating an `EntraToken` instance will automatically and implicitly [Validate](#token-validation) the token.

**Note:** Validating an `EntraToken` instance will automatically fetch the OIDC metadata and the JSON Web Key Set 
(JWKS) from their respective URIs.

If desired this class can be used outside the [Resource Protector](#resource-protector) by passing a token string,
OIDC metadata endpoint, client ID (audience) and optionally an allowed list of subjects and client applications:

```python
from flask import Flask
from flask_entra_auth.token import EntraToken

app = Flask(__name__)
app.config["ENTRA_AUTH_CLIENT_ID"] = 'xxx'
app.config["ENTRA_AUTH_OIDC_ENDPOINT"] = 'xxx'
app.config["ENTRA_AUTH_ALLOWED_SUBJECTS"] = ['xxx']  # optional, allows all subjects if empty or not set
app.config["ENTRA_AUTH_ALLOWED_APPS"] = ['xxx']  # optional, allows all applications if empty or not set

# allowing all subjects but a restricted list of client applications
token = EntraToken(
  token='eyJhbGciOiJSUzI1NiIsImtpZCI6IjBYZ0ZndE5iLXVHazU1LUdSX1BMQ3JzN29aREtLWlRRNE5YUVM2NnhyLWsiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5hdXRoLmV4YW1wbGUuY29tIiwic3ViIjoidGVzdF9zdWJqZWN0IiwiYXVkIjoidGVzdF9hcHBfMSIsImV4cCI6MTcyMzQ1NzAwOCwibmJmIjoxNzIzNDUzNDA4LCJhenAiOiJ0ZXN0X2FwcF8yIiwidmVyIjoiMi4wIiwic2NwcyI6WyJTQ09QRV9BIiwiU0NPUEVfQiIsIlNDT1BFX0MiXSwicm9sZXMiOlsiUk9MRV8xIiwiUk9MRV8yIiwiUk9MRV8zIl19.jOoVhWLku34OUY4XBfUddeW39R0W2PxMmf_dKiSPr87pzg0m3d5_HqVOOVyB_qKvODPT8LHT3lrKIn1D9_67ERoa5clCn23DJAOZnux-hMXd19CCPWdBMu2yC1_kBzMdIkZbTgiuTjTleLYLl5JV3livdE0JVXaSHsj7Qt5c6yypfOBbk5uM4hYqpAnMpl6XToZgnBaI1SuRF2bj2bddLNzVxvg4yOYnX25Ruz5eMkKZonBI9FyumysD7CNOEnyANdaT4z4Z5siGI046hjt10if-Iz8EmDR7Srx_wX_KLng8qS0VE3qzxhEAycoBS6RKlZ2NRfPqkwkizUi0TlDLsA',
  oidc_endpoint='https://login.microsoftonline.com/{tenancy}/v2.0/.well-known/openid-configuration',
  client_id='test_app_1',
  allowed_apps=['deb4356e-1570-4d5a-bdaa-86cf545a8045']
)

# get a validated claim
print(token.claims['exp'])  # 1723457008

# get list of scopes
print(token.scopes)  # ['SCOPE_A', 'SCOPE_B', 'SCOPE_C', 'ROLE_1', 'ROLE_2', 'ROLE_3']
```

## Token scopes

Typically, applications wish to limit which users or clients can perform particular actions (e.g. read vs. read-write)
using custom permissions. These can be defined within the application registration in Entra ID and then checked for 
using the [Resource Protector](#resource-protector).

Entra distinguishes between permissions:

- that apply to client applications directly, termed `scps` (scopes)
- that apply users (or other principles such as service accounts) delegated to client applications, termed `roles`

This library combines any `scps` and `roles` into a generic list of _scopes_, returned by the `EntraToken.scopes` 
property to make it easier to combine different levels of access.

See the Entra Documentation for how to 
[Register custom client scopes](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-expose-web-apis)
or to [Register custom user roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps).

In addition to using scopes and checking these within Flask, Entra also offers features such as 
[User Assignment](https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users).

The [Resource Protector](#resource-protector) decorator supports both logic _AND_ and _OR_ combinations of scopes. See 
the [AuthLib](https://docs.authlib.org/en/latest/flask/2/resource-server.html#multiple-scopes) documentation for more 
information.

## Token validation

Microsoft does not provide an official library or implementation for validating [Entra Tokens](#entra-tokens) in Python.

This library opts to validate tokens using a combination of [PyJWT](https://pyjwt.readthedocs.io/) and some additional 
custom validation methods. This is in line with how others have solved the same 
[problem](https://github.com/AzureAD/microsoft-authentication-library-for-python/issues/147).

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

### Validation limitations

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

## Token introspection

The [`EntraToken`](#entra-tokens) class provides a `rfc7662_introspection()` method that returns standard/common claims
within a token according to [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) (OAuth Token Introspection).

This returns a dict that can returned as a response. As per the RFC, the token to be introspected MUST be specified as
form data. It MUST also be authenticated via a separate mechanism - this feature is not provided by this library and
would need implementing separately.

**Note:** The optional `jti` claim is not included as this isn't included in Entra tokens.

Example route:

```python
from flask import Flask, request
from flask_entra_auth.exceptions import EntraAuthError
from flask_entra_auth.token import EntraToken

app = Flask(__name__)
app.config["ENTRA_AUTH_CLIENT_ID"] = 'xxx'
app.config["ENTRA_AUTH_OIDC_ENDPOINT"] = 'xxx'

@app.route("/introspect", methods=["POST"])
def introspect_rfc7662():
    """
    Token introspection as per RFC7662.
    """
    try:
        token = EntraToken(
            token=request.form.get("token"),
            oidc_endpoint=app.config["ENTRA_AUTH_OIDC_ENDPOINT"],
            client_id=app.config["ENTRA_AUTH_CLIENT_ID"],
        )
        return token.rfc7662_introspection  # noqa: TRY300
    except EntraAuthError as e:
        return {"error": str(e)}, e.problem.status
```

## Error handling

Errors encountered when accessing or validating the access token are raised as exceptions inheriting from a base
`EntraAuthError` exception. Exceptions are based on [RFC7807](https://datatracker.ietf.org/doc/html/rfc7807), returned
as a JSON response.

Example response:

```json
{
  "detail": "Ensure your request includes an 'Authorization' header and try again.", 
  "status": 401, 
  "title": "Missing authorization header", 
  "type": "auth_header_missing"
}
```

## Developing

See [Developing](DEVELOPING.md) documentation.

## Releases

- [latest release 🛡️](https://gitlab.data.bas.ac.uk/.../-/releases/permalink/latest)
- [all releases 🛡️](https://gitlab.data.bas.ac.uk/.../-/releases)
- GitHub
- PyPi

## Project maintainer

British Antarctic Survey ([BAS](https://www.bas.ac.uk)) Mapping and Geographic Information Centre
([MAGIC](https://www.bas.ac.uk/teams/magic)). Contact [magic@bas.ac.uk](mailto:magic@bas.ac.uk).

The project lead is [@felnne](https://www.bas.ac.uk/profile/felnne).

## Licence

Copyright (c) 2019 - 2024 UK Research and Innovation (UKRI), British Antarctic Survey (BAS).

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

