# Flask Azure Auth Experiments

Experiment to update how access to a Flask app can be controlled using Azure/Entra ID.

## Purpose

To find a replacement for the now outdated
[Flask Azure OAuth](https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth) package.

See https://gitlab.data.bas.ac.uk/MAGIC/add-metadata-toolbox/-/issues/384 for background.

## Usage

Start server:

```
$ poetry run flask --app=flask_azure.__main__:app run --debug --port 5005
```

Get auth token:

- from [`flask_azure.http`](flask_azure.http) using PyCharm run:
  - the `login.microsoftonline.com/.../devicecode` request, following the prompt to sign in with the device code
  - then the `login.microsoftonline.com/.../token` request, to set an access token for use in app requests

To view details about the current token:

- from [`flask_azure.http`](flask_azure.http) using PyCharm run either:
  - the `/introspect` request, where data is returned according to RFC7662
  - the `/restricted/current-token` request, where all token claims are returned as a JSON object

## Tests

To run tests:

```
$ poetry run pytest
```

To run coverage:

```
$ poetry run pytest --cov --cov-report=html
```

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

- [ ] change POST to GET in routes
- [ ] note Token class implicitly validates for safety (currently)
- [ ] warn that initialising an EntraToken will fetch OIDC metadata and the JWKS
- [ ] doc blocks
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

## Experiments

### Token validation

Sources:

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

Summary:

- we check all standard claims (not sure about `nbf` and we ignore `iat` as we don't have a use for it)
- we additionally check the `ver` Entra specific claim is '2.0'
- we optionally additionally check the `sub` and/or `azp` claim values are allowed as per a list

### Resource protector 1

There are various implementations of a similar concept (decorator for routes). As we know the AuthLib version works I've
stuck with that.

At a minimum this needs a bearer token validator, a class that requires an `authenticate()` (not validate) method for a 
token (taken from the `Authorization` request header). This assumes we're running our own OAuth server, and so have a 
record of tokens we've issued. We don't and instead use this method to validate the token.

This validator class then calls its own `validate()` method which checks the token is specified, not revoked/expired 
and has the required set of scopes present.

The resource protector class itself then registers this validator. We don't need to make any changes to it.

### Resource protector 2

As an evolved version of the resource protector:

- overloads `validate()` method of bearer token validator as much of its validation checks are done implicitly by
  initialising an `EntraToken` (such as expiry), now only checks for required scopes
- means we can remove the derived `EntraTokenAuthlib` class
- means we essentially have an authenticate and authorise method (but with the latter called 'validate')
- refactors into a Flask extension

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

